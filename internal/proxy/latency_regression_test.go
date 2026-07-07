package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

const latencyRegressionBudget = 250 * time.Millisecond

func TestRawUDPClientStatsLocalizeTargetStallInMilliseconds(t *testing.T) {
	now := time.Now()
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43123}
	cfg := &config.ServerConfig{
		ID:         "raw-stall-ms-test",
		Target:     "203.0.113.10",
		Port:       19132,
		ListenAddr: "127.0.0.1:0",
	}
	p := NewRawUDPProxy("raw-stall-ms-test", cfg, nil, session.NewSessionManager(time.Hour))

	clientInfo := &rawUDPClientInfo{
		clientAddr: clientAddr,
		startTime:  now.Add(-RawUDPDirectionalStallThreshold - 250*time.Millisecond),
		sessionKey: p.makeSessionKey(clientAddr),
		proxyNode:  "node-a",
	}
	clientInfo.lastClientPacket.Store(now.Add(-15 * time.Millisecond).UnixNano())
	clientInfo.lastSeen.Store(now.UnixNano())
	clientInfo.packetsUp.Store(3)
	clientInfo.bytesUp.Store(96)
	p.clients.Store(clientAddr.String(), clientInfo)

	stats := p.GetRawUDPClientStats()
	if len(stats) != 1 {
		t.Fatalf("expected one RawUDP client stat, got %d", len(stats))
	}
	got := stats[0]
	if got.SinceClientMs > latencyRegressionBudget.Milliseconds() {
		t.Fatalf("client-side freshness was not localized in milliseconds: since_client_ms=%d budget_ms=%d", got.SinceClientMs, latencyRegressionBudget.Milliseconds())
	}
	if got.SinceTargetMs < RawUDPDirectionalStallThreshold.Milliseconds() {
		t.Fatalf("target stall was not measured past threshold: since_target_ms=%d threshold_ms=%d", got.SinceTargetMs, RawUDPDirectionalStallThreshold.Milliseconds())
	}
	if got.StallReason != "target_no_packet_yet" {
		t.Fatalf("expected target_no_packet_yet stall reason, got %q (client_ms=%d target_ms=%d)", got.StallReason, got.SinceClientMs, got.SinceTargetMs)
	}
}

func TestSharedUDPRelayBlockedWriteDoesNotHeadOfLineOtherDestinations(t *testing.T) {
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay UDP: %v", err)
	}

	slowDest := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 40), Port: 19132}
	fastDest := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 41), Port: 19132}
	mgr := &latencyBlockingRelayOutboundManager{
		slowDest:     slowDest.String(),
		slowStarted:  make(chan struct{}),
		releaseSlow:  make(chan struct{}),
		fastWritten:  make(chan struct{}),
		selectedNode: "node-a",
	}
	ctx, cancel := context.WithCancel(context.Background())
	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:            "shared-udp-write-hol-ms-test",
		ListenAddr:    "127.0.0.1:0",
		Type:          config.ProxyPortTypeSocks5,
		Enabled:       true,
		ProxyOutbound: mgr.selectedNode,
	}, mgr, nil)
	listener.ctx = ctx

	relay := &sharedUDPRelay{
		conn:      relayConn,
		clients:   make(map[string]*udpClientEntry),
		activeIPs: make(map[string]int),
		stopCh:    make(chan struct{}),
		cfgID:     "shared-udp-write-hol-ms-test",
	}
	relay.registerClientIP(net.IPv4(127, 0, 0, 1))
	relay.wg.Add(1)
	go relay.readLoop(listener)
	defer func() {
		close(mgr.releaseSlow)
		cancel()
		relay.close()
	}()

	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	clientA := listenLatencyUDP(t)
	defer clientA.Close()
	clientB := listenLatencyUDP(t)
	defer clientB.Close()

	if _, err := clientA.WriteToUDP(socks5UDPIPv4Datagram(slowDest, []byte("slow")), relayAddr); err != nil {
		t.Fatalf("write slow datagram: %v", err)
	}
	waitLatencySignal(t, "slow upstream write did not start", mgr.slowStarted, time.Second)

	started := time.Now()
	if _, err := clientB.WriteToUDP(socks5UDPIPv4Datagram(fastDest, []byte("fast")), relayAddr); err != nil {
		t.Fatalf("write fast datagram: %v", err)
	}
	waitLatencySignal(t, fmt.Sprintf("fast destination was HOL-blocked behind slow WriteTo for >%dms", latencyRegressionBudget.Milliseconds()), mgr.fastWritten, latencyRegressionBudget)
	t.Logf("fast destination escaped blocked WriteTo in %dms", time.Since(started).Milliseconds())
}

func TestSharedUDPRelayQueueDropOldestKeepsEnqueueNonBlocking(t *testing.T) {
	uc := newUpstreamConn()
	packet := udpRelayPacket{
		payload: []byte("packet"),
		dest:    &net.UDPAddr{IP: net.IPv4(203, 0, 113, 50), Port: 19132},
	}

	started := time.Now()
	var last udpRelayEnqueueResult
	for i := 0; i < sharedUDPRelayQueueSize+1; i++ {
		packet.payload = []byte{byte(i)}
		last = uc.enqueue(packet)
	}
	elapsed := time.Since(started)
	if elapsed > latencyRegressionBudget {
		t.Fatalf("enqueue path blocked for %dms while queue was full", elapsed.Milliseconds())
	}
	if !last.queued || !last.droppedOldest {
		t.Fatalf("expected full queue to drop oldest and keep newest queued, got %+v", last)
	}
	if depth := uc.stats().QueueDepth; depth != sharedUDPRelayQueueSize {
		t.Fatalf("expected queue depth %d, got %d", sharedUDPRelayQueueSize, depth)
	}
}

func TestPlainUDPProxyLocalRoundTripLatencyBudget(t *testing.T) {
	targetAddr, stopTarget := startLatencyUDPEcho(t)
	defer stopTarget()
	proxyListen := latencyFreeUDPAddr(t)

	cfg := &config.ServerConfig{
		ID:          "plain-udp-latency-test",
		Target:      "127.0.0.1",
		Port:        targetAddr.Port,
		ListenAddr:  proxyListen.String(),
		Protocol:    "udp",
		IdleTimeout: 1,
	}
	p := NewPlainUDPProxy("plain-udp-latency-test", cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start plain UDP proxy: %v", err)
	}
	defer p.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Listen(ctx) }()

	client, err := net.DialUDP("udp", nil, proxyListen)
	if err != nil {
		t.Fatalf("dial plain UDP proxy: %v", err)
	}
	defer client.Close()

	payload := []byte("plain-udp-ms")
	started := time.Now()
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write plain UDP payload: %v", err)
	}
	buf := make([]byte, 128)
	_ = client.SetReadDeadline(time.Now().Add(latencyRegressionBudget))
	n, err := client.Read(buf)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("plain UDP local RTT exceeded %dms after %dms: %v", latencyRegressionBudget.Milliseconds(), elapsed.Milliseconds(), err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("plain UDP echo mismatch: got %q want %q", buf[:n], payload)
	}
	t.Logf("plain UDP local proxy RTT=%dms", elapsed.Milliseconds())
}

func TestRelayStreamRemoteToLocalNotDelayedByBlockedUpload(t *testing.T) {
	localClient, localProxy := net.Pipe()
	remoteProxy, remoteServer := net.Pipe()
	defer localClient.Close()
	defer remoteServer.Close()

	done := make(chan struct{})
	go func() {
		relayStream(localProxy, localProxy, remoteProxy)
		close(done)
	}()

	uploadStarted := make(chan struct{})
	go func() {
		close(uploadStarted)
		_, _ = localClient.Write(bytes.Repeat([]byte("x"), 64*1024))
	}()
	waitLatencySignal(t, "upload goroutine did not start", uploadStarted, time.Second)
	time.Sleep(10 * time.Millisecond)

	payload := []byte("tcp-downstream")
	writeDone := make(chan error, 1)
	go func() {
		_, err := remoteServer.Write(payload)
		writeDone <- err
	}()

	buf := make([]byte, len(payload))
	_ = localClient.SetReadDeadline(time.Now().Add(latencyRegressionBudget))
	started := time.Now()
	n, err := localClient.Read(buf)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("downstream relay was blocked by upload backpressure for %dms: %v", elapsed.Milliseconds(), err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("downstream payload mismatch: got %q want %q", buf[:n], payload)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("remote write failed: %v", err)
		}
	case <-time.After(latencyRegressionBudget):
		t.Fatalf("remote write did not complete within %dms", latencyRegressionBudget.Milliseconds())
	}

	_ = localClient.Close()
	_ = remoteServer.Close()
	waitLatencySignal(t, "relayStream did not exit after both test endpoints closed", done, time.Second)
}

func BenchmarkSharedUDPRelayEnqueueFullQueue(b *testing.B) {
	uc := newUpstreamConn()
	packet := udpRelayPacket{
		payload: []byte("bench"),
		dest:    &net.UDPAddr{IP: net.IPv4(203, 0, 113, 60), Port: 19132},
	}
	for i := 0; i < sharedUDPRelayQueueSize; i++ {
		uc.enqueue(packet)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if result := uc.enqueue(packet); !result.queued {
			b.Fatalf("enqueue dropped newest packet at iteration %d", i)
		}
	}
}

type latencyBlockingRelayOutboundManager struct {
	countingRawUDPOutboundManager
	slowDest     string
	slowStarted  chan struct{}
	releaseSlow  chan struct{}
	fastWritten  chan struct{}
	selectedNode string
}

func (m *latencyBlockingRelayOutboundManager) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	if destination == m.slowDest {
		return &latencyBlockingPacketConn{
			closed:  make(chan struct{}),
			started: m.slowStarted,
			release: m.releaseSlow,
		}, nil
	}
	return &latencySignalingPacketConn{closed: make(chan struct{}), wrote: m.fastWritten}, nil
}

func (m *latencyBlockingRelayOutboundManager) SelectOutbound(groupOrName, strategy, sortBy string) (*config.ProxyOutbound, error) {
	name := m.selectedNode
	if name == "" {
		name = groupOrName
	}
	ob := &config.ProxyOutbound{Name: name, Type: config.ProtocolSOCKS5, Enabled: true}
	ob.SetHealthy(true)
	return ob, nil
}

func (m *latencyBlockingRelayOutboundManager) SelectOutboundWithFailoverForServer(serverID, groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	return m.SelectOutbound(groupOrName, strategy, sortBy)
}

type latencyBlockingPacketConn struct {
	closed    chan struct{}
	once      sync.Once
	startOnce sync.Once
	started   chan struct{}
	release   chan struct{}
}

func (c *latencyBlockingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, latencyTimeoutErr{}
	case <-time.After(10 * time.Millisecond):
		return 0, nil, latencyTimeoutErr{}
	}
}

func (c *latencyBlockingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.startOnce.Do(func() {
		if c.started != nil {
			close(c.started)
		}
	})
	select {
	case <-c.release:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *latencyBlockingPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *latencyBlockingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *latencyBlockingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *latencyBlockingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *latencyBlockingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type latencySignalingPacketConn struct {
	closed chan struct{}
	once   sync.Once
	wrote  chan struct{}
}

func (c *latencySignalingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, latencyTimeoutErr{}
	case <-time.After(10 * time.Millisecond):
		return 0, nil, latencyTimeoutErr{}
	}
}

func (c *latencySignalingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.wrote != nil {
		select {
		case <-c.wrote:
		default:
			close(c.wrote)
		}
	}
	return len(p), nil
}

func (c *latencySignalingPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *latencySignalingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *latencySignalingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *latencySignalingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *latencySignalingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type latencyTimeoutErr struct{}

func (latencyTimeoutErr) Error() string   { return "timeout" }
func (latencyTimeoutErr) Timeout() bool   { return true }
func (latencyTimeoutErr) Temporary() bool { return true }

func listenLatencyUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	return conn
}

func latencyFreeUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn := listenLatencyUDP(t)
	addr := conn.LocalAddr().(*net.UDPAddr)
	_ = conn.Close()
	return addr
}

func startLatencyUDPEcho(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn := listenLatencyUDP(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), func() {
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("UDP echo server did not stop")
		}
	}
}

func waitLatencySignal(t *testing.T, label string, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	started := time.Now()
	select {
	case <-ch:
		return
	case <-time.After(timeout):
		t.Fatalf("%s after %dms", label, time.Since(started).Milliseconds())
	}
}
