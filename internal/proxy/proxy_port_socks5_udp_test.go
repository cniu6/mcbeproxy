package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// TestProxyPortSOCKS5UDPAssociate verifies that the proxy port SOCKS5 server
// correctly handles UDP ASSOCIATE requests and relays UDP datagrams.
func TestProxyPortSOCKS5UDPAssociate(t *testing.T) {
	// Start a UDP echo server as the target
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start UDP echo: %v", err)
	}
	defer udpEcho.Close()

	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], addr)
		}
	}()

	// Create a proxy port listener with direct connection (no outbound)
	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:         "test-socks5-udp",
		ListenAddr: "127.0.0.1:0",
		Type:       config.ProxyPortTypeSocks5,
		Enabled:    true,
	}, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listener.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener.ctx = ctx
	listener.cancel = cancel

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.handleConn(conn)
		}
	}()

	// Connect to the SOCKS5 proxy port
	proxyAddr := ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting (no auth)
	greeting := []byte{0x05, 0x01, 0x00}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected greeting resp: %v", resp)
	}

	// Send UDP ASSOCIATE request
	// DST.ADDR = 0.0.0.0:0 (client doesn't know its source addr yet)
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("send UDP ASSOCIATE: %v", err)
	}

	// Read reply
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read UDP ASSOCIATE reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed with reply code %d", reply[1])
	}

	// Parse relay address
	relayIP := net.IP(reply[4:8])
	relayPort := int(binary.BigEndian.Uint16(reply[8:10]))
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}
	t.Logf("UDP relay at %s", relayAddr)

	// Create local UDP socket to talk to the relay
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	// Send a datagram to the echo server through the relay
	// SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT + DATA
	testData := []byte("hello-udp-associate")
	udpHeader := []byte{0x00, 0x00, 0x00, 0x01} // RSV + FRAG + ATYP=IPv4
	udpHeader = append(udpHeader, echoAddr.IP.To4()...)
	udpHeader = append(udpHeader, byte(echoAddr.Port>>8), byte(echoAddr.Port&0xFF))
	datagram := append(udpHeader, testData...)

	_ = clientUDP.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
		t.Fatalf("write to relay: %v", err)
	}

	// Read response from relay
	_ = clientUDP.SetReadDeadline(time.Now().Add(10 * time.Second))
	respBuf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	if n < 10 {
		t.Fatalf("response too short: %d bytes", n)
	}

	// Parse SOCKS5 UDP response header
	payloadOffset := assertSocks5UDPIPv4ResponseHeader(t, respBuf[:n], echoAddr)
	respData := respBuf[payloadOffset:n]
	if len(respData) != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), len(respData))
	}
	for i := 0; i < len(testData); i++ {
		if respData[i] != testData[i] {
			t.Fatalf("byte mismatch at %d: expected %c, got %c", i, testData[i], respData[i])
		}
	}
	t.Logf("UDP echo through SOCKS5 UDP ASSOCIATE: %d bytes match", len(respData))

	// Close control connection
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// TestProxyPortSOCKS5UDPAssociateWithAuth tests UDP ASSOCIATE with username/password auth.
type timeoutOnlyPacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func newTimeoutOnlyPacketConn() *timeoutOnlyPacketConn {
	return &timeoutOnlyPacketConn{closed: make(chan struct{})}
}

func (c *timeoutOnlyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, timeoutErr{}
	case <-time.After(10 * time.Millisecond):
		return 0, nil, timeoutErr{}
	}
}

func (c *timeoutOnlyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }
func (c *timeoutOnlyPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *timeoutOnlyPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *timeoutOnlyPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *timeoutOnlyPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *timeoutOnlyPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestSharedUDPRelayIPv6ActivityUsesParsedClientIP(t *testing.T) {
	relay := &sharedUDPRelay{
		clients: make(map[string]*udpClientEntry),
	}
	relay.clients["[::1]:50000"] = &udpClientEntry{upstreams: map[string]*upstreamConn{
		"127.0.0.1:19132": {lastSeen: time.Now()},
	}}

	if !relay.hasRecentActivity(net.ParseIP("::1"), time.Minute) {
		t.Fatal("expected IPv6 client activity to match parsed UDP client host")
	}
	if relay.hasRecentActivity(net.ParseIP("::2"), time.Minute) {
		t.Fatal("unexpected activity match for different IPv6 client")
	}
}

func TestSharedUDPRelayCloseStopsTimeoutOnlyResponseLoop(t *testing.T) {
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay UDP: %v", err)
	}

	relay := &sharedUDPRelay{
		conn:      relayConn,
		clients:   make(map[string]*udpClientEntry),
		activeIPs: make(map[string]int),
		stopCh:    make(chan struct{}),
		cfgID:     "timeout-close-test",
	}
	pc := newTimeoutOnlyPacketConn()
	relay.clients["127.0.0.1:50000"] = &udpClientEntry{upstreams: map[string]*upstreamConn{
		"127.0.0.1:19132": {pc: pc, lastSeen: time.Now()},
	}}

	relay.wg.Add(1)
	go relay.forwardUDPResponses(pc, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}, nil)

	done := make(chan struct{})
	go func() {
		relay.close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shared UDP relay close did not stop timeout-only response loop")
	}
}

type blockingSharedUDPOutboundManager struct {
	countingRawUDPOutboundManager
	blockDest        string
	firstDialStarted chan struct{}
	releaseFirstDial chan struct{}
	secondWriteDone  chan struct{}
	startOnce        sync.Once
}

func (m *blockingSharedUDPOutboundManager) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	if destination == m.blockDest {
		m.startOnce.Do(func() { close(m.firstDialStarted) })
		select {
		case <-m.releaseFirstDial:
			return newSignalingPacketConn(nil), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return newSignalingPacketConn(m.secondWriteDone), nil
}

type signalingPacketConn struct {
	closed chan struct{}
	once   sync.Once
	wrote  chan struct{}
}

func newSignalingPacketConn(wrote chan struct{}) *signalingPacketConn {
	return &signalingPacketConn{closed: make(chan struct{}), wrote: wrote}
}

func (c *signalingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, timeoutErr{}
	case <-time.After(10 * time.Millisecond):
		return 0, nil, timeoutErr{}
	}
}

func (c *signalingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.wrote != nil {
		select {
		case <-c.wrote:
		default:
			close(c.wrote)
		}
	}
	return len(p), nil
}

func (c *signalingPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *signalingPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *signalingPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *signalingPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *signalingPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type failingSharedUDPOutboundManager struct {
	countingRawUDPOutboundManager
	pc *failingWritePacketConn
}

func (m *failingSharedUDPOutboundManager) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	return m.pc, nil
}

type failingWritePacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func newFailingWritePacketConn() *failingWritePacketConn {
	return &failingWritePacketConn{closed: make(chan struct{})}
}

func (c *failingWritePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, timeoutErr{}
	case <-time.After(10 * time.Millisecond):
		return 0, nil, timeoutErr{}
	}
}

func (c *failingWritePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, fmt.Errorf("forced write failure")
}

func (c *failingWritePacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *failingWritePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *failingWritePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *failingWritePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *failingWritePacketConn) SetWriteDeadline(t time.Time) error { return nil }

func assertSocks5UDPIPv4ResponseHeader(t *testing.T, packet []byte, expected *net.UDPAddr) int {
	t.Helper()
	if len(packet) < 10 {
		t.Fatalf("response too short for SOCKS5 UDP IPv4 header: %d bytes", len(packet))
	}
	if packet[0] != 0x00 || packet[1] != 0x00 || packet[2] != 0x00 || packet[3] != 0x01 {
		t.Fatalf("unexpected SOCKS5 UDP response header prefix: %v", packet[:4])
	}
	gotIP := net.IPv4(packet[4], packet[5], packet[6], packet[7])
	if expectedIP := expected.IP.To4(); expectedIP == nil || !gotIP.Equal(expectedIP) {
		t.Fatalf("unexpected SOCKS5 UDP response source IP: got %s want %s", gotIP, expected.IP)
	}
	gotPort := int(binary.BigEndian.Uint16(packet[8:10]))
	if gotPort != expected.Port {
		t.Fatalf("unexpected SOCKS5 UDP response source port: got %d want %d", gotPort, expected.Port)
	}
	return 10
}

func socks5UDPIPv4Datagram(dest *net.UDPAddr, payload []byte) []byte {
	header := []byte{0x00, 0x00, 0x00, 0x01}
	header = append(header, dest.IP.To4()...)
	header = append(header, byte(dest.Port>>8), byte(dest.Port&0xff))
	return append(header, payload...)
}

func TestSharedUDPRelayWriteFailuresRemoveUnhealthyUpstream(t *testing.T) {
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay UDP: %v", err)
	}

	pc := newFailingWritePacketConn()
	mgr := &failingSharedUDPOutboundManager{pc: pc}
	ctx, cancel := context.WithCancel(context.Background())
	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:            "shared-udp-write-failure-test",
		ListenAddr:    "127.0.0.1:0",
		Type:          config.ProxyPortTypeSocks5,
		Enabled:       true,
		ProxyOutbound: "node-a",
	}, mgr, nil)
	listener.ctx = ctx

	relay := &sharedUDPRelay{
		conn:      relayConn,
		clients:   make(map[string]*udpClientEntry),
		activeIPs: make(map[string]int),
		stopCh:    make(chan struct{}),
		cfgID:     "shared-udp-write-failure-test",
	}
	relay.registerClientIP(net.IPv4(127, 0, 0, 1))
	relay.wg.Add(1)
	go relay.readLoop(listener)
	defer func() {
		cancel()
		relay.close()
	}()

	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client UDP: %v", err)
	}
	defer clientUDP.Close()

	dest := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 20), Port: 19132}
	for i := 0; i < sharedUDPRelayMaxWriteFailures; i++ {
		if _, err := clientUDP.WriteToUDP(socks5UDPIPv4Datagram(dest, []byte{byte(i + 1)}), relayAddr); err != nil {
			t.Fatalf("write datagram %d: %v", i, err)
		}
	}

	select {
	case <-pc.closed:
	case <-time.After(time.Second):
		t.Fatal("unhealthy upstream was not closed after consecutive write failures")
	}

	clientKey := clientUDP.LocalAddr().String()
	deadline := time.After(time.Second)
	for {
		relay.mu.Lock()
		_, stillPresent := relay.clients[clientKey]
		relay.mu.Unlock()
		if !stillPresent {
			return
		}
		select {
		case <-deadline:
			t.Fatal("unhealthy upstream was not removed from relay clients")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestSharedUDPRelaySlowUpstreamDialDoesNotBlockOtherClients(t *testing.T) {
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay UDP: %v", err)
	}

	blockedDest := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 19132}
	fastDest := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 11), Port: 19132}
	mgr := &blockingSharedUDPOutboundManager{
		blockDest:        blockedDest.String(),
		firstDialStarted: make(chan struct{}),
		releaseFirstDial: make(chan struct{}),
		secondWriteDone:  make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:            "shared-udp-hol-test",
		ListenAddr:    "127.0.0.1:0",
		Type:          config.ProxyPortTypeSocks5,
		Enabled:       true,
		ProxyOutbound: "node-a",
	}, mgr, nil)
	listener.ctx = ctx

	relay := &sharedUDPRelay{
		conn:      relayConn,
		clients:   make(map[string]*udpClientEntry),
		activeIPs: make(map[string]int),
		stopCh:    make(chan struct{}),
		cfgID:     "shared-udp-hol-test",
	}
	relay.registerClientIP(net.IPv4(127, 0, 0, 1))
	relay.wg.Add(1)
	go relay.readLoop(listener)
	defer func() {
		close(mgr.releaseFirstDial)
		cancel()
		relay.close()
	}()

	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	clientA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client A UDP: %v", err)
	}
	defer clientA.Close()
	clientB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client B UDP: %v", err)
	}
	defer clientB.Close()

	if _, err := clientA.WriteToUDP(socks5UDPIPv4Datagram(blockedDest, []byte("first")), relayAddr); err != nil {
		t.Fatalf("write first datagram: %v", err)
	}
	select {
	case <-mgr.firstDialStarted:
	case <-time.After(time.Second):
		t.Fatal("first upstream dial did not start")
	}

	if _, err := clientB.WriteToUDP(socks5UDPIPv4Datagram(fastDest, []byte("second")), relayAddr); err != nil {
		t.Fatalf("write second datagram: %v", err)
	}
	select {
	case <-mgr.secondWriteDone:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("second client was blocked by another client's slow upstream dial")
	}
}

func TestProxyPortSOCKS5UDPAssociateWithAuth(t *testing.T) {
	// Start a UDP echo server
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start UDP echo: %v", err)
	}
	defer udpEcho.Close()

	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], addr)
		}
	}()

	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:         "test-socks5-udp-auth",
		ListenAddr: "127.0.0.1:0",
		Type:       config.ProxyPortTypeSocks5,
		Enabled:    true,
		Username:   "user",
		Password:   "pass",
	}, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listener.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener.ctx = ctx
	listener.cancel = cancel

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.handleConn(conn)
		}
	}()

	proxyAddr := ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting with user/pass auth
	greeting := []byte{0x05, 0x02, 0x00, 0x02}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}
	if resp[1] != 0x02 {
		t.Fatalf("expected user/pass auth (0x02), got %d", resp[1])
	}

	// Send auth
	auth := []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("send auth: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth resp: %v", err)
	}
	if authResp[1] != 0x00 {
		t.Fatalf("auth failed: %v", authResp)
	}

	// Send UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("send UDP ASSOCIATE: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read UDP ASSOCIATE reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed with reply code %d", reply[1])
	}

	relayIP := net.IP(reply[4:8])
	relayPort := int(binary.BigEndian.Uint16(reply[8:10]))
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	testData := []byte("auth-udp-works")
	udpHeader := []byte{0x00, 0x00, 0x00, 0x01}
	udpHeader = append(udpHeader, echoAddr.IP.To4()...)
	udpHeader = append(udpHeader, byte(echoAddr.Port>>8), byte(echoAddr.Port&0xFF))
	datagram := append(udpHeader, testData...)

	_ = clientUDP.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
		t.Fatalf("write to relay: %v", err)
	}

	_ = clientUDP.SetReadDeadline(time.Now().Add(10 * time.Second))
	respBuf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	payloadOffset := assertSocks5UDPIPv4ResponseHeader(t, respBuf[:n], echoAddr)
	respData := respBuf[payloadOffset:n]
	if len(respData) != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), len(respData))
	}
	t.Logf("UDP echo through SOCKS5 UDP ASSOCIATE with auth: %d bytes match", len(respData))

	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// Ensure fmt is used
var _ = fmt.Sprintf

// TestProxyPortSOCKS5UDPRapidReconnect verifies that rapidly disconnecting
// and reconnecting a SOCKS5 UDP ASSOCIATE from the same IP does not kill the
// new connection's upstream. This is a regression test for a race condition
// in unregisterClientIP where the old connection's cleanup would close the
// new connection's upstreams.
func TestProxyPortSOCKS5UDPRapidReconnect(t *testing.T) {
	// Start a UDP echo server as the target
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start UDP echo: %v", err)
	}
	defer udpEcho.Close()

	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], addr)
		}
	}()

	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:         "test-rapid-reconnect",
		ListenAddr: "127.0.0.1:0",
		Type:       config.ProxyPortTypeSocks5,
		Enabled:    true,
	}, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listener.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener.ctx = ctx
	listener.cancel = cancel

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.handleConn(conn)
		}
	}()

	proxyAddr := ln.Addr().String()
	echoIP := echoAddr.IP.To4()
	echoPort := echoAddr.Port

	// Perform 6 cycles of connect → ping → disconnect
	// With reuseCount=3 on the client side, this simulates rapid reconnection
	// after cache eviction. The server must not close the new upstream when
	// the old TCP control connection's cleanup runs.
	for cycle := 0; cycle < 6; cycle++ {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("cycle %d: dial proxy: %v", cycle, err)
		}

		// SOCKS5 greeting
		greeting := []byte{0x05, 0x01, 0x00}
		if _, err := conn.Write(greeting); err != nil {
			t.Fatalf("cycle %d: send greeting: %v", cycle, err)
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("cycle %d: read greeting resp: %v", cycle, err)
		}

		// UDP ASSOCIATE
		req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("cycle %d: send UDP ASSOCIATE: %v", cycle, err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("cycle %d: read UDP ASSOCIATE reply: %v", cycle, err)
		}
		if reply[1] != 0x00 {
			t.Fatalf("cycle %d: UDP ASSOCIATE failed with reply code %d", cycle, reply[1])
		}

		relayIP := net.IP(reply[4:8])
		relayPort := int(binary.BigEndian.Uint16(reply[8:10]))
		if relayIP.IsUnspecified() {
			relayIP = net.IPv4(127, 0, 0, 1)
		}
		relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}

		clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("cycle %d: listen UDP: %v", cycle, err)
		}

		testData := []byte("rapid-reconnect-test")
		udpHeader := []byte{0x00, 0x00, 0x00, 0x01}
		udpHeader = append(udpHeader, echoIP...)
		udpHeader = append(udpHeader, byte(echoPort>>8), byte(echoPort&0xFF))
		datagram := append(udpHeader, testData...)

		_ = clientUDP.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
			t.Fatalf("cycle %d: write to relay: %v", cycle, err)
		}

		_ = clientUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
		respBuf := make([]byte, 65535)
		n, _, err := clientUDP.ReadFromUDP(respBuf)
		if err != nil {
			t.Fatalf("cycle %d: read from relay: %v (upstream may have been killed by old cleanup)", cycle, err)
		}
		if n < 10 {
			t.Fatalf("cycle %d: response too short: %d bytes", cycle, n)
		}
		payloadOffset := assertSocks5UDPIPv4ResponseHeader(t, respBuf[:n], echoAddr)
		respData := respBuf[payloadOffset:n]
		if len(respData) != len(testData) {
			t.Fatalf("cycle %d: expected %d bytes, got %d", cycle, len(testData), len(respData))
		}

		clientUDP.Close()
		conn.Close()
		t.Logf("Cycle %d: ok", cycle)
	}
}
