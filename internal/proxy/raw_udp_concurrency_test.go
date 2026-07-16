package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

type countingRawUDPOutboundManager struct {
	mu          sync.Mutex
	dials       int
	pingDials   int
	active      map[string]int64
	conns       []*countingPacketConn
	connFactory func() *countingPacketConn
}

func (m *countingRawUDPOutboundManager) AddOutbound(cfg *config.ProxyOutbound) error { return nil }
func (m *countingRawUDPOutboundManager) GetOutbound(name string) (*config.ProxyOutbound, bool) {
	ob := &config.ProxyOutbound{Name: name, Type: config.ProtocolSOCKS5, Enabled: true}
	ob.SetHealthy(true)
	return ob, true
}
func (m *countingRawUDPOutboundManager) DeleteOutbound(name string) error       { return nil }
func (m *countingRawUDPOutboundManager) ListOutbounds() []*config.ProxyOutbound { return nil }
func (m *countingRawUDPOutboundManager) UpdateOutbound(name string, cfg *config.ProxyOutbound) error {
	return nil
}
func (m *countingRawUDPOutboundManager) CheckHealth(ctx context.Context, name string) error {
	return nil
}
func (m *countingRawUDPOutboundManager) GetHealthStatus(name string) *HealthStatus               { return nil }
func (m *countingRawUDPOutboundManager) SetOutboundLatency(name, sortBy string, latencyMs int64) {}
func (m *countingRawUDPOutboundManager) GetOutboundLatencyHistory(name, sortBy string) []OutboundLatencySample {
	return nil
}
func (m *countingRawUDPOutboundManager) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dials++
	if m.active == nil {
		m.active = make(map[string]int64)
	}
	m.active[outboundName]++
	pc := newCountingPacketConn()
	if m.connFactory != nil {
		pc = m.connFactory()
	}
	pc.onClose = func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.active[outboundName] > 0 {
			m.active[outboundName]--
		}
	}
	m.conns = append(m.conns, pc)
	return pc, nil
}
func (m *countingRawUDPOutboundManager) DialPacketConnForPing(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pingDials++
	pc := newCountingPacketConn()
	m.conns = append(m.conns, pc)
	return pc, nil
}
func (m *countingRawUDPOutboundManager) Start() error  { return nil }
func (m *countingRawUDPOutboundManager) Stop() error   { return nil }
func (m *countingRawUDPOutboundManager) Reload() error { return nil }
func (m *countingRawUDPOutboundManager) GetActiveConnectionCount() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var total int64
	for _, count := range m.active {
		total += count
	}
	return total
}
func (m *countingRawUDPOutboundManager) GetOutboundConnectionCount(outboundName string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[outboundName]
}
func (m *countingRawUDPOutboundManager) GetGroupStats(groupName string) *GroupStats { return nil }
func (m *countingRawUDPOutboundManager) ListGroups() []*GroupStats                  { return nil }
func (m *countingRawUDPOutboundManager) GetOutboundsByGroup(groupName string) []*config.ProxyOutbound {
	return nil
}
func (m *countingRawUDPOutboundManager) SelectOutbound(groupOrName, strategy, sortBy string) (*config.ProxyOutbound, error) {
	ob := &config.ProxyOutbound{Name: groupOrName, Type: config.ProtocolSOCKS5, Enabled: true}
	ob.SetHealthy(true)
	return ob, nil
}
func (m *countingRawUDPOutboundManager) SelectOutboundWithFailover(groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	return m.SelectOutbound(groupOrName, strategy, sortBy)
}
func (m *countingRawUDPOutboundManager) SetServerNodeLatency(serverID, nodeName, sortBy string, latencyMs int64) {
}
func (m *countingRawUDPOutboundManager) GetServerNodeLatency(serverID, nodeName, sortBy string) (int64, bool) {
	return 0, false
}
func (m *countingRawUDPOutboundManager) GetServerNodeLatencyHistory(serverID, nodeName, sortBy string) []ServerNodeLatencySample {
	return nil
}
func (m *countingRawUDPOutboundManager) SelectOutboundWithFailoverForServer(serverID, groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	return m.SelectOutbound(groupOrName, strategy, sortBy)
}
func (m *countingRawUDPOutboundManager) GetServerSelectedNode(serverID string) (string, bool) {
	return "", false
}
func (m *countingRawUDPOutboundManager) SetServerSelectedNode(serverID, nodeName string)       {}
func (m *countingRawUDPOutboundManager) SetServerSelectedNodeManual(serverID, nodeName string) {}
func (m *countingRawUDPOutboundManager) IsServerNodeManual(serverID string) bool               { return false }
func (m *countingRawUDPOutboundManager) GetBestNodeForServer(serverID, groupOrName, sortBy string) (string, int64) {
	return "", 0
}

func (m *countingRawUDPOutboundManager) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dials, m.pingDials
}

type countingPacketConn struct {
	readCh         chan []byte
	closed         chan struct{}
	once           sync.Once
	writeStartOnce sync.Once
	onClose        func()
	writeStarted   chan struct{}
	releaseWrites  chan struct{}
	writes         int
	mu             sync.Mutex
}

func newCountingPacketConn() *countingPacketConn {
	return &countingPacketConn{readCh: make(chan []byte), closed: make(chan struct{})}
}

func (c *countingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case data := <-c.readCh:
		return copy(p, data), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}, nil
	case <-c.closed:
		return 0, nil, errors.New("closed")
	case <-time.After(10 * time.Millisecond):
		return 0, nil, timeoutErr{}
	}
}

func (c *countingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.writeStarted != nil {
		c.writeStartOnce.Do(func() { close(c.writeStarted) })
	}
	if c.releaseWrites != nil {
		select {
		case <-c.releaseWrites:
		case <-c.closed:
			return 0, errors.New("closed")
		}
	}
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	return len(p), nil
}
func (c *countingPacketConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}
func (c *countingPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (c *countingPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *countingPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *countingPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestRawUDPProxy_SameIPHandshakeDoesNotRemoveEstablishedClient(t *testing.T) {
	// 已建立会话在短于 sameIPEstablishedHandshakeGrace 的沉默期内，OCR 重连不应踢掉旧链路
	// （保护同公网 IP 下仍可能短暂卡顿的在线玩家）。
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "same-ip-established", IdleTimeout: 300}
	p := NewRawUDPProxy("same-ip-established", cfg, nil, sm)

	oldAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001}
	oldKey := oldAddr.String()
	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()

	oldClient := &rawUDPClientInfo{
		clientAddr: oldAddr,
		targetConn: targetConn,
		sessionKey: p.makeSessionKey(oldAddr),
		startTime:  time.Now().Add(-time.Minute),
	}
	oldClient.sessionCreated.Store(true)
	// 沉默略长于未建会话 handshake grace，但仍短于已建会话 grace → 应保留
	stale := time.Now().Add(-sameIPHandshakeGrace - time.Second).UnixNano()
	oldClient.lastClientPacket.Store(stale)
	oldClient.lastSeen.Store(stale)
	p.clients.Store(oldKey, oldClient)

	newAddr := &net.UDPAddr{IP: oldAddr.IP, Port: 50002}
	ocr1 := append([]byte{raknetOpenConnectionReq1}, make([]byte, 8)...)
	p.cleanupStaleSameIPClients(newAddr, ocr1)

	if p.GetActiveClientCount() != 1 {
		t.Fatalf("expected established same-IP client to survive short silence, got %d active", p.GetActiveClientCount())
	}
	if _, ok := p.clients.Load(oldKey); !ok {
		t.Fatal("established same-IP client was removed too early")
	}
}

func TestRawUDPProxy_SameIPOCRRemovesEstablishedSilentClient(t *testing.T) {
	// 已建立会话沉默超过 sameIPEstablishedHandshakeGrace 后，OCR 重连应踢掉旧链路
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "same-ip-est-ocr", IdleTimeout: 300}
	p := NewRawUDPProxy("same-ip-est-ocr", cfg, nil, sm)

	oldAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50011}
	oldKey := oldAddr.String()
	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()

	oldClient := &rawUDPClientInfo{
		clientAddr: oldAddr,
		targetConn: targetConn,
		sessionKey: p.makeSessionKey(oldAddr),
		startTime:  time.Now().Add(-time.Minute),
	}
	oldClient.sessionCreated.Store(true)
	stale := time.Now().Add(-sameIPEstablishedHandshakeGrace - time.Second).UnixNano()
	oldClient.lastClientPacket.Store(stale)
	oldClient.lastSeen.Store(stale)
	p.clients.Store(oldKey, oldClient)

	newAddr := &net.UDPAddr{IP: oldAddr.IP, Port: 50012}
	ocr1 := append([]byte{raknetOpenConnectionReq1}, make([]byte, 8)...)
	p.cleanupStaleSameIPClients(newAddr, ocr1)

	if p.GetActiveClientCount() != 0 {
		t.Fatalf("expected established silent client removed by OCR reconnect, got %d active", p.GetActiveClientCount())
	}
}

func TestRawUDPProxy_SameIPSilentRemovesEstablishedClient(t *testing.T) {
	// 已建立会话沉默超过 sameIPReconnectGrace，即使新包不是 OCR 也应被替换
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "same-ip-est-silent", IdleTimeout: 300}
	p := NewRawUDPProxy("same-ip-est-silent", cfg, nil, sm)

	oldAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50021}
	oldKey := oldAddr.String()
	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()

	oldClient := &rawUDPClientInfo{
		clientAddr: oldAddr,
		targetConn: targetConn,
		sessionKey: p.makeSessionKey(oldAddr),
		startTime:  time.Now().Add(-time.Minute),
	}
	oldClient.sessionCreated.Store(true)
	oldClient.loginParsed.Store(true)
	stale := time.Now().Add(-sameIPReconnectGrace - time.Second).UnixNano()
	oldClient.lastClientPacket.Store(stale)
	oldClient.lastSeen.Store(stale)
	p.clients.Store(oldKey, oldClient)

	newAddr := &net.UDPAddr{IP: oldAddr.IP, Port: 50022}
	// 非 OCR 包（例如可靠帧）
	p.cleanupStaleSameIPClients(newAddr, []byte{0x80, 0x00})

	if p.GetActiveClientCount() != 0 {
		t.Fatalf("expected established client silent >15s to be removed, got %d active", p.GetActiveClientCount())
	}
}

func TestRawUDPProxy_SameIPTakeoverWorksWithIdleNever(t *testing.T) {
	// idle_timeout=-1 时 sweep 不会因沉默清链路，同 IP 接管是唯一快速回收路径
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{ID: "same-ip-idle-never", IdleTimeout: -1}
	p := NewRawUDPProxy("same-ip-idle-never", cfg, nil, sm)
	p.updateTimeouts()

	oldAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50031}
	oldKey := oldAddr.String()
	targetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dummy target: %v", err)
	}
	defer targetConn.Close()

	oldClient := &rawUDPClientInfo{
		clientAddr: oldAddr,
		targetConn: targetConn,
		sessionKey: p.makeSessionKey(oldAddr),
		startTime:  time.Now().Add(-time.Minute),
	}
	oldClient.sessionCreated.Store(true)
	stale := time.Now().Add(-sameIPEstablishedHandshakeGrace - time.Second).UnixNano()
	oldClient.lastClientPacket.Store(stale)
	oldClient.lastSeen.Store(stale)
	p.clients.Store(oldKey, oldClient)

	// sweep 在 idle_timeout=-1 下应保留
	p.sweepInactiveClients(time.Now(), p.effectiveClientDisconnectTimeout())
	if p.GetActiveClientCount() != 1 {
		t.Fatalf("expected idle_timeout=-1 sweep to keep client, got %d", p.GetActiveClientCount())
	}

	newAddr := &net.UDPAddr{IP: oldAddr.IP, Port: 50032}
	ocr1 := append([]byte{raknetOpenConnectionReq1}, make([]byte, 8)...)
	p.cleanupStaleSameIPClients(newAddr, ocr1)

	if p.GetActiveClientCount() != 0 {
		t.Fatalf("expected same-IP OCR takeover under idle_timeout=-1, got %d active", p.GetActiveClientCount())
	}
}

func TestRawUDPProxy_SessionKeyIncludesServerAndListener(t *testing.T) {
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
	cfg1 := &config.ServerConfig{ID: "srv-a", ListenAddr: "127.0.0.1:20001"}
	cfg2 := &config.ServerConfig{ID: "srv-b", ListenAddr: "127.0.0.1:20002"}
	p1 := NewRawUDPProxy("srv-a", cfg1, nil, session.NewSessionManager(time.Hour))
	p2 := NewRawUDPProxy("srv-b", cfg2, nil, session.NewSessionManager(time.Hour))

	key1 := p1.makeSessionKey(clientAddr)
	key2 := p2.makeSessionKey(clientAddr)
	if key1 == key2 {
		t.Fatalf("session keys should differ across servers/listeners: %q", key1)
	}
	if key1 == clientAddr.String() || key2 == clientAddr.String() {
		t.Fatalf("session key must include server/listener scope, got %q and %q", key1, key2)
	}
}

func TestRawUDPProxy_PingSkippedWhileClientAssociationActive(t *testing.T) {
	sm := session.NewSessionManager(time.Hour)
	cfg := &config.ServerConfig{
		ID:            "ping-skip-active",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:20003",
		ProxyMode:     "raw_udp",
		ProxyOutbound: "node-a",
		IdleTimeout:   300,
	}
	mgr := &countingRawUDPOutboundManager{}
	p := NewRawUDPProxy("ping-skip-active", cfg, nil, sm)
	p.SetOutboundManager(mgr)
	p.targetAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}
	p.targetPacketAddr = p.targetAddr
	p.updateTimeouts()

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50001}
	client, isNew := p.getOrCreateClient(clientAddr, []byte{raknetOpenConnectionReq1})
	if client == nil || !isNew {
		t.Fatalf("expected new client association, got client=%v isNew=%v", client, isNew)
	}
	defer p.removeClient(clientAddr.String())

	p.pingTargetServer()
	playerDials, pingDials := mgr.counts()
	if playerDials != 1 {
		t.Fatalf("expected one player DialPacketConn, got %d", playerDials)
	}
	if pingDials != 0 {
		t.Fatalf("expected no ping DialPacketConn while active client exists, got %d", pingDials)
	}
}

func TestRawUDPProxy_PingSkippedWhileSameOutboundActiveOnAnotherServer(t *testing.T) {
	mgr := &countingRawUDPOutboundManager{}
	cfgA := &config.ServerConfig{
		ID:            "server-a",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:21001",
		ProxyMode:     "raw_udp",
		ProxyOutbound: "shared-node",
		IdleTimeout:   300,
	}
	cfgB := &config.ServerConfig{
		ID:            "server-b",
		Target:        "127.0.0.1",
		Port:          19133,
		ListenAddr:    "127.0.0.1:21002",
		ProxyMode:     "raw_udp",
		ProxyOutbound: "shared-node",
		IdleTimeout:   300,
	}
	pA := NewRawUDPProxy("server-a", cfgA, nil, session.NewSessionManager(time.Hour))
	pB := NewRawUDPProxy("server-b", cfgB, nil, session.NewSessionManager(time.Hour))
	pA.SetOutboundManager(mgr)
	pB.SetOutboundManager(mgr)
	pA.targetAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}
	pA.targetPacketAddr = pA.targetAddr
	pB.targetAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19133}
	pB.targetPacketAddr = pB.targetAddr
	pA.updateTimeouts()
	pB.updateTimeouts()

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50101}
	client, isNew := pA.getOrCreateClient(clientAddr, []byte{raknetOpenConnectionReq1})
	if client == nil || !isNew {
		t.Fatalf("expected server-a client association, got client=%v isNew=%v", client, isNew)
	}
	defer pA.removeClient(clientAddr.String())

	pB.pingTargetServer()
	playerDials, pingDials := mgr.counts()
	if playerDials != 1 {
		t.Fatalf("expected only the player association dial, got %d", playerDials)
	}
	if pingDials != 0 {
		t.Fatalf("expected server-b ping to skip shared active outbound, got %d ping dials", pingDials)
	}
}

func TestRawUDPProxy_ForwardResponsesToleratesNilContextAndListener(t *testing.T) {
	p := &RawUDPProxy{
		serverID:   "half-init",
		sessionMgr: session.NewSessionManager(time.Hour),
	}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50201}
	pc := newCountingPacketConn()
	client := &rawUDPClientInfo{
		clientAddr: clientAddr,
		targetConn: pc,
		targetAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132},
		startTime:  time.Now(),
		sessionKey: p.makeSessionKey(clientAddr),
	}
	now := time.Now().UnixNano()
	client.lastSeen.Store(now)
	client.lastClientPacket.Store(now)
	p.clients.Store(clientAddr.String(), client)

	panicCh := make(chan interface{}, 1)
	done := make(chan struct{})
	p.wg.Add(1)
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
		}()
		p.forwardResponses(clientAddr, client)
	}()

	select {
	case pc.readCh <- []byte{0x80, 0x00, 0x00, 0x00}:
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwardResponses did not start reading from target connection")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwardResponses did not exit after listener write failed")
	}

	select {
	case recovered := <-panicCh:
		t.Fatalf("forwardResponses panicked with nil ctx/listener: %v", recovered)
	default:
	}
	if p.GetActiveClientCount() != 0 {
		t.Fatalf("expected half-initialized client to be removed, got %d active", p.GetActiveClientCount())
	}
}

func TestRawUDPProxy_ListenHotLoopDoesNotWaitForSlowUpstreamWrite(t *testing.T) {
	slowConn := newCountingPacketConn()
	slowConn.writeStarted = make(chan struct{})
	slowConn.releaseWrites = make(chan struct{})

	mgr := &countingRawUDPOutboundManager{
		connFactory: func() *countingPacketConn { return slowConn },
	}
	cfg := &config.ServerConfig{
		ID:            "slow-upstream-hot-loop",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:0",
		ProxyMode:     "raw_udp",
		ProxyOutbound: "node-a",
		IdleTimeout:   300,
	}
	p := NewRawUDPProxy("slow-upstream-hot-loop", cfg, nil, session.NewSessionManager(time.Hour))
	p.SetOutboundManager(mgr)
	if err := p.Start(); err != nil {
		t.Fatalf("start raw udp proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Listen(ctx) }()

	cleanup := func() {
		cancel()
		close(slowConn.releaseWrites)
		_ = p.Stop()
		select {
		case <-errCh:
		case <-time.After(time.Second):
			t.Fatal("Listen did not exit during cleanup")
		}
	}
	defer cleanup()

	clientConn, err := net.DialUDP("udp", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial proxy listener: %v", err)
	}
	defer clientConn.Close()
	clientKey := clientConn.LocalAddr().String()

	if _, err := clientConn.Write([]byte{0x80, 0x00, 0x00, 0x00, 0xfe}); err != nil {
		t.Fatalf("send first datagram: %v", err)
	}
	select {
	case <-slowConn.writeStarted:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("upstream writer did not start first blocked write")
	}

	start := time.Now()
	if _, err := clientConn.Write([]byte{0x80, 0x00, 0x00, 0x01, 0xfe}); err != nil {
		t.Fatalf("send second datagram: %v", err)
	}

	deadline := time.After(75 * time.Millisecond)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if val, ok := p.clients.Load(clientKey); ok {
			if clientInfo, ok := val.(*rawUDPClientInfo); ok && clientInfo.packetsUp.Load() >= 2 {
				if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
					t.Fatalf("second datagram reached hot loop too slowly: %v", elapsed)
				}
				return
			}
		}
		select {
		case <-deadline:
			if val, ok := p.clients.Load(clientKey); ok {
				if clientInfo, ok := val.(*rawUDPClientInfo); ok {
					t.Fatalf("hot loop blocked behind upstream write; packetsUp=%d", clientInfo.packetsUp.Load())
				}
			}
			t.Fatal("hot loop did not create client for second datagram")
		case <-ticker.C:
		}
	}
}
