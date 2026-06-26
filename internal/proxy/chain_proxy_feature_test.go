package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
	"mcpeserverproxy/internal/singboxcore"
)

// TestChainProxy_UDP_SOCKS5 verifies that a chain proxy outbound works for UDP.
// Setup:
//
//	SOCKS5-A (simulates proxy server 1)
//	SOCKS5-B (simulates proxy server 2)
//
//	Chain outbound "chain-node" = [socks5-hop1, socks5-hop2]
//	Traffic flow: client → chain-node → SOCKS5-B → SOCKS5-A → real server
//
// The chain node's own Server/Port point to SOCKS5-B (the last hop).
// The chain list contains ["socks5-hop1"] which points to SOCKS5-A.
// So the full chain is: socks5-hop1 (SOCKS5-A) → chain-node (SOCKS5-B) → target.
func TestChainProxy_UDP_SOCKS5(t *testing.T) {
	// 1. Start fake real server
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	// 2. Start two SOCKS5 proxy servers
	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	socks5B := startSOCKS5Server(t, "", "")
	socks5BHost, socks5BPort := splitHostPort(t, socks5B.String())

	// 3. Create outbound manager with chain proxy node
	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())

	// Add hop1 outbound (SOCKS5-A)
	hop1 := &config.ProxyOutbound{
		Name:    "socks5-hop1",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5AHost,
		Port:    socks5APort,
		Enabled: true,
	}
	if err := hop1.Validate(); err != nil {
		t.Fatalf("validate hop1: %v", err)
	}
	if err := mgr.AddOutbound(hop1); err != nil {
		t.Fatalf("add hop1: %v", err)
	}

	// Add chain node (SOCKS5-B as final hop, with chain=[socks5-hop1])
	chainNode := &config.ProxyOutbound{
		Name:    "chain-node",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5BHost,
		Port:    socks5BPort,
		Enabled: true,
		Chain:   []string{"socks5-hop1"},
	}
	if err := chainNode.Validate(); err != nil {
		t.Fatalf("validate chain node: %v", err)
	}
	if err := mgr.AddOutbound(chainNode); err != nil {
		t.Fatalf("add chain node: %v", err)
	}

	// 4. Create RawUDPProxy using the chain node
	proxyListen := freeUDPPort(t)
	cfg := &config.ServerConfig{
		ID:            "chain-test",
		Target:        "127.0.0.1",
		Port:          realServer.Port,
		ListenAddr:    proxyListen.String(),
		ProxyMode:     "raw_udp",
		ProxyOutbound: "chain-node",
		IdleTimeout:   3600,
	}

	sm := session.NewSessionManager(time.Hour)
	proxy := NewRawUDPProxy("chain-test", cfg, nil, sm)
	proxy.SetOutboundManager(mgr)
	if err := proxy.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = proxy.Listen(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// 5. Connect client and do RakNet handshake through the chain
	client, err := net.DialUDP("udp", nil, proxyListen)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	// Send OpenConnectionRequest1
	ocr1 := append([]byte{0x05}, make([]byte, 32)...)
	if _, err := client.Write(ocr1); err != nil {
		t.Fatalf("write OCR1: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read OCR1 reply through chain: %v", err)
	}
	if n == 0 || buf[0] != 0x06 {
		t.Fatalf("expected OpenConnectionReply1 (0x06), got 0x%02x (n=%d)", buf[0], n)
	}
	t.Logf("OCR1 reply received through chain: 0x%02x (%d bytes)", buf[0], n)

	// Send OpenConnectionRequest2
	ocr2 := append([]byte{0x07}, make([]byte, 32)...)
	if _, err := client.Write(ocr2); err != nil {
		t.Fatalf("write OCR2: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("read OCR2 reply: %v", err)
	}
	if n == 0 || buf[0] != 0x08 {
		t.Fatalf("expected OpenConnectionReply2 (0x08), got 0x%02x (n=%d)", buf[0], n)
	}
	t.Logf("OCR2 reply received through chain: 0x%02x (%d bytes)", buf[0], n)

	// Send game packet and verify echo
	gamePacket := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0xaa, 0xbb, 0xcc, 0xdd}
	if _, err := client.Write(gamePacket); err != nil {
		t.Fatalf("write game packet: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("read game packet echo: %v", err)
	}
	if n != len(gamePacket) {
		t.Fatalf("expected echo of %d bytes, got %d bytes", len(gamePacket), n)
	}
	for i := 0; i < len(gamePacket); i++ {
		if buf[i] != gamePacket[i] {
			t.Fatalf("byte mismatch at index %d: expected 0x%02x, got 0x%02x", i, gamePacket[i], buf[i])
		}
	}
	t.Logf("Game packet echoed back through chain: %d bytes match", n)
}

// TestChainProxy_TCP_SOCKS5 verifies that a chain proxy outbound works for TCP
// connections via the singboxcore.Dialer path (used by proxy ports / plain TCP).
func TestChainProxy_TCP_SOCKS5(t *testing.T) {
	// 1. Start a TCP echo server as the "real server"
	echoAddr := startTCPEcho(t)

	// 2. Start two SOCKS5 proxy servers
	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	socks5B := startSOCKS5Server(t, "", "")
	socks5BHost, socks5BPort := splitHostPort(t, socks5B.String())

	// 3. Create outbound manager with chain proxy node
	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())

	hop1 := &config.ProxyOutbound{
		Name:    "socks5-tcp-hop1",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5AHost,
		Port:    socks5APort,
		Enabled: true,
	}
	if err := hop1.Validate(); err != nil {
		t.Fatalf("validate hop1: %v", err)
	}
	if err := mgr.AddOutbound(hop1); err != nil {
		t.Fatalf("add hop1: %v", err)
	}

	chainNode := &config.ProxyOutbound{
		Name:    "socks5-tcp-chain",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5BHost,
		Port:    socks5BPort,
		Enabled: true,
		Chain:   []string{"socks5-tcp-hop1"},
	}
	if err := chainNode.Validate(); err != nil {
		t.Fatalf("validate chain node: %v", err)
	}
	if err := mgr.AddOutbound(chainNode); err != nil {
		t.Fatalf("add chain node: %v", err)
	}

	// 4. Use the ChainFactory directly to create a dialer
	chainFactory := NewChainFactory(NewSingboxCoreFactory(), mgr)
	dialer, err := chainFactory.CreateDialer(context.Background(), chainNode)
	if err != nil {
		t.Fatalf("create chain dialer: %v", err)
	}
	defer dialer.Close()

	// 5. Dial the echo server through the chain
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial through chain: %v", err)
	}
	defer conn.Close()

	// 6. Send data and verify echo
	testData := []byte("hello-chain-proxy")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(testData) {
		t.Fatalf("expected %d bytes echo, got %d", len(testData), n)
	}
	for i := 0; i < len(testData); i++ {
		if resp[i] != testData[i] {
			t.Fatalf("byte mismatch at %d: expected %c, got %c", i, testData[i], resp[i])
		}
	}
	t.Logf("TCP echo through chain: %d bytes match", n)
}

// TestChainProxy_NestedChainSupported verifies that nested chains work correctly.
// chain2 → chain1 → hop1 → target
func TestChainProxy_NestedChainSupported(t *testing.T) {
	// Start SOCKS5 servers for 3 hops
	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	socks5B := startSOCKS5Server(t, "", "")
	socks5BHost, socks5BPort := splitHostPort(t, socks5B.String())

	socks5C := startSOCKS5Server(t, "", "")
	socks5CHost, socks5CPort := splitHostPort(t, socks5C.String())

	// Start TCP echo as target
	echoAddr := startTCPEcho(t)

	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())

	// hop1 = SOCKS5-A (plain node)
	hop1 := &config.ProxyOutbound{
		Name: "hop1", Type: config.ProtocolSOCKS5,
		Server: socks5AHost, Port: socks5APort, Enabled: true,
	}
	if err := mgr.AddOutbound(hop1); err != nil {
		t.Fatalf("add hop1: %v", err)
	}

	// chain1 = SOCKS5-B with chain=[hop1]  (chain proxy)
	chain1 := &config.ProxyOutbound{
		Name: "chain1", Type: config.ProtocolSOCKS5,
		Server: socks5BHost, Port: socks5BPort, Enabled: true,
		Chain: []string{"hop1"},
	}
	if err := mgr.AddOutbound(chain1); err != nil {
		t.Fatalf("add chain1: %v", err)
	}

	// chain2 = SOCKS5-C with chain=[chain1]  (nested chain proxy!)
	chain2 := &config.ProxyOutbound{
		Name: "chain2", Type: config.ProtocolSOCKS5,
		Server: socks5CHost, Port: socks5CPort, Enabled: true,
		Chain: []string{"chain1"},
	}
	if err := mgr.AddOutbound(chain2); err != nil {
		t.Fatalf("add chain2: %v", err)
	}

	// Create dialer for chain2 — should expand to: hop1 → chain1(SOCKS5-B) → chain2(SOCKS5-C)
	chainFactory := NewChainFactory(NewSingboxCoreFactory(), mgr)
	dialer, err := chainFactory.CreateDialer(context.Background(), chain2)
	if err != nil {
		t.Fatalf("create nested chain dialer: %v", err)
	}
	defer dialer.Close()

	// Dial the echo server through the nested chain
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial through nested chain: %v", err)
	}
	defer conn.Close()

	testData := []byte("nested-chain-works")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), n)
	}
	for i := 0; i < len(testData); i++ {
		if resp[i] != testData[i] {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
	t.Logf("TCP echo through nested chain (3 hops): %d bytes match", n)
}

// TestChainProxy_CycleDetected verifies that circular chain references are rejected.
func TestChainProxy_CycleDetected(t *testing.T) {
	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())

	// chainA → chainB → chainA (circular)
	chainA := &config.ProxyOutbound{
		Name: "chainA", Type: config.ProtocolSOCKS5,
		Server: "127.0.0.1", Port: 1080, Enabled: true,
		Chain: []string{"chainB"},
	}
	if err := mgr.AddOutbound(chainA); err != nil {
		t.Fatalf("add chainA: %v", err)
	}

	chainB := &config.ProxyOutbound{
		Name: "chainB", Type: config.ProtocolSOCKS5,
		Server: "127.0.0.1", Port: 1081, Enabled: true,
		Chain: []string{"chainA"},
	}
	if err := mgr.AddOutbound(chainB); err != nil {
		t.Fatalf("add chainB: %v", err)
	}

	chainFactory := NewChainFactory(NewSingboxCoreFactory(), mgr)
	_, err := chainFactory.CreateDialer(context.Background(), chainA)
	if err == nil {
		t.Fatal("expected error for circular chain, got nil")
	}
	t.Logf("Circular chain correctly rejected: %v", err)
}

// TestChainProxy_MissingHopRejected verifies that referencing a non-existent hop fails.
func TestChainProxy_MissingHopRejected(t *testing.T) {
	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())

	chainNode := &config.ProxyOutbound{
		Name:    "chain-missing",
		Type:    config.ProtocolSOCKS5,
		Server:  "127.0.0.1",
		Port:    1080,
		Enabled: true,
		Chain:   []string{"nonexistent-hop"},
	}

	chainFactory := NewChainFactory(NewSingboxCoreFactory(), mgr)
	_, err := chainFactory.CreateDialer(context.Background(), chainNode)
	if err == nil {
		t.Fatal("expected error for missing hop, got nil")
	}
	t.Logf("Missing hop correctly rejected: %v", err)
}

// Ensure singboxcore.Factory interface is satisfied
var _ singboxcore.Factory = (*ChainFactory)(nil)
