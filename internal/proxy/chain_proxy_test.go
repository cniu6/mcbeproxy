package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// TestRawUDPProxy_ChainViaSOCKS5 verifies that a two-level proxy chain works
// when both proxies use SOCKS5 outbound to reach their upstream:
//
//	Client → Proxy B (SOCKS5 outbound → Proxy A listen port)
//	        → Proxy A (SOCKS5 outbound → Real Server)
//
// This reproduces the user's scenario: "A机器代理后，B机器也用当前软件调用不行"
// where both machines use proxy outbounds.
func TestRawUDPProxy_ChainViaSOCKS5(t *testing.T) {
	// 1. Start fake real server
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	// 2. Start a SOCKS5 proxy server (simulates the proxy node for A)
	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	// 3. Start Proxy A (targets real server, via SOCKS5 outbound)
	proxyAListen := freeUDPPort(t)
	cfgA := &config.ServerConfig{
		ID:          "proxy-a-socks",
		Target:      "127.0.0.1",
		Port:        realServer.Port,
		ListenAddr:  proxyAListen.String(),
		ProxyMode:   "raw_udp",
		ProxyOutbound: "socks5-A",
		IdleTimeout: 3600,
	}
	outboundA := &config.ProxyOutbound{
		Name:    "socks5-A",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5AHost,
		Port:    socks5APort,
		Enabled: true,
	}
	if err := outboundA.Validate(); err != nil {
		t.Fatalf("validate outbound A: %v", err)
	}
	mgrA := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	if err := mgrA.AddOutbound(outboundA); err != nil {
		t.Fatalf("add outbound A: %v", err)
	}

	smA := session.NewSessionManager(time.Hour)
	proxyA := NewRawUDPProxy("proxy-a-socks", cfgA, nil, smA)
	proxyA.SetOutboundManager(mgrA)
	if err := proxyA.Start(); err != nil {
		t.Fatalf("start proxy A: %v", err)
	}
	defer proxyA.Stop()

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() { _ = proxyA.Listen(ctxA) }()
	time.Sleep(100 * time.Millisecond)

	// 4. Start a SOCKS5 proxy server (simulates the proxy node for B)
	socks5B := startSOCKS5Server(t, "", "")
	socks5BHost, socks5BPort := splitHostPort(t, socks5B.String())

	// 5. Start Proxy B (targets Proxy A, via SOCKS5 outbound)
	proxyBListen := freeUDPPort(t)
	cfgB := &config.ServerConfig{
		ID:          "proxy-b-socks",
		Target:      "127.0.0.1",
		Port:        proxyAListen.Port,
		ListenAddr:  proxyBListen.String(),
		ProxyMode:   "raw_udp",
		ProxyOutbound: "socks5-B",
		IdleTimeout: 3600,
	}
	outboundB := &config.ProxyOutbound{
		Name:    "socks5-B",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5BHost,
		Port:    socks5BPort,
		Enabled: true,
	}
	if err := outboundB.Validate(); err != nil {
		t.Fatalf("validate outbound B: %v", err)
	}
	mgrB := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	if err := mgrB.AddOutbound(outboundB); err != nil {
		t.Fatalf("add outbound B: %v", err)
	}

	smB := session.NewSessionManager(time.Hour)
	proxyB := NewRawUDPProxy("proxy-b-socks", cfgB, nil, smB)
	proxyB.SetOutboundManager(mgrB)
	if err := proxyB.Start(); err != nil {
		t.Fatalf("start proxy B: %v", err)
	}
	defer proxyB.Stop()

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	go func() { _ = proxyB.Listen(ctxB) }()
	time.Sleep(100 * time.Millisecond)

	// 6. Connect client to Proxy B and do RakNet handshake
	client, err := net.DialUDP("udp", nil, proxyBListen)
	if err != nil {
		t.Fatalf("client dial proxy B: %v", err)
	}
	defer client.Close()

	// Send OpenConnectionRequest1 (0x05)
	ocr1 := append([]byte{0x05}, make([]byte, 32)...)
	if _, err := client.Write(ocr1); err != nil {
		t.Fatalf("client write OCR1: %v", err)
	}

	// Wait for OpenConnectionReply1 (0x06) through the SOCKS5 chain
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read OCR1 reply through SOCKS5 chain: %v", err)
	}
	if n == 0 || buf[0] != 0x06 {
		t.Fatalf("expected OpenConnectionReply1 (0x06), got 0x%02x (n=%d)", buf[0], n)
	}
	t.Logf("OCR1 reply received through SOCKS5 chain: 0x%02x (%d bytes)", buf[0], n)

	// Send OpenConnectionRequest2 (0x07)
	ocr2 := append([]byte{0x07}, make([]byte, 32)...)
	if _, err := client.Write(ocr2); err != nil {
		t.Fatalf("client write OCR2: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read OCR2 reply: %v", err)
	}
	if n == 0 || buf[0] != 0x08 {
		t.Fatalf("expected OpenConnectionReply2 (0x08), got 0x%02x (n=%d)", buf[0], n)
	}
	t.Logf("OCR2 reply received through SOCKS5 chain: 0x%02x (%d bytes)", buf[0], n)

	// Send a game packet and verify echo
	gamePacket := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0xaa, 0xbb, 0xcc, 0xdd}
	if _, err := client.Write(gamePacket); err != nil {
		t.Fatalf("client write game packet: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read game packet echo: %v", err)
	}
	if n != len(gamePacket) {
		t.Fatalf("expected echo of %d bytes, got %d bytes", len(gamePacket), n)
	}
	for i := 0; i < len(gamePacket); i++ {
		if buf[i] != gamePacket[i] {
			t.Fatalf("byte mismatch at index %d: expected 0x%02x, got 0x%02x", i, gamePacket[i], buf[i])
		}
	}
	t.Logf("Game packet echoed back through SOCKS5 chain: %d bytes match", n)
}

// splitHostPort splits a host:port string and returns the host as string and port as int.
func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port %q: %v", addr, err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}
