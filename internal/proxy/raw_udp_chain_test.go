package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// startFakeRakNetServer starts a UDP server that responds to RakNet handshake
// packets (OpenConnectionRequest1 -> OpenConnectionReply1, etc.) and echoes
// all other packets back to the sender. This simulates a real Minecraft Bedrock
// server at the end of a proxy chain.
func startFakeRakNetServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen fake raknet server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			if n == 0 {
				continue
			}
			// Respond to OpenConnectionRequest1 (0x07) with OpenConnectionReply1 (0x06)
			// Actually 0x05 is OpenConnectionRequest1, 0x06 is OpenConnectionReply1
			// 0x07 is OpenConnectionRequest2, 0x08 is OpenConnectionReply2
			switch buf[0] {
			case 0x05: // OpenConnectionRequest1
				reply := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00}
				_, _ = conn.WriteToUDP(reply, addr)
			case 0x07: // OpenConnectionRequest2
				reply := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00}
				_, _ = conn.WriteToUDP(reply, addr)
			default:
				// Echo everything else (game packets, reliable frames, etc.)
				_, _ = conn.WriteToUDP(buf[:n], addr)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), func() {
		close(done)
		_ = conn.Close()
	}
}

// TestRawUDPProxy_ChainDirectToDirect verifies that a two-level proxy chain
// works: Client -> Proxy B (direct) -> Proxy A (direct) -> Real Server.
//
// Both proxies use raw_udp mode with direct (no outbound) connections.
// The test sends a RakNet handshake sequence through Proxy B and verifies
// that packets reach the fake server and responses come back through both
// proxies to the client.
func TestRawUDPProxy_ChainDirectToDirect(t *testing.T) {
	// 1. Start fake real server
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	// 2. Start Proxy A (targets real server, direct)
	proxyAListen := freeUDPPort(t)
	cfgA := &config.ServerConfig{
		ID:          "proxy-a",
		Target:      "127.0.0.1",
		Port:        realServer.Port,
		ListenAddr:  proxyAListen.String(),
		ProxyMode:   "raw_udp",
		ProxyOutbound: "", // direct
		IdleTimeout: 3600,
	}
	smA := session.NewSessionManager(time.Hour)
	proxyA := NewRawUDPProxy("proxy-a", cfgA, nil, smA)
	if err := proxyA.Start(); err != nil {
		t.Fatalf("start proxy A: %v", err)
	}
	defer proxyA.Stop()

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() { _ = proxyA.Listen(ctxA) }()

	// Give proxy A time to start listening
	time.Sleep(100 * time.Millisecond)

	// 3. Start Proxy B (targets Proxy A, direct)
	proxyBListen := freeUDPPort(t)
	cfgB := &config.ServerConfig{
		ID:          "proxy-b",
		Target:      "127.0.0.1",
		Port:        proxyAListen.Port,
		ListenAddr:  proxyBListen.String(),
		ProxyMode:   "raw_udp",
		ProxyOutbound: "", // direct
		IdleTimeout: 3600,
	}
	smB := session.NewSessionManager(time.Hour)
	proxyB := NewRawUDPProxy("proxy-b", cfgB, nil, smB)
	if err := proxyB.Start(); err != nil {
		t.Fatalf("start proxy B: %v", err)
	}
	defer proxyB.Stop()

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	go func() { _ = proxyB.Listen(ctxB) }()

	// Give proxy B time to start listening
	time.Sleep(100 * time.Millisecond)

	// 4. Connect client to Proxy B and do RakNet handshake
	client, err := net.DialUDP("udp", nil, proxyBListen)
	if err != nil {
		t.Fatalf("client dial proxy B: %v", err)
	}
	defer client.Close()

	// Send OpenConnectionRequest1 (0x05) + magic + some payload
	ocr1 := append([]byte{0x05}, make([]byte, 32)...)
	if _, err := client.Write(ocr1); err != nil {
		t.Fatalf("client write OCR1: %v", err)
	}

	// Wait for OpenConnectionReply1 (0x06) to come back through the chain
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read OCR1 reply: %v (chain: Client -> B(%s) -> A(%s) -> Real(%s))",
			err, proxyBListen, proxyAListen, realServer)
	}
	if n == 0 || buf[0] != 0x06 {
		t.Fatalf("expected OpenConnectionReply1 (0x06), got 0x%02x (n=%d)", buf[0], n)
	}
	t.Logf("OCR1 reply received through chain: 0x%02x (%d bytes)", buf[0], n)

	// Send OpenConnectionRequest2 (0x07) + some payload
	ocr2 := append([]byte{0x07}, make([]byte, 32)...)
	if _, err := client.Write(ocr2); err != nil {
		t.Fatalf("client write OCR2: %v", err)
	}

	// Wait for OpenConnectionReply2 (0x08)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read OCR2 reply: %v", err)
	}
	if n == 0 || buf[0] != 0x08 {
		t.Fatalf("expected OpenConnectionReply2 (0x08), got 0x%02x (n=%d)", buf[0], n)
	}
	t.Logf("OCR2 reply received through chain: 0x%02x (%d bytes)", buf[0], n)

	// Send a game packet (reliable frame 0x84) and verify it's echoed back
	gamePacket := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0xaa, 0xbb, 0xcc, 0xdd}
	if _, err := client.Write(gamePacket); err != nil {
		t.Fatalf("client write game packet: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
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
	t.Logf("Game packet echoed back through chain: %d bytes match", n)
}

// TestRawUDPProxy_ChainThreeLevelDirectToDirectToDirect verifies a three-level
// chain: Client -> Proxy C -> Proxy B -> Proxy A -> Real Server.
func TestRawUDPProxy_ChainThreeLevelDirectToDirectToDirect(t *testing.T) {
	// 1. Start fake real server
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	// 2. Start Proxy A (targets real server)
	proxyAListen := freeUDPPort(t)
	cfgA := &config.ServerConfig{
		ID:          "proxy-a",
		Target:      "127.0.0.1",
		Port:        realServer.Port,
		ListenAddr:  proxyAListen.String(),
		ProxyMode:   "raw_udp",
		ProxyOutbound: "",
		IdleTimeout: 3600,
	}
	smA := session.NewSessionManager(time.Hour)
	proxyA := NewRawUDPProxy("proxy-a", cfgA, nil, smA)
	if err := proxyA.Start(); err != nil {
		t.Fatalf("start proxy A: %v", err)
	}
	defer proxyA.Stop()

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() { _ = proxyA.Listen(ctxA) }()
	time.Sleep(100 * time.Millisecond)

	// 3. Start Proxy B (targets Proxy A)
	proxyBListen := freeUDPPort(t)
	cfgB := &config.ServerConfig{
		ID:          "proxy-b",
		Target:      "127.0.0.1",
		Port:        proxyAListen.Port,
		ListenAddr:  proxyBListen.String(),
		ProxyMode:   "raw_udp",
		ProxyOutbound: "",
		IdleTimeout: 3600,
	}
	smB := session.NewSessionManager(time.Hour)
	proxyB := NewRawUDPProxy("proxy-b", cfgB, nil, smB)
	if err := proxyB.Start(); err != nil {
		t.Fatalf("start proxy B: %v", err)
	}
	defer proxyB.Stop()

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	go func() { _ = proxyB.Listen(ctxB) }()
	time.Sleep(100 * time.Millisecond)

	// 4. Start Proxy C (targets Proxy B)
	proxyCListen := freeUDPPort(t)
	cfgC := &config.ServerConfig{
		ID:          "proxy-c",
		Target:      "127.0.0.1",
		Port:        proxyBListen.Port,
		ListenAddr:  proxyCListen.String(),
		ProxyMode:   "raw_udp",
		ProxyOutbound: "",
		IdleTimeout: 3600,
	}
	smC := session.NewSessionManager(time.Hour)
	proxyC := NewRawUDPProxy("proxy-c", cfgC, nil, smC)
	if err := proxyC.Start(); err != nil {
		t.Fatalf("start proxy C: %v", err)
	}
	defer proxyC.Stop()

	ctxC, cancelC := context.WithCancel(context.Background())
	defer cancelC()
	go func() { _ = proxyC.Listen(ctxC) }()
	time.Sleep(100 * time.Millisecond)

	// 5. Connect client to Proxy C
	client, err := net.DialUDP("udp", nil, proxyCListen)
	if err != nil {
		t.Fatalf("client dial proxy C: %v", err)
	}
	defer client.Close()

	// Send OpenConnectionRequest1 (0x05)
	ocr1 := append([]byte{0x05}, make([]byte, 32)...)
	if _, err := client.Write(ocr1); err != nil {
		t.Fatalf("client write OCR1: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read OCR1 reply through 3-level chain: %v", err)
	}
	if n == 0 || buf[0] != 0x06 {
		t.Fatalf("expected OpenConnectionReply1 (0x06), got 0x%02x (n=%d)", buf[0], n)
	}
	t.Logf("3-level chain: OCR1 reply received: 0x%02x (%d bytes)", buf[0], n)

	// Send a game packet and verify echo
	gamePacket := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0xaa, 0xbb, 0xcc, 0xdd}
	if _, err := client.Write(gamePacket); err != nil {
		t.Fatalf("client write game packet: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read game packet echo through 3-level chain: %v", err)
	}
	if n != len(gamePacket) {
		t.Fatalf("expected echo of %d bytes, got %d bytes", len(gamePacket), n)
	}
	t.Logf("3-level chain: game packet echoed back: %d bytes match", n)
}

// TestRawUDPProxy_ChainDisconnectForwarding verifies that when a client sends
// a RakNet DisconnectNotification to Proxy B, the disconnect is forwarded to
// Proxy A so that Proxy A can also clean up its upstream connection. Without
// this forwarding, multi-level chains with idle_timeout=-1 would leak
// upstream connections forever.
func TestRawUDPProxy_ChainDisconnectForwarding(t *testing.T) {
	// 1. Start fake real server that tracks disconnects
	realServerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen real server: %v", err)
	}
	disconnectReceived := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = realServerConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := realServerConn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			if n > 0 && buf[0] == 0x13 { // raknetDisconnectNotification
				select {
				case disconnectReceived <- struct{}{}:
				default:
				}
			}
			// Echo back for handshake packets
			if n > 0 {
				switch buf[0] {
				case 0x05:
					reply := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00}
					_, _ = realServerConn.WriteToUDP(reply, addr)
				case 0x07:
					reply := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00}
					_, _ = realServerConn.WriteToUDP(reply, addr)
				default:
					_, _ = realServerConn.WriteToUDP(buf[:n], addr)
				}
			}
		}
	}()
	defer func() {
		close(done)
		_ = realServerConn.Close()
	}()
	realServer := realServerConn.LocalAddr().(*net.UDPAddr)

	// 2. Start Proxy A (targets real server)
	proxyAListen := freeUDPPort(t)
	cfgA := &config.ServerConfig{
		ID:            "proxy-a-disc",
		Target:        "127.0.0.1",
		Port:          realServer.Port,
		ListenAddr:    proxyAListen.String(),
		ProxyMode:     "raw_udp",
		ProxyOutbound: "",
		IdleTimeout:   -1, // never disconnect - makes the leak bug visible
	}
	smA := session.NewSessionManager(time.Hour)
	proxyA := NewRawUDPProxy("proxy-a-disc", cfgA, nil, smA)
	if err := proxyA.Start(); err != nil {
		t.Fatalf("start proxy A: %v", err)
	}
	defer proxyA.Stop()

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() { _ = proxyA.Listen(ctxA) }()
	time.Sleep(100 * time.Millisecond)

	// 3. Start Proxy B (targets Proxy A)
	proxyBListen := freeUDPPort(t)
	cfgB := &config.ServerConfig{
		ID:            "proxy-b-disc",
		Target:        "127.0.0.1",
		Port:          proxyAListen.Port,
		ListenAddr:    proxyBListen.String(),
		ProxyMode:     "raw_udp",
		ProxyOutbound: "",
		IdleTimeout:   -1,
	}
	smB := session.NewSessionManager(time.Hour)
	proxyB := NewRawUDPProxy("proxy-b-disc", cfgB, nil, smB)
	if err := proxyB.Start(); err != nil {
		t.Fatalf("start proxy B: %v", err)
	}
	defer proxyB.Stop()

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	go func() { _ = proxyB.Listen(ctxB) }()
	time.Sleep(100 * time.Millisecond)

	// 4. Connect client to Proxy B, do handshake
	client, err := net.DialUDP("udp", nil, proxyBListen)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()

	// Send OpenConnectionRequest1
	ocr1 := append([]byte{0x05}, make([]byte, 32)...)
	if _, err := client.Write(ocr1); err != nil {
		t.Fatalf("write OCR1: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	_, err = client.Read(buf)
	if err != nil {
		t.Fatalf("read OCR1 reply: %v", err)
	}

	// 5. Send disconnect notification
	disconnect := []byte{0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := client.Write(disconnect); err != nil {
		t.Fatalf("write disconnect: %v", err)
	}

	// 6. Verify the real server receives the disconnect through the chain
	select {
	case <-disconnectReceived:
		t.Logf("Real server received disconnect notification through chain")
	case <-time.After(3 * time.Second):
		t.Fatal("Real server did NOT receive disconnect notification through chain - upstream connection leak with idle_timeout=-1")
	}
}
