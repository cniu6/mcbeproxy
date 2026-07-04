package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// TestRawUDPProxy_SameIPReconnectE2E verifies that a player reconnecting from a
// new UDP port (same IP) can still reach the target and does not leak an extra
// upstream client entry.
func TestRawUDPProxy_SameIPReconnectE2E(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	proxyListen := freeUDPPort(t)
	cfg := &config.ServerConfig{
		ID:            "same-ip-e2e",
		Target:        "127.0.0.1",
		Port:          realServer.Port,
		ListenAddr:    proxyListen.String(),
		ProxyMode:     "raw_udp",
		ProxyOutbound: "",
		IdleTimeout:   -1,
	}
	sm := session.NewSessionManager(time.Hour)
	proxy := NewRawUDPProxy("same-ip-e2e", cfg, nil, sm)
	if err := proxy.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = proxy.Listen(ctx) }()
	time.Sleep(100 * time.Millisecond)

	client1, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, proxyListen)
	if err != nil {
		t.Fatalf("client1 dial: %v", err)
	}
	defer client1.Close()

	ocr1 := append([]byte{raknetOpenConnectionReq1}, make([]byte, 32)...)
	if _, err := client1.Write(ocr1); err != nil {
		t.Fatalf("client1 write OCR1: %v", err)
	}
	buf := make([]byte, 2048)
	_ = client1.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := client1.Read(buf)
	if err != nil || n == 0 || buf[0] != raknetOpenConnectionReply1 {
		t.Fatalf("client1 read OCR1 reply: n=%d err=%v first=0x%02x", n, err, buf[0])
	}
	if proxy.GetActiveClientCount() != 1 {
		t.Fatalf("after client1 handshake expected 1 active client, got %d", proxy.GetActiveClientCount())
	}

	// Simulate reconnect: same IP, new ephemeral port after brief silence.
	time.Sleep(sameIPHandshakeGrace + 500*time.Millisecond)

	client2, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, proxyListen)
	if err != nil {
		t.Fatalf("client2 dial: %v", err)
	}
	defer client2.Close()

	if _, err := client2.Write(ocr1); err != nil {
		t.Fatalf("client2 write OCR1: %v", err)
	}
	_ = client2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = client2.Read(buf)
	if err != nil || n == 0 || buf[0] != raknetOpenConnectionReply1 {
		t.Fatalf("client2 read OCR1 reply through proxy after same-IP reconnect: n=%d err=%v first=0x%02x", n, err, buf[0])
	}
	if proxy.GetActiveClientCount() != 1 {
		t.Fatalf("after same-IP reconnect expected 1 active client, got %d", proxy.GetActiveClientCount())
	}

	gamePacket := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0xaa, 0xbb, 0xcc, 0xdd}
	if _, err := client2.Write(gamePacket); err != nil {
		t.Fatalf("client2 write game packet: %v", err)
	}
	_ = client2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = client2.Read(buf)
	if err != nil {
		t.Fatalf("client2 read game echo: %v", err)
	}
	if n != len(gamePacket) {
		t.Fatalf("expected echo of %d bytes, got %d", len(gamePacket), n)
	}
}
