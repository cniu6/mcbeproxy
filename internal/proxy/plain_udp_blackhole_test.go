package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// TestPlainUDPProxy_BlackholedAssociationIsReplaced reproduces the
// vip1-20002-ven failure: the first SOCKS5 UDP association swallows every
// packet. The proxy must tear it down within plainUDPBlackholeRecoverAfter so
// the client's RakNet retries (still inside Minecraft's ~10s connect window)
// dial a fresh association and get a reply.
func TestPlainUDPProxy_BlackholedAssociationIsReplaced(t *testing.T) {
	deadConn := newCountingPacketConn()
	liveConn := newCountingPacketConn()
	var mu sync.Mutex
	dials := 0
	mgr := &countingRawUDPOutboundManager{
		connFactory: func() *countingPacketConn {
			mu.Lock()
			defer mu.Unlock()
			dials++
			if dials == 1 {
				return deadConn
			}
			return liveConn
		},
	}
	go func() {
		for {
			select {
			case liveConn.readCh <- []byte("pong"):
			case <-liveConn.closed:
				return
			}
		}
	}()

	cfg := &config.ServerConfig{
		ID:            "plain-blackhole-test",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:0",
		ProxyOutbound: "node-a",
		IdleTimeout:   300,
	}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	p.SetOutboundManager(mgr)
	p.UpdateConfig(cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start plain udp proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		_ = p.Stop()
	}()
	go func() { _ = p.Listen(ctx) }()

	client, err := net.DialUDP("udp", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial proxy listener: %v", err)
	}
	defer client.Close()

	start := time.Now()
	buf := make([]byte, 64)
	for time.Since(start) < 8*time.Second {
		if _, err := client.Write([]byte("ocr1")); err != nil {
			t.Fatalf("client write: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := client.Read(buf); err == nil {
			if string(buf[:n]) != "pong" {
				t.Fatalf("unexpected reply %q", buf[:n])
			}
			mu.Lock()
			got := dials
			mu.Unlock()
			if got < 2 {
				t.Fatalf("reply arrived without a fresh association (dials=%d)", got)
			}
			if elapsed := time.Since(start); elapsed > 6*time.Second {
				t.Fatalf("recovered too late for Minecraft's connect window: %v", elapsed)
			}
			return
		}
	}
	t.Fatal("client never received a reply; blackholed association was not replaced")
}

// TestPlainUDPProxy_ClampsRakNetHandshakeMTU guards the other half of the
// vip1-20002-ven failure: plain_udp forwarded Minecraft's 1492-byte
// OpenConnectionRequest1 unchanged, which exceeds 1500 bytes once wrapped in
// a SOCKS5 UDP header and was dropped on the node leg (raw_udp clamped it).
func TestPlainUDPProxy_ClampsRakNetHandshakeMTU(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen fake server: %v", err)
	}
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	cfg := &config.ServerConfig{
		ID:          "plain-mtu-test",
		Target:      "127.0.0.1",
		Port:        serverAddr.Port,
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 300,
		RakNetMTU:   1400,
	}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start plain udp proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		_ = p.Stop()
	}()
	go func() { _ = p.Listen(ctx) }()

	client, err := net.DialUDP("udp", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial proxy listener: %v", err)
	}
	defer client.Close()

	ocr1 := rakNetOffline(raknetOpenConnectionReq1, []byte{11}, make([]byte, 1492-28-18))
	if _, err := client.Write(ocr1); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 2048)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if got := n + rakNetUDPIPv4Overhead; got != 1400 {
		t.Fatalf("OCR1 reached server with mtu %d, want 1400", got)
	}

	reply1 := rakNetOffline(raknetOpenConnectionReply1, make([]byte, 8), []byte{0}, u16(1492))
	if _, err := server.WriteToUDP(reply1, from); err != nil {
		t.Fatalf("server write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if got := binary.BigEndian.Uint16(buf[n-2 : n]); got != 1400 {
		t.Fatalf("OCR1 reply reached client with mtu %d, want 1400", got)
	}
}
