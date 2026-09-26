package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// TestTCPUDPForwardSamePort runs protocol=tcp_udp end to end: one listen
// port, TCP and UDP both forwarded directly to echo servers on one target port.
func TestTCPUDPForwardSamePort(t *testing.T) {
	// Echo servers sharing one port number, like a real tcp+udp target.
	tcpEcho, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	port := tcpEcho.Addr().(*net.TCPAddr).Port
	udpEcho, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skipf("udp port %d busy: %v", port, err)
	}
	defer udpEcho.Close()
	go func() {
		for {
			c, err := tcpEcho.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := udpEcho.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDPAddrPort(buf[:n], a)
		}
	}()

	// Proxy: pick a port free for both TCP and UDP.
	var listen string
	for i := 0; i < 20 && listen == ""; i++ {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p}); err == nil {
			u.Close()
			listen = "127.0.0.1:" + strconv.Itoa(p)
		}
	}
	cfg := &config.ServerConfig{ID: "tcp-udp", Target: "127.0.0.1", Port: port, ListenAddr: listen, Protocol: "tcp_udp", IdleTimeout: 300}
	l := newCombinedListener(NewPlainTCPProxy(cfg.ID, cfg), NewPlainUDPProxy(cfg.ID, cfg))
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Listen(ctx) }()
	defer l.Stop()

	// TCP round trip (and a large payload to exercise the relay copy loop).
	tc, err := net.DialTimeout("tcp", listen, 2*time.Second)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer tc.Close()
	payload := bytes.Repeat([]byte("mcbe"), 64<<10) // 256 KiB
	go func() { _, _ = tc.Write(payload) }()
	got := make([]byte, len(payload))
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tc, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("tcp echo through proxy failed: %v", err)
	}

	// UDP round trip on the same port number.
	uc, err := net.Dial("udp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if _, err := uc.Write([]byte("udp-ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "udp-ping" {
		t.Fatalf("udp echo through proxy = %q, %v", buf[:n], err)
	}
}
