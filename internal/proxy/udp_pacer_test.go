package proxy

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandertv/go-raknet"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

func TestPacedPacketConnPacesBulkAndPassesSmall(t *testing.T) {
	rx, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	tx, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := newPacedPacketConn(tx, 800) // 100 KB/s
	defer pc.Close()
	dst := rx.LocalAddr()

	got := make(chan int, 256)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := rx.ReadFrom(buf)
			if err != nil {
				return
			}
			got <- n
		}
	}()

	start := time.Now()
	for i := 0; i < 80; i++ { // 80 KB: fits the 1s queue budget, needs ~0.8s
		if _, err := pc.WriteTo(make([]byte, 1000), dst); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pc.WriteTo(make([]byte, 40), dst); err != nil { // ACK-sized
		t.Fatal(err)
	}
	if n := <-got; n != 40 && time.Since(start) > 50*time.Millisecond {
		t.Fatalf("small datagram was queued behind bulk data (first=%dB after %v)", n, time.Since(start))
	}
	bulk := 0
	deadline := time.After(5 * time.Second)
	for bulk < 80 {
		select {
		case n := <-got:
			if n == 1000 {
				bulk++
			}
		case <-deadline:
			t.Fatalf("only %d/80 bulk datagrams arrived", bulk)
		}
	}
	if el := time.Since(start); el < 600*time.Millisecond || el > 2*time.Second {
		t.Fatalf("80KB at 100KB/s took %v, want ~0.8s", el)
	}
	if d := pc.Dropped(dst); d != 0 {
		t.Fatalf("dropped %d datagrams within budget", d)
	}
}

func TestPacedPacketConnDropsBeyondQueueBudget(t *testing.T) {
	rx, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer rx.Close()
	tx, _ := net.ListenPacket("udp", "127.0.0.1:0")
	pc := newPacedPacketConn(tx, 800) // budget = max(100KB, 64KB) = 100KB
	defer pc.Close()
	for i := 0; i < 200; i++ {
		_, _ = pc.WriteTo(make([]byte, 1000), rx.LocalAddr())
	}
	if d := pc.Dropped(rx.LocalAddr()); d < 90 {
		t.Fatalf("dropped=%d, want the ~100 datagrams beyond the 1s budget", d)
	}
}

// TestRakNetProxyPacedDownstreamDeliversBurst drives a real go-raknet server
// burst through proxy_mode raknet with downstream_limit_kbps: every byte must
// arrive, at the configured rate rather than all at once.
func TestRakNetProxyPacedDownstreamDeliversBurst(t *testing.T) {
	srv, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	const total = 3 << 20
	go func() {
		c, err := srv.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		if _, err := c.Read(buf); err != nil {
			return
		}
		// 30KB every 10ms = 3MB/s: faster than the 2MB/s limit, like a
		// server join burst, but not a loopback-overflowing single blast
		// (go-raknet has no congestion control on either end).
		chunk := make([]byte, 30<<10)
		chunk[0] = 0xfe // game packet; 0x00.. would be eaten as a RakNet internal message
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(10 * time.Second)
	}()

	cm, _ := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	cfg := &config.ServerConfig{
		ID:                  "paced",
		Name:                "paced",
		Target:              "127.0.0.1",
		Port:                srv.Addr().(*net.UDPAddr).Port,
		ListenAddr:          "127.0.0.1:0",
		Protocol:            "raknet",
		ProxyMode:           "raknet",
		Enabled:             true,
		DownstreamLimitKbps: 16000, // 2 MB/s -> ~1.5s for 3 MB
	}
	if err := cm.AddServer(cfg); err != nil {
		t.Fatalf("add server: %v", err)
	}
	p := NewRakNetProxy(cfg.ID, cfg, cm, session.NewSessionManager(time.Hour))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		_ = p.Stop()
	}()
	go func() { _ = p.Listen(ctx) }()

	client, err := raknet.Dial(p.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte{0xfe, 1}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got := 0
	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	for got < total {
		pk, err := client.ReadPacket()
		if err != nil {
			t.Fatalf("read after %d/%d bytes: %v", got, total, err)
		}
		got += len(pk)
	}
	el := time.Since(start)
	if el < time.Second {
		t.Fatalf("3MB arrived in %v: not paced to 2MB/s", el)
	}
	if el > 6*time.Second {
		t.Fatalf("3MB took %v at 2MB/s: relay stalled", el)
	}
	t.Logf("3MB relayed in %v at 16000kbps, pacer drops=%d", el, p.pacer.Dropped(client.LocalAddr()))
}
