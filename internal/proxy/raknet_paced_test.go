package proxy

import (
	"context"
	"math"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandertv/go-raknet"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

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
	t.Logf("3MB relayed in %v at 16000kbps", el)
	stats := p.GetRawUDPClientStats()
	if len(stats) != 1 || stats[0].DownBytes < total || stats[0].UpBytes == 0 || stats[0].Route != "direct" {
		t.Fatalf("dashboard stats wrong: %+v", stats)
	}
	if n := p.GetActiveClientCount(); n != 1 {
		t.Fatalf("active clients = %d, want 1", n)
	}
}

// policedUDPRelay forwards client<->proxy datagrams and drops downstream
// traffic above ratePerSec (token bucket, small burst) - a cloud egress cap.
func policedUDPRelay(t *testing.T, proxyAddr *net.UDPAddr, ratePerSec float64) (addr string, dropped *atomic.Int64) {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close(); back.Close() })
	dropped = &atomic.Int64{}
	var client atomic.Pointer[net.UDPAddr]
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			client.Store(a)
			back.Write(buf[:n])
		}
	}()
	go func() {
		buf := make([]byte, 2048)
		burst := ratePerSec / 10
		tokens, last := burst, time.Now()
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			now := time.Now()
			tokens = math.Min(tokens+ratePerSec*now.Sub(last).Seconds(), burst)
			last = now
			if tokens < float64(n) {
				dropped.Add(1)
				continue
			}
			tokens -= float64(n)
			if a := client.Load(); a != nil {
				front.WriteToUDP(buf[:n], a)
			}
		}
	}()
	return front.LocalAddr().String(), dropped
}

// TestRakNetProxyPacedThroughPolicedLink is the vip1-20002-ven case: the
// server bursts far above a policed client link. With downstream_limit_kbps
// just under the cap, every byte must arrive at close to the cap's rate
// instead of collapsing into resends.
func TestRakNetProxyPacedThroughPolicedLink(t *testing.T) {
	srv, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	const total = 1 << 20
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
		chunk := make([]byte, 30<<10)
		chunk[0] = 0xfe
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond) // ~1.5MB/s, 7x the cap
		}
		time.Sleep(20 * time.Second)
	}()

	cm, _ := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	cfg := &config.ServerConfig{
		ID: "policed", Name: "policed", Target: "127.0.0.1",
		Port:       srv.Addr().(*net.UDPAddr).Port,
		ListenAddr: "127.0.0.1:0", Protocol: "raknet", ProxyMode: "raknet", Enabled: true,
		DownstreamLimitKbps: 1400, // 175KB/s under a 200KB/s cap
	}
	if err := cm.AddServer(cfg); err != nil {
		t.Fatal(err)
	}
	p := NewRakNetProxy(cfg.ID, cfg, cm, session.NewSessionManager(time.Hour))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); _ = p.Stop() }()
	go func() { _ = p.Listen(ctx) }()

	relay, dropped := policedUDPRelay(t, p.listener.Addr().(*net.UDPAddr), 200<<10)
	client, err := raknet.Dial(relay)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	client.Write([]byte{0xfe, 1})
	start := time.Now()
	got := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for got < total {
			pk, err := client.ReadPacket()
			if err != nil {
				return
			}
			got += len(pk)
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
	}
	el := time.Since(start)
	t.Logf("got %d/%d in %v (%.0f KB/s), policer dropped %d datagrams", got, total, el.Round(time.Millisecond), float64(got)/1024/el.Seconds(), dropped.Load())
	if got < total {
		t.Fatalf("only %d/%d bytes arrived through a 200KB/s link", got, total)
	}
	if el > 10*time.Second {
		t.Fatalf("1MB took %v through a 200KB/s link: goodput collapsed", el)
	}
}
