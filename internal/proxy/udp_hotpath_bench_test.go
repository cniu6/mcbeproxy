package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// Hot-path benchmarks: one client ping-pongs game-sized datagrams through a
// direct raw_udp / plain_udp listener to a local echo server. ns/op is the
// full proxy round trip (two proxy hops), allocs/op the per-round-trip garbage.

func startBenchUDPEcho(b *testing.B) *net.UDPAddr {
	b.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen echo: %v", err)
	}
	b.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n > 0 && buf[0]&0x80 != 0 && buf[0]&0x60 != 0 {
				continue // a paced proxy's RakNet ACK/NACK: not part of the ping-pong
			}
			_, _ = conn.WriteToUDPAddrPort(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func benchUDPRoundTrip(b *testing.B, listenAddr *net.UDPAddr, afterWarmup ...func()) {
	b.Helper()
	client, err := net.DialUDP("udp4", nil, listenAddr)
	if err != nil {
		b.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	// RakNet frame set (0x84) of a typical in-game size.
	payload := make([]byte, 256)
	payload[0] = 0x84
	buf := make([]byte, 2048)
	// Warm up: session creation and first dial are not the hot path.
	for i := 0; i < 50; i++ {
		_, _ = client.Write(payload)
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(buf); err != nil {
			b.Fatalf("warm-up round trip: %v", err)
		}
	}
	for _, f := range afterWarmup {
		f()
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := client.Read(buf); err != nil {
			b.Fatalf("round trip %d: %v", i, err)
		}
	}
}

func benchServerConfig(id string, echo *net.UDPAddr) *config.ServerConfig {
	return &config.ServerConfig{
		ID:          id,
		Target:      "127.0.0.1",
		Port:        echo.Port,
		ListenAddr:  "127.0.0.1:0",
		IdleTimeout: 300,
		ProxyMode:   "raw_udp",
	}
}

func BenchmarkRawUDPRoundTrip(b *testing.B) {
	benchRawUDPRoundTrip(b, 0)
}

// BenchmarkRawUDPPacedRoundTrip is the same with downstream_limit_kbps set
// far above the traffic: the cost of the pacer when nothing has to wait.
func BenchmarkRawUDPPacedRoundTrip(b *testing.B) {
	benchRawUDPRoundTrip(b, 1000000)
}

func benchRawUDPRoundTrip(b *testing.B, downstreamKbps int) {
	echo := startBenchUDPEcho(b)
	cfg := benchServerConfig("bench-raw", echo)
	cfg.DownstreamLimitKbps = downstreamKbps
	p := NewRawUDPProxy("bench-raw", cfg, nil, session.NewSessionManager(time.Hour))
	if err := p.Start(); err != nil {
		b.Fatalf("start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = p.Listen(ctx) }()
	defer func() { cancel(); _ = p.Stop() }()
	// Measure the post-login steady state, not the bounded Login-parse phase.
	benchUDPRoundTrip(b, p.listener.LocalAddr().(*net.UDPAddr), func() {
		p.clients.Range(func(_, v any) bool {
			v.(*rawUDPClientInfo).loginParseDone.Store(true)
			return true
		})
	})
}

func BenchmarkPlainUDPRoundTrip(b *testing.B) {
	echo := startBenchUDPEcho(b)
	cfg := benchServerConfig("bench-plain", echo)
	cfg.Protocol = "udp"
	p := NewPlainUDPProxy("bench-plain", cfg)
	if err := p.Start(); err != nil {
		b.Fatalf("start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = p.Listen(ctx) }()
	defer func() { cancel(); _ = p.Stop() }()
	benchUDPRoundTrip(b, p.listener.LocalAddr().(*net.UDPAddr))
}

// BenchmarkUDPDirectRoundTrip is the floor: the same ping-pong with no proxy.
func BenchmarkUDPDirectRoundTrip(b *testing.B) {
	benchUDPRoundTrip(b, startBenchUDPEcho(b))
}
