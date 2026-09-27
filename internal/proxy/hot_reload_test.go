package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// TestUpdateConfigWhileForwarding hammers UpdateConfig on running raw_udp and
// plain_udp proxies while packets flow. Under -race this used to report the
// unsynchronised p.config / target / timeout / buffer pool writes.
func TestUpdateConfigWhileForwarding(t *testing.T) {
	for _, mode := range []string{"raw_udp", "plain_udp"} {
		t.Run(mode, func(t *testing.T) {
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				buf := make([]byte, 2048)
				for {
					n, a, err := echo.ReadFromUDPAddrPort(buf)
					if err != nil {
						return
					}
					_, _ = echo.WriteToUDPAddrPort(buf[:n], a)
				}
			}()
			mkCfg := func(idle int) *config.ServerConfig {
				return &config.ServerConfig{ID: "hot-" + mode, Target: "127.0.0.1", Port: echo.LocalAddr().(*net.UDPAddr).Port,
					ListenAddr: "127.0.0.1:0", IdleTimeout: idle, ProxyMode: "raw_udp", BufferSize: 4096 + (idle%2)*4096}
			}
			var p relayHost
			var update func(*config.ServerConfig)
			var udp func() *net.UDPConn
			if mode == "raw_udp" {
				raw := NewRawUDPProxy("hot", mkCfg(300), nil, session.NewSessionManager(time.Hour))
				p, update, udp = raw, raw.UpdateConfig, func() *net.UDPConn { return raw.listener }
			} else {
				plain := NewPlainUDPProxy("hot", mkCfg(300))
				p, update, udp = plain, plain.UpdateConfig, func() *net.UDPConn { return plain.listener }
			}
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			go func() { _ = p.Listen(ctx) }()
			defer func() { cancel(); _ = p.Stop() }()

			client, err := net.DialUDP("udp4", nil, udp().LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					update(mkCfg(200 + i%100))
				}
			}()
			pkt := make([]byte, 64)
			pkt[0] = 0x84
			buf := make([]byte, 256)
			got := 0
			for i := 0; i < 300; i++ {
				_, _ = client.Write(pkt)
				_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if _, err := client.Read(buf); err == nil {
					got++
				}
			}
			close(stop)
			wg.Wait()
			if got == 0 {
				t.Fatal("no packet forwarded while config was being updated")
			}
			if plain, ok := p.(*PlainUDPProxy); ok {
				// buffer_size must now apply live, not only after a restart.
				update(mkCfg(301))
				if size := plain.pool().Size(); size != 8192 {
					t.Fatalf("buffer pool size = %d after hot update, want 8192", size)
				}
				update(mkCfg(300))
				if size := plain.pool().Size(); size != 4096 {
					t.Fatalf("buffer pool size = %d after hot update, want 4096", size)
				}
			}
		})
	}
}

// TestNetherNetRelayHotToggle switches nethernet_relay on and off on a
// running listener through UpdateConfig; before the fix the relay was only
// created in Start, so the switch had no effect until a restart.
func TestNetherNetRelayHotToggle(t *testing.T) {
	cfg := &config.ServerConfig{ID: "toggle", Target: "127.0.0.1", Port: 1, ListenAddr: "127.0.0.1:0", IdleTimeout: 300}
	p := NewPlainUDPProxy(cfg.ID, cfg)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	addr := p.listener.LocalAddr().String()
	probe := func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	if probe() {
		t.Fatal("signaling port open while relay is off")
	}

	on := *cfg
	on.NetherNetRelay = true
	p.UpdateConfig(&on)
	if p.nnRelay.Load() == nil || !probe() {
		t.Fatal("relay not started by UpdateConfig")
	}

	p.UpdateConfig(cfg)
	if p.nnRelay.Load() != nil {
		t.Fatal("relay not stopped by UpdateConfig")
	}
	deadline := time.Now().Add(2 * time.Second)
	for probe() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if probe() {
		t.Fatal("signaling port still open after relay was disabled")
	}
}

func newTestRelay(t *testing.T) (*netherNetRelay, *net.UDPConn) {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	cfg := &config.ServerConfig{ID: "relay-unit", Target: "127.0.0.1", Port: 1, NetherNetRelay: true}
	r, err := newNetherNetRelay("relay-unit", func() *config.ServerConfig { return cfg }, nil, udp)
	if err != nil {
		t.Fatal(err)
	}
	return r, udp
}

// TestNetherNetRelayCapsSessionAddrs checks a session cannot be made to
// remember an unbounded number of client addresses.
func TestNetherNetRelayCapsSessionAddrs(t *testing.T) {
	r, _ := newTestRelay(t)
	defer r.Close()
	up, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &netherNetSession{ufrag: "capU", upstream: up, mediaAddr: up.LocalAddr(), created: time.Now(),
		writeCh: make(chan *netherNetPacket, netherNetRelayWriteQueue), done: make(chan struct{})}
	r.sessions.Store("capU", s)
	r.count.Add(1)
	for i := 0; i < 40; i++ {
		from := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(40000+i))
		r.handleDatagram(stunRequest("capU:cli"), from)
	}
	s.addrsMu.Lock()
	n := len(s.addrs)
	s.addrsMu.Unlock()
	if n != netherNetRelayMaxAddrsPerSession {
		t.Fatalf("session bound %d addresses, want cap %d", n, netherNetRelayMaxAddrsPerSession)
	}
}

// TestNetherNetRelayRefusesOfferAfterClose covers the Close window: an offer
// finishing after Close started must be refused, not published as a session
// whose forwarders Close would never stop (hanging Stop in wg.Wait).
func TestNetherNetRelayRefusesOfferAfterClose(t *testing.T) {
	r, _ := newTestRelay(t)
	media, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()

	done := make(chan struct{})
	go func() { _ = r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}

	answer := "v=0\r\na=ice-ufrag:late\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"a=candidate:1 1 udp 1 127.0.0.1 " + itoa(media.LocalAddr().(*net.UDPAddr).Port) + " typ host\r\n"
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1/v1/join/1", nil)
	if _, err := r.bridge(context.Background(), req, answer); err == nil {
		t.Fatal("offer accepted after Close")
	}
	if r.count.Load() != 0 {
		t.Fatalf("session published after Close: count=%d", r.count.Load())
	}
}

func itoa(n int) string {
	return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(n)).String()[len("0.0.0.0:"):]
}
