package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// blackholeFirstDialMgr hands out a real UDP socket (which honours read
// deadlines) for the first dial and a replying conn afterwards.
type blackholeFirstDialMgr struct {
	*countingRawUDPOutboundManager
	mu    sync.Mutex
	dials int
	dead  net.PacketConn
	live  *countingPacketConn
}

func (m *blackholeFirstDialMgr) DialPacketConn(ctx context.Context, outboundName, destination string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dials++
	if m.dials == 1 {
		return m.dead, nil
	}
	return m.live, nil
}

func (m *blackholeFirstDialMgr) dialCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dials
}

// TestRawUDPProxy_BlackholedAssociationIsReplaced is the raw_udp twin of the
// plain test: the 21:59:40 vip1-20002-ven join died because a dead SOCKS5
// association was only noticed at the 30s read timeout, long after Minecraft
// stopped retrying OpenConnectionRequest1 (~6s).
func TestRawUDPProxy_BlackholedAssociationIsReplaced(t *testing.T) {
	silentTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen silent target: %v", err)
	}
	defer silentTarget.Close()
	deadConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dead conn: %v", err)
	}
	defer deadConn.Close()

	live := newCountingPacketConn()
	go func() {
		for {
			select {
			case live.readCh <- []byte("pong"):
			case <-live.closed:
				return
			}
		}
	}()
	mgr := &blackholeFirstDialMgr{countingRawUDPOutboundManager: &countingRawUDPOutboundManager{}, dead: deadConn, live: live}

	cfg := &config.ServerConfig{
		ID:            "raw-blackhole-test",
		Target:        "127.0.0.1",
		Port:          silentTarget.LocalAddr().(*net.UDPAddr).Port,
		ListenAddr:    "127.0.0.1:0",
		ProxyOutbound: "node-a",
		IdleTimeout:   300,
	}
	p := NewRawUDPProxy(cfg.ID, cfg, nil, session.NewSessionManager(time.Hour))
	p.SetOutboundManager(mgr)
	if err := p.Start(); err != nil {
		t.Fatalf("start raw udp proxy: %v", err)
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

	ocr1 := rakNetOffline(raknetOpenConnectionReq1, []byte{11}, make([]byte, 1372-18))
	start := time.Now()
	buf := make([]byte, 2048)
	for time.Since(start) < 8*time.Second {
		if _, err := client.Write(ocr1); err != nil {
			t.Fatalf("client write: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := client.Read(buf); err == nil {
			if string(buf[:n]) != "pong" {
				t.Fatalf("unexpected reply %q", buf[:n])
			}
			if got := mgr.dialCount(); got < 2 {
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
