package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/protocol"
	"mcpeserverproxy/internal/session"
)

// TestUDPListenerPreservesPerClientOrder guards the transparent (default)
// mode against reordering: packets used to be spread over a shared worker
// pool, so a burst from one client could reach the server out of order.
func TestUDPListenerPreservesPerClientOrder(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	_ = target.SetReadBuffer(4 << 20)

	cfgMgr, _ := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	listen := freeUDPPort(t)
	cfg := &config.ServerConfig{
		ID: "order", Name: "order", Target: "127.0.0.1", Port: target.LocalAddr().(*net.UDPAddr).Port,
		ListenAddr: listen.String(), Protocol: "raknet", Enabled: true, IdleTimeout: 300,
	}
	if err := cfgMgr.AddServer(cfg); err != nil {
		t.Fatalf("add server: %v", err)
	}
	pool := NewBufferPool(DefaultBufferSize)
	l := NewUDPListener("order", cfg, pool, session.NewSessionManager(time.Hour),
		NewForwarder(protocol.NewProtocolHandler(), pool), cfgMgr)
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Listen(ctx) }()
	defer l.Stop()

	client, err := net.DialUDP("udp4", nil, listen)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	const total = 3000
	pkt := make([]byte, 64)
	pkt[0] = 0x84 // RakNet frame set
	for i := uint32(0); i < total; i++ {
		binary.BigEndian.PutUint32(pkt[1:5], i)
		if _, err := client.Write(pkt); err != nil {
			t.Fatal(err)
		}
		if i%200 == 199 {
			// Short breather so a loaded machine (full suite in parallel)
			// drops nothing to socket-buffer overflow; order is what we test.
			time.Sleep(2 * time.Millisecond)
		}
	}

	buf := make([]byte, 2048)
	last, received, reordered := int64(-1), 0, 0
	for {
		_ = target.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := target.Read(buf)
		if err != nil {
			break
		}
		if n < 5 {
			continue
		}
		seq := int64(binary.BigEndian.Uint32(buf[1:5]))
		if seq < last {
			reordered++
		}
		last = seq
		received++
	}
	if received < total/2 {
		t.Fatalf("only %d/%d packets forwarded", received, total)
	}
	t.Logf("received=%d reordered=%d", received, reordered)
	// Windows loopback itself reorders ~1-2%% of such a burst (measured without
	// the proxy), so the strict check only runs where loopback keeps order.
	if reordered != 0 && runtime.GOOS != "windows" {
		t.Fatalf("%d of %d packets arrived out of order", reordered, received)
	}
}

func TestListenerShardIndexStable(t *testing.T) {
	ap := netip.MustParseAddrPort("1.2.3.4:5")
	if a, b := listenerShardIndex(ap, 64), listenerShardIndex(ap, 64); a != b || a < 0 || a >= 64 {
		t.Fatalf("shard index unstable or out of range: %d %d", a, b)
	}
}
