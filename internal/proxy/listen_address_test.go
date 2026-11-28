package proxy

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"

	"github.com/sandertv/go-raknet"
)

func TestListenNetworkForAddress(t *testing.T) {
	for _, tc := range []struct{ network, address, want string }{
		{"tcp", "0.0.0.0:20003", "tcp4"},
		{"udp", "127.0.0.1:20003", "udp4"},
		{"udp", "192.0.2.1:20003", "udp4"},
		{"tcp", ":20003", "tcp"},
		{"udp", "[::]:20003", "udp"},
		{"udp", "[fe80::1%eth0]:20003", "udp"},
		{"tcp", "[::ffff:192.0.2.1]:20003", "tcp"},
		{"tcp", "localhost:20003", "tcp"},
		{"tcp6", "0.0.0.0:20003", "tcp6"},
		{"unix", "127.0.0.1:20003", "unix"},
	} {
		if got := listenNetworkForAddress(tc.network, tc.address); got != tc.want {
			t.Errorf("%s %s: network = %s, want %s", tc.network, tc.address, got, tc.want)
		}
	}
}

func TestMinecraftListenersBindIPv4Wildcard(t *testing.T) {
	origin, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	origin.PongData([]byte("MCPE;IPv4 test;0;0;0;1;1;Test;Survival;1;0;0;"))
	cfgMgr, err := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"raknet", "passthrough", "mitm"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.ServerConfig{ListenAddr: "0.0.0.0:0", Target: "127.0.0.1", Port: origin.Addr().(*net.UDPAddr).Port}
			var bound net.Addr
			switch mode {
			case "raknet":
				p := NewRakNetProxy(mode, cfg, cfgMgr, nil)
				if err := p.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = p.Stop() })
				bound = p.listener.Addr()
			case "passthrough":
				p := NewPassthroughProxy(mode, cfg, cfgMgr, nil)
				if err := p.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = p.Stop() })
				bound = p.listener.Addr()
			case "mitm":
				p := NewMITMProxy(mode, cfg, cfgMgr, nil)
				if err := p.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = p.Stop() })
				bound = p.listener.Addr()
			}
			addr := bound.(*net.UDPAddr)
			if !addr.IP.Equal(net.IPv4zero) {
				t.Fatalf("listener bound to %s, want IPv4 wildcard", addr)
			}
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if _, err := raknet.PingContext(ctx, peer.String()); err != nil {
				t.Fatalf("IPv4 RakNet ping: %v", err)
			}
		})
	}
}
