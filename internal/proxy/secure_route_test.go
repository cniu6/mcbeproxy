package proxy

import (
	"context"
	"net"
	"testing"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/singboxcore"
)

type secureRouteDialer struct {
	name     string
	selected chan string
}

func (d *secureRouteDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	b.Close()
	d.selected <- d.name
	return a, nil
}
func (d *secureRouteDialer) Close() error { return nil }

// 新入口必须复用每用户路由和节点计数，不能认证后降级为默认直连。
func TestSecureProxyUserRoutesAndCounts(t *testing.T) {
	selected := make(chan string, 4)
	factory := singboxcore.FactoryFuncs{CreateDialerFunc: func(_ context.Context, p *config.ProxyOutbound) (singboxcore.Dialer, error) {
		return &secureRouteDialer{name: p.Name, selected: selected}, nil
	}}
	manager := NewOutboundManagerWithSingboxFactory(nil, factory)
	for _, name := range []string{"route-a", "route-b"} {
		if err := manager.AddOutbound(&config.ProxyOutbound{Name: name, Type: "socks5", Server: "127.0.0.1", Port: 1080, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	pool := newProxyPortDialerPool(factory)
	defer pool.CloseAll()
	cfg := &config.ProxyPortConfig{ID: "secure", Username: "owner", Password: "fixture-password-a", Users: []config.ProxyPortUser{{Username: "a", Password: "fixture-password-b", ProxyOutbound: "route-a"}, {Username: "b", Password: "fixture-password-c", ProxyOutbound: "route-b"}}}
	l := newProxyPortListener(cfg, manager, pool)
	if err := l.updateAuth(cfg); err != nil {
		t.Fatal(err)
	}
	r := &securePortRuntime{owner: l}
	source := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	for _, user := range []string{"a", "b"} {
		id, err := r.identity(user, source, false)
		if err != nil {
			t.Fatal(err)
		}
		c, err := r.dial(context.Background(), id, "127.0.0.1:19132")
		if err != nil {
			t.Fatal(err)
		}
		want := "route-" + user
		if got := <-selected; got != want {
			t.Fatalf("user %s selected %s", user, got)
		}
		if manager.GetOutboundConnectionCount(want) != 1 {
			t.Fatal("missing node ownership")
		}
		c.Close()
		c.Close()
		id.release()
		if manager.GetOutboundConnectionCount(want) != 0 {
			t.Fatal("node ownership not released exactly once")
		}
	}
}
