package proxy

import (
	"errors"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

func TestAutoModeRawUDPDoesNotStartSignaling(t *testing.T) {
	c := &config.ServerConfig{ID: "raw-only", Protocol: "raknet", ProxyMode: "raw_udp", Target: "127.0.0.1", Port: 1, ListenAddr: "127.0.0.1:0"}
	raw := NewRawUDPProxy(c.ID, c, nil, session.NewSessionManager(time.Hour))
	if err := raw.Start(); err != nil {
		t.Fatal(err)
	}
	defer raw.Stop()
	if raw.nnRelay.Load() != nil {
		t.Fatal("raw_udp started relay")
	}
	ln, err := net.Listen("tcp", raw.listener.LocalAddr().String())
	if err != nil {
		t.Fatalf("raw_udp occupied TCP: %v", err)
	}
	ln.Close()
	raw.UpdateConfig(c)
	if raw.nnRelay.Load() != nil {
		t.Fatal("raw_udp hot update started relay")
	}
}

func TestAutoModeBusyTransportChange(t *testing.T) {
	c := &config.ServerConfig{ID: "s", Protocol: "raknet", ProxyMode: "raw_udp", ListenAddr: "127.0.0.1:19132"}
	sm := session.NewSessionManager(time.Hour)
	raw := NewRawUDPProxy(c.ID, c, nil, sm)
	p := &ProxyServer{sessionMgr: sm, listeners: map[string]Listener{"s": raw}, listenAddrs: map[string]string{"s": c.ListenAddr}}
	next := *c
	next.ProxyMode = "auto"
	if err := p.ValidateServerTransportChange(&next); err != nil {
		t.Fatal(err)
	}
	active, _ := sm.GetOrCreate("127.0.0.1:1234", "s")
	if err := p.ValidateServerTransportChange(&next); !errors.Is(err, ErrActiveTransportChange) {
		t.Fatalf("busy: %v", err)
	}
	if listenerKind(raw) != "raw_udp" || listenerKindFromConfig(&next) != "auto" {
		t.Fatal("transport kinds conflated")
	}
	raw.UpdateConfig(&next)
	if raw.conf().GetProxyMode() != "raw_udp" {
		t.Fatal("hot update changed mode")
	}
	if err := p.reserveServerTransportChange(c.ID); !errors.Is(err, ErrActiveTransportChange) {
		t.Fatalf("reserve did not reject active session: %v", err)
	}
	if raw.transportChanging.Load() {
		t.Fatal("rejected change froze existing listener")
	}
	sm.RemoveByID(active.ID)
	if err := p.ValidateServerTransportChange(&next); err != nil {
		t.Fatal(err)
	}
	if err := p.reserveServerTransportChange(c.ID); err != nil {
		t.Fatal(err)
	}
	if !raw.transportChanging.Load() {
		t.Fatal("new admissions not frozen")
	}
	if ci, _ := raw.getOrCreateClientKeyed(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, "127.0.0.1:1234", []byte{0x70}); ci != nil {
		t.Fatal("new client admitted after transport reservation")
	}
}
