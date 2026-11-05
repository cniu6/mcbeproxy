package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// 显式 auto 入口自动兼容，热更新复用原信令监听与活跃会话。
func TestRawUDPNetherNetAutoStartsAndSurvivesUpdate(t *testing.T) {
	metadata := `{"name":"target","protocol":9999,"version":"target-defined"}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, metadata)
	}))
	defer upstream.Close()
	cfg := &config.ServerConfig{ID: "raw-auto", Protocol: "raknet", ProxyMode: "auto", Target: "127.0.0.1", Port: 1, ListenAddr: "127.0.0.1:0", IdleTimeout: 300, NetherNetUpstream: upstream.URL}
	p := NewRawUDPProxy(cfg.ID, cfg, nil, session.NewSessionManager(time.Hour))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	r := p.nnRelay.Load()
	if r == nil {
		t.Fatal("automatic NetherNet relay missing")
	}
	select {
	case <-r.firstProbe:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not finish")
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + p.listener.LocalAddr().String() + "/v1/join")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != metadata {
		t.Fatalf("capability response: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
	updated := *cfg
	updated.Name = "hot update"
	p.UpdateConfig(&updated)
	if p.nnRelay.Load() != r {
		t.Fatal("hot update disabled/replaced automatic relay")
	}
	if r.handleDatagram([]byte{0x70, 0x01, 0x02}, p.listener.LocalAddr().(*net.UDPAddr).AddrPort()) {
		t.Error("unrelated UDP packet was consumed by NetherNet")
	}
}

func TestRawUDPNetherNetAutoTCPConflictKeepsUDP(t *testing.T) {
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	cfg := &config.ServerConfig{ID: "raw-auto-conflict", Protocol: "raknet", ProxyMode: "auto", Target: "127.0.0.1", Port: 1, ListenAddr: tcp.Addr().String(), IdleTimeout: 300}
	p := NewRawUDPProxy(cfg.ID, cfg, nil, session.NewSessionManager(time.Hour))
	if err := p.Start(); err != nil {
		t.Fatalf("TCP conflict stopped old UDP path: %v", err)
	}
	defer p.Stop()
	if p.nnRelay.Load() != nil {
		t.Error("relay unexpectedly stole occupied TCP port")
	}
	if _, err := p.listener.WriteToUDP([]byte{0x70}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatalf("UDP listener unusable: %v", err)
	}
}

// 信令已自动启用时，旧 UDP 会话仍经同一个监听端口原样往返。
func TestRawUDPNetherNetAutoKeepsLegacyUDP(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, 2048)
		for {
			n, addr, err := target.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = target.WriteToUDP(buf[:n], addr)
		}
	}()
	defer func() { _ = target.Close(); <-echoDone }()
	cfg := &config.ServerConfig{ID: "raw-auto-legacy", Protocol: "raknet", ProxyMode: "auto", Target: "127.0.0.1", Port: target.LocalAddr().(*net.UDPAddr).Port, ListenAddr: "127.0.0.1:0", IdleTimeout: 300}
	p := NewRawUDPProxy(cfg.ID, cfg, nil, session.NewSessionManager(time.Hour))
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if p.nnRelay.Load() == nil {
		t.Fatal("automatic relay missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Listen(ctx) }()
	client, err := net.DialUDP("udp4", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte{0x70, 0x11, 0x22, 0x33}
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil || string(buf[:n]) != string(payload) {
		t.Fatalf("legacy UDP response=%x err=%v", buf[:n], err)
	}
}
