package proxy

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func freeTCPListenAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func newTestProxyPortConfig(id string, listenAddr string) *config.ProxyPortConfig {
	return &config.ProxyPortConfig{
		ID:            id,
		Name:          id,
		ListenAddr:    listenAddr,
		Type:          config.ProxyPortTypeSocks5,
		Enabled:       true,
		ProxyOutbound: "direct",
		AllowList:     []string{"127.0.0.1/32"},
	}
}

func TestProxyPortManagerReloadPreservesUnchangedPorts(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "proxy_ports.json")
	cfgMgr := config.NewProxyPortConfigManager(configPath)

	portA := newTestProxyPortConfig("port-a", freeTCPListenAddr(t))
	portB := newTestProxyPortConfig("port-b", freeTCPListenAddr(t))
	if err := cfgMgr.AddPorts([]*config.ProxyPortConfig{portA, portB}); err != nil {
		t.Fatalf("add initial ports: %v", err)
	}

	mgr := NewProxyPortManager(cfgMgr, nil)
	if err := mgr.Start(true); err != nil {
		t.Fatalf("start proxy ports: %v", err)
	}
	defer mgr.Stop()

	mgr.mu.Lock()
	listenerA := mgr.listeners["port-a"]
	listenerB := mgr.listeners["port-b"]
	if listenerA == nil || listenerB == nil {
		mgr.mu.Unlock()
		t.Fatalf("expected both listeners to start, got A=%v B=%v", listenerA, listenerB)
	}
	portBAddr := listenerB.listener.Addr().String()
	mgr.mu.Unlock()

	clientB, err := net.DialTimeout("tcp", portBAddr, time.Second)
	if err != nil {
		t.Fatalf("dial unchanged port B: %v", err)
	}
	defer clientB.Close()

	changedA := portA.Clone()
	changedA.Username = "user"
	changedA.Password = "pass"
	if err := cfgMgr.UpdatePort("port-a", changedA); err != nil {
		t.Fatalf("update port A: %v", err)
	}

	if err := mgr.Reload(true); err != nil {
		t.Fatalf("reload proxy ports: %v", err)
	}

	mgr.mu.Lock()
	newListenerA := mgr.listeners["port-a"]
	newListenerB := mgr.listeners["port-b"]
	mgr.mu.Unlock()
	if newListenerA == nil || newListenerA == listenerA {
		t.Fatal("changed port A should have been restarted")
	}
	if newListenerB != listenerB {
		t.Fatal("unchanged port B listener should have been preserved")
	}

	if _, err := clientB.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("unchanged port B existing connection was closed on reload: %v", err)
	}
	_ = clientB.SetReadDeadline(time.Now().Add(time.Second))
	resp := make([]byte, 2)
	if _, err := clientB.Read(resp); err != nil {
		t.Fatalf("unchanged port B existing connection stopped responding after reload: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected SOCKS5 greeting response on preserved port B: %v", resp)
	}
}
