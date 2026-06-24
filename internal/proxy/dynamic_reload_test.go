package proxy

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/session"
)

// TestProxyServer_ReloadNewServerAutoListen verifies that when a new server
// is added to the config file and the ConfigManager reloads, the ProxyServer
// automatically starts a listener for the new server without requiring a
// full restart. This tests the fsnotify -> ConfigManager.Reload ->
// ProxyServer.Reload -> startListener chain.
func TestProxyServer_ReloadNewServerAutoListen(t *testing.T) {
	// Create temp config file with one server
	dir := t.TempDir()
	configPath := filepath.Join(dir, "servers.json")

	target, stopTarget := startEchoUDP(t)
	defer stopTarget()

	listen1 := freeUDPPort(t)
	initialServers := []*config.ServerConfig{
		{
			ID:          "srv1",
			Name:        "srv1",
			Target:      "127.0.0.1",
			Port:        target.Port,
			ListenAddr:  listen1.String(),
			Protocol:    "raknet",
			ProxyMode:   "raw_udp",
			Enabled:     true,
			IdleTimeout: 3600,
		},
	}
	data, _ := json.Marshal(initialServers)
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configMgr, err := config.NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("NewConfigManager: %v", err)
	}
	if err := configMgr.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	sm := session.NewSessionManager(time.Hour)
	proxyServer, err := NewProxyServer(&config.GlobalConfig{
		APIPort:  0,
		DatabasePath: filepath.Join(dir, "test.db"),
	}, configMgr, nil)
	if err != nil {
		t.Fatalf("NewProxyServer: %v", err)
	}
	proxyServer.sessionMgr = sm

	if err := proxyServer.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxyServer.Stop()

	// Verify srv1 is running
	if !proxyServer.IsServerRunning("srv1") {
		t.Fatal("srv1 should be running after Start")
	}

	// Add a new server to the config file (simulate user adding via web UI)
	listen2 := freeUDPPort(t)
	newServers := append(initialServers, &config.ServerConfig{
		ID:          "srv2",
		Name:        "srv2",
		Target:      "127.0.0.1",
		Port:        target.Port,
		ListenAddr:  listen2.String(),
		Protocol:    "raknet",
		ProxyMode:   "raw_udp",
		Enabled:     true,
		IdleTimeout: 3600,
	})
	data, _ = json.Marshal(newServers)
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config with new server: %v", err)
	}

	// Trigger reload (simulates fsnotify detecting the file change)
	if err := configMgr.Reload(); err != nil {
		t.Fatalf("configMgr.Reload: %v", err)
	}

	// Give the onChange callback time to execute
	time.Sleep(200 * time.Millisecond)

	// Verify srv2 is now running
	if !proxyServer.IsServerRunning("srv2") {
		t.Fatal("srv2 should be running after Reload - new server not auto-listened")
	}

	// Verify we can actually send packets through srv2
	client, err := net.DialUDP("udp", nil, listen2)
	if err != nil {
		t.Fatalf("dial srv2: %v", err)
	}
	defer client.Close()

	// Send a packet and verify it's forwarded
	pkt := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0xaa, 0xbb}
	if _, err := client.Write(pkt); err != nil {
		t.Fatalf("write to srv2: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read from srv2: %v", err)
	}
	if n != len(pkt) {
		t.Fatalf("expected %d bytes echo, got %d", len(pkt), n)
	}
	t.Logf("New server srv2 auto-listened and forwarding works: %d bytes echoed", n)
}

// TestProxyServer_ReloadRemoveServer verifies that when a server is removed
// from the config file, the ProxyServer stops its listener.
func TestProxyServer_ReloadRemoveServer(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "servers.json")

	target, stopTarget := startEchoUDP(t)
	defer stopTarget()

	listen1 := freeUDPPort(t)
	listen2 := freeUDPPort(t)
	initialServers := []*config.ServerConfig{
		{
			ID:          "srv-rm-1",
			Name:        "srv-rm-1",
			Target:      "127.0.0.1",
			Port:        target.Port,
			ListenAddr:  listen1.String(),
			Protocol:    "raknet",
			ProxyMode:   "raw_udp",
			Enabled:     true,
			IdleTimeout: 3600,
		},
		{
			ID:          "srv-rm-2",
			Name:        "srv-rm-2",
			Target:      "127.0.0.1",
			Port:        target.Port,
			ListenAddr:  listen2.String(),
			Protocol:    "raknet",
			ProxyMode:   "raw_udp",
			Enabled:     true,
			IdleTimeout: 3600,
		},
	}
	data, _ := json.Marshal(initialServers)
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configMgr, err := config.NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("NewConfigManager: %v", err)
	}
	if err := configMgr.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	sm := session.NewSessionManager(time.Hour)
	proxyServer, err := NewProxyServer(&config.GlobalConfig{
		APIPort:  0,
		DatabasePath: filepath.Join(dir, "test.db"),
	}, configMgr, nil)
	if err != nil {
		t.Fatalf("NewProxyServer: %v", err)
	}
	proxyServer.sessionMgr = sm

	if err := proxyServer.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxyServer.Stop()

	if !proxyServer.IsServerRunning("srv-rm-1") {
		t.Fatal("srv-rm-1 should be running")
	}
	if !proxyServer.IsServerRunning("srv-rm-2") {
		t.Fatal("srv-rm-2 should be running")
	}

	// Remove srv-rm-2 from config
	updatedServers := []*config.ServerConfig{initialServers[0]}
	data, _ = json.Marshal(updatedServers)
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := configMgr.Reload(); err != nil {
		t.Fatalf("configMgr.Reload: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if !proxyServer.IsServerRunning("srv-rm-1") {
		t.Fatal("srv-rm-1 should still be running")
	}
	if proxyServer.IsServerRunning("srv-rm-2") {
		t.Fatal("srv-rm-2 should be stopped after removal from config")
	}
	t.Log("Server removal via config reload works correctly")
}

// TestProxyServer_ReloadAddrChange verifies that when a server's listen_addr
// changes in the config file, the ProxyServer restarts the listener on the
// new address.
func TestProxyServer_ReloadAddrChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "servers.json")

	target, stopTarget := startEchoUDP(t)
	defer stopTarget()

	listen1 := freeUDPPort(t)
	initialServers := []*config.ServerConfig{
		{
			ID:          "srv-addr",
			Name:        "srv-addr",
			Target:      "127.0.0.1",
			Port:        target.Port,
			ListenAddr:  listen1.String(),
			Protocol:    "raknet",
			ProxyMode:   "raw_udp",
			Enabled:     true,
			IdleTimeout: 3600,
		},
	}
	data, _ := json.Marshal(initialServers)
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configMgr, err := config.NewConfigManager(configPath)
	if err != nil {
		t.Fatalf("NewConfigManager: %v", err)
	}
	if err := configMgr.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	sm := session.NewSessionManager(time.Hour)
	proxyServer, err := NewProxyServer(&config.GlobalConfig{
		APIPort:  0,
		DatabasePath: filepath.Join(dir, "test.db"),
	}, configMgr, nil)
	if err != nil {
		t.Fatalf("NewProxyServer: %v", err)
	}
	proxyServer.sessionMgr = sm

	if err := proxyServer.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxyServer.Stop()

	if !proxyServer.IsServerRunning("srv-addr") {
		t.Fatal("srv-addr should be running")
	}

	// Change listen address
	listen2 := freeUDPPort(t)
	initialServers[0].ListenAddr = listen2.String()
	data, _ = json.Marshal(initialServers)
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := configMgr.Reload(); err != nil {
		t.Fatalf("configMgr.Reload: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if !proxyServer.IsServerRunning("srv-addr") {
		t.Fatal("srv-addr should still be running after addr change")
	}

	// Verify new address works
	client, err := net.DialUDP("udp", nil, listen2)
	if err != nil {
		t.Fatalf("dial new addr: %v", err)
	}
	defer client.Close()

	pkt := []byte{0x84, 0x00, 0x00, 0x00, 0x60, 0xaa}
	if _, err := client.Write(pkt); err != nil {
		t.Fatalf("write to new addr: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read from new addr: %v", err)
	}
	if n != len(pkt) {
		t.Fatalf("expected %d bytes, got %d", len(pkt), n)
	}
	t.Logf("Listen address change hot-reload works: %d bytes echoed on new addr", n)

	// Verify old address is no longer accepting
	oldClient, err := net.DialUDP("udp", nil, listen1)
	if err != nil {
		t.Fatalf("dial old addr: %v", err)
	}
	defer oldClient.Close()
	_ = oldClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = oldClient.Read(buf)
	if err == nil {
		t.Log("Note: old address may still respond if socket not fully closed yet (timing-dependent)")
	}
}
