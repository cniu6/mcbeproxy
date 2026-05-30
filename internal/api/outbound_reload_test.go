package api

import (
	"path/filepath"
	"testing"

	"mcpeserverproxy/internal/config"
)

// recordingProxyController records ReloadServer/ReloadProxyPorts calls and lets
// tests control which servers are considered running.
type recordingProxyController struct {
	running          map[string]bool
	reloadedServers  []string
	reloadPortsCalls int
}

func (m *recordingProxyController) StartServer(string) error { return nil }
func (m *recordingProxyController) StopServer(string) error  { return nil }
func (m *recordingProxyController) ReloadServer(serverID string) error {
	m.reloadedServers = append(m.reloadedServers, serverID)
	return nil
}
func (m *recordingProxyController) IsServerRunning(serverID string) bool           { return m.running[serverID] }
func (m *recordingProxyController) GetServerStatus(string) string                  { return "running" }
func (m *recordingProxyController) GetActiveSessionsForServer(string) int          { return 0 }
func (m *recordingProxyController) GetAllServerStatuses() []config.ServerConfigDTO { return nil }
func (m *recordingProxyController) KickPlayer(string, string) int                  { return 0 }
func (m *recordingProxyController) GetServerLatency(string) (int64, bool)          { return 0, false }
func (m *recordingProxyController) ReloadProxyPorts() error {
	m.reloadPortsCalls++
	return nil
}

func contains(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func TestReloadServersUsingOutbound(t *testing.T) {
	dir := t.TempDir()
	outboundMgr := config.NewProxyOutboundConfigManager(filepath.Join(dir, "proxy_outbounds.json"))
	subConfigMgr := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "proxy_subscriptions.json"))
	serverConfigMgr, err := config.NewConfigManager(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatalf("NewConfigManager failed: %v", err)
	}
	portMgr := config.NewProxyPortConfigManager(filepath.Join(dir, "proxy_ports.json"))

	addOutbound := func(name, group string) {
		o := &config.ProxyOutbound{Name: name, Type: config.ProtocolShadowsocks, Server: name + ".example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test", Group: group}
		if err := outboundMgr.AddOutbound(o); err != nil {
			t.Fatalf("AddOutbound %s failed: %v", name, err)
		}
	}
	addOutbound("node-a", "")
	addOutbound("node-b", "")
	addOutbound("node-d", "g1")

	addServer := func(id, proxyOutbound string) {
		s := &config.ServerConfig{ID: id, Name: id, Target: "example.com", Port: 19132, ListenAddr: "0.0.0.0:0", Protocol: "raknet", Enabled: true, ProxyOutbound: proxyOutbound}
		if err := serverConfigMgr.AddServer(s); err != nil {
			t.Fatalf("AddServer %s failed: %v", id, err)
		}
	}
	addServer("srv-single", "node-a")
	addServer("srv-multi", "node-a,node-b")
	addServer("srv-other", "node-b")
	addServer("srv-direct", "direct")
	addServer("srv-stopped", "node-a")
	addServer("srv-group", "@g1")

	ctrl := &recordingProxyController{running: map[string]bool{
		"srv-single": true, "srv-multi": true, "srv-other": true,
		"srv-direct": true, "srv-stopped": false, "srv-group": true,
	}}

	handler := NewProxyOutboundHandler(outboundMgr, subConfigMgr, serverConfigMgr, newMockOutboundManager())
	api := &APIServer{
		configMgr:            serverConfigMgr,
		proxyPortConfigMgr:   portMgr,
		proxyController:      ctrl,
		proxyOutboundHandler: handler,
	}

	// Editing node-a should reload only running servers that reference it directly or via multi-node list.
	api.reloadServersUsingOutbound("node-a")
	if !contains(ctrl.reloadedServers, "srv-single") || !contains(ctrl.reloadedServers, "srv-multi") {
		t.Fatalf("expected srv-single and srv-multi reloaded, got %v", ctrl.reloadedServers)
	}
	for _, bad := range []string{"srv-other", "srv-direct", "srv-stopped", "srv-group"} {
		if contains(ctrl.reloadedServers, bad) {
			t.Fatalf("did not expect %s to be reloaded, got %v", bad, ctrl.reloadedServers)
		}
	}

	// Editing a group member should reload servers selecting that group.
	ctrl.reloadedServers = nil
	api.reloadServersUsingOutbound("node-d")
	if !contains(ctrl.reloadedServers, "srv-group") {
		t.Fatalf("expected srv-group reloaded for group member edit, got %v", ctrl.reloadedServers)
	}

	// A proxy port referencing the edited node triggers a single ReloadProxyPorts.
	port := &config.ProxyPortConfig{ID: "port-1", Name: "port-1", ListenAddr: "0.0.0.0:11080", Type: config.ProxyPortTypeSocks5, Enabled: true, ProxyOutbound: "node-a"}
	if err := portMgr.AddPort(port); err != nil {
		t.Fatalf("AddPort failed: %v", err)
	}
	ctrl.reloadPortsCalls = 0
	api.reloadServersUsingOutbound("node-a")
	if ctrl.reloadPortsCalls != 1 {
		t.Fatalf("expected ReloadProxyPorts called once, got %d", ctrl.reloadPortsCalls)
	}

	// Editing a node no port references must not reload ports.
	ctrl.reloadPortsCalls = 0
	api.reloadServersUsingOutbound("node-b")
	if ctrl.reloadPortsCalls != 0 {
		t.Fatalf("expected ReloadProxyPorts not called, got %d", ctrl.reloadPortsCalls)
	}
}
