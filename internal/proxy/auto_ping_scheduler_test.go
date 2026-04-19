package proxy

import (
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func TestShouldRunScheduledFullScan(t *testing.T) {
	now := time.Date(2026, 4, 18, 4, 30, 0, 0, time.Local)

	daily := &config.ServerConfig{
		AutoPingFullScanMode: config.AutoPingFullScanModeDaily,
		AutoPingFullScanTime: "04:00",
	}
	if due, _ := shouldRunScheduledFullScan(daily, now, time.Time{}); !due {
		t.Fatal("expected daily full scan to be due after scheduled time")
	}
	if due, _ := shouldRunScheduledFullScan(daily, now, now); due {
		t.Fatal("expected daily full scan not to repeat after same-day scan")
	}

	interval := &config.ServerConfig{
		AutoPingFullScanMode:          config.AutoPingFullScanModeInterval,
		AutoPingFullScanIntervalHours: 6,
	}
	if due, _ := shouldRunScheduledFullScan(interval, now, now.Add(-7*time.Hour)); !due {
		t.Fatal("expected interval full scan to be due after interval elapsed")
	}
	if due, _ := shouldRunScheduledFullScan(interval, now, now.Add(-5*time.Hour)); due {
		t.Fatal("expected interval full scan not to be due before interval elapsed")
	}

	portDaily := &config.ProxyPortConfig{
		AutoPingFullScanMode: config.AutoPingFullScanModeDaily,
		AutoPingFullScanTime: "04:00",
	}
	if due, _ := shouldRunScheduledFullScanForProxyPort(portDaily, now, time.Time{}); !due {
		t.Fatal("expected proxy port daily full scan to be due after scheduled time")
	}
}

func TestSelectAutoPingTargets_PartialUsesCurrentAndTopCandidates(t *testing.T) {
	outboundCfgMgr := config.NewProxyOutboundConfigManager(filepath.Join(t.TempDir(), "proxy_outbounds.json"))
	manager := NewOutboundManager(nil)

	nodes := []*config.ProxyOutbound{
		{Name: "node-a", Type: config.ProtocolVLESS, Server: "a.example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Enabled: true, UDPLatencyMs: 90},
		{Name: "node-b", Type: config.ProtocolVLESS, Server: "b.example.com", Port: 443, UUID: "22222222-2222-2222-2222-222222222222", Enabled: true, UDPLatencyMs: 70},
		{Name: "node-c", Type: config.ProtocolVLESS, Server: "c.example.com", Port: 443, UUID: "33333333-3333-3333-3333-333333333333", Enabled: true, UDPLatencyMs: 50},
		{Name: "node-d", Type: config.ProtocolVLESS, Server: "d.example.com", Port: 443, UUID: "44444444-4444-4444-4444-444444444444", Enabled: true, UDPLatencyMs: 30},
	}
	for _, node := range nodes {
		if err := outboundCfgMgr.AddOutbound(node); err != nil {
			t.Fatalf("AddOutbound(configMgr) failed: %v", err)
		}
		if err := manager.AddOutbound(node); err != nil {
			t.Fatalf("AddOutbound(outboundMgr) failed: %v", err)
		}
	}
	manager.SetServerSelectedNode("srv1", "node-b")
	manager.SetServerNodeLatency("srv1", "node-a", config.LoadBalanceSortUDP, 80)
	manager.SetServerNodeLatency("srv1", "node-c", config.LoadBalanceSortUDP, 40)
	manager.SetServerNodeLatency("srv1", "node-d", config.LoadBalanceSortUDP, 20)

	server := &config.ServerConfig{
		ID:                    "srv1",
		AutoPingTopCandidates: 2,
	}
	proxyServer := &ProxyServer{
		outboundMgr:            manager,
		proxyOutboundConfigMgr: outboundCfgMgr,
	}

	targets, fallbackFullScan := proxyServer.selectAutoPingTargets(server, []string{"node-a", "node-b", "node-c", "node-d"}, config.LoadBalanceSortUDP)
	if fallbackFullScan {
		t.Fatal("expected partial scan target selection, got fallback full scan")
	}
	if len(targets) != 3 {
		t.Fatalf("expected current node + top 2 candidates, got %v", targets)
	}
	if targets[0] != "node-b" {
		t.Fatalf("expected current node first, got %v", targets)
	}
	if targets[1] != "node-d" || targets[2] != "node-c" {
		t.Fatalf("expected best candidates ordered by latency, got %v", targets)
	}
}

func TestSelectAutoPingTargets_BootstrapSubsetWithoutSamples(t *testing.T) {
	server := &config.ServerConfig{ID: "srv1", AutoPingTopCandidates: 2}
	proxyServer := &ProxyServer{
		outboundMgr:            NewOutboundManager(nil),
		proxyOutboundConfigMgr: config.NewProxyOutboundConfigManager(filepath.Join(t.TempDir(), "proxy_outbounds.json")),
	}
	targets, fallbackFullScan := proxyServer.selectAutoPingTargets(server, []string{"node-a", "node-b", "node-c", "node-d"}, config.LoadBalanceSortUDP)
	if fallbackFullScan {
		t.Fatal("expected rotating bootstrap subset when no latency samples exist")
	}
	if len(targets) != 2 {
		t.Fatalf("expected bootstrap subset with top candidate size, got %v", targets)
	}
	if targets[0] != "node-a" || targets[1] != "node-b" {
		t.Fatalf("expected bootstrap subset to start from first nodes, got %v", targets)
	}

	targets, fallbackFullScan = proxyServer.selectAutoPingTargets(server, []string{"node-a", "node-b", "node-c", "node-d"}, config.LoadBalanceSortUDP)
	if fallbackFullScan {
		t.Fatal("expected rotating bootstrap subset on subsequent selection")
	}
	if len(targets) != 2 {
		t.Fatalf("expected second bootstrap subset with top candidate size, got %v", targets)
	}
	if targets[0] != "node-c" || targets[1] != "node-d" {
		t.Fatalf("expected bootstrap subset rotation across calls, got %v", targets)
	}
}
