package api

import (
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func TestRecordServerLatencyUsesServerAutoPingIntervalWhenShorterThanHistoryMinInterval(t *testing.T) {
	globalConfig := config.DefaultGlobalConfig()
	globalConfig.LatencyHistoryMinIntervalMinutes = 10
	globalConfig.ServerAutoPingIntervalMinutesDefault = 10

	configMgr, err := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatalf("NewConfigManager failed: %v", err)
	}
	if err := configMgr.AddServer(&config.ServerConfig{
		ID:                      "srv1",
		Name:                    "srv1",
		Target:                  "127.0.0.1",
		Port:                    19132,
		ListenAddr:              "0.0.0.0:19132",
		Protocol:                "raknet",
		Enabled:                 true,
		ProxyOutbound:           "node-a,node-b",
		AutoPingEnabled:         true,
		AutoPingIntervalMinutes: 1,
	}); err != nil {
		t.Fatalf("AddServer failed: %v", err)
	}

	server := &APIServer{
		globalConfig:         globalConfig,
		configMgr:            configMgr,
		serverLatencyHistory: newServerLatencyHistoryStore(globalConfig),
	}

	base := time.Now().Add(-3 * time.Minute)
	server.RecordServerLatency("srv1", base.UnixMilli(), 91, true, false, "auto_ping")
	server.RecordServerLatency("srv1", base.Add(2*time.Minute).UnixMilli(), 73, true, false, "auto_ping")

	samples := server.serverLatencyHistory.History("srv1")
	if len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(samples))
	}
	if samples[0].LatencyMs != 91 || !samples[0].Online {
		t.Fatalf("unexpected first sample: %+v", samples[0])
	}
	if samples[1].LatencyMs != 73 || !samples[1].Online {
		t.Fatalf("unexpected second sample: %+v", samples[1])
	}
}

func TestRecordServerLatencyStillRespectsGlobalMinIntervalForNonAutoPingSources(t *testing.T) {
	globalConfig := config.DefaultGlobalConfig()
	globalConfig.LatencyHistoryMinIntervalMinutes = 10

	server := &APIServer{
		globalConfig:         globalConfig,
		serverLatencyHistory: newServerLatencyHistoryStore(globalConfig),
	}

	base := time.Now().Add(-3 * time.Minute)
	server.RecordServerLatency("srv1", base.UnixMilli(), 91, true, false, "manual")
	server.RecordServerLatency("srv1", base.Add(2*time.Minute).UnixMilli(), 73, true, false, "manual")

	samples := server.serverLatencyHistory.History("srv1")
	if len(samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(samples))
	}
	if samples[0].LatencyMs != 73 {
		t.Fatalf("expected coalesced latest sample latency 73, got %+v", samples[0])
	}
}

func TestServerLatencyOverviewRunningGatesAllRunningServers(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"running", true},
		{"Running", true},
		{" running ", true},
		{"stopped", false},
		{"", false},
	}
	for _, tc := range cases {
		got := serverLatencyOverviewRunning(config.ServerConfigDTO{Status: tc.status, AutoPingEnabled: false})
		if got != tc.want {
			t.Fatalf("serverLatencyOverviewRunning(status=%q)=%v, want %v", tc.status, got, tc.want)
		}
	}
	// Public-page gate now includes all running servers (including direct
	// and non-raknet protocol servers) so they display online status via
	// TCP connect probe.
	if !shouldExposeServerLatencyOverview(config.ServerConfigDTO{Status: "running", AutoPingEnabled: false}) {
		t.Fatalf("shouldExposeServerLatencyOverview should be true for running servers regardless of auto-ping")
	}
	if shouldExposeServerLatencyOverview(config.ServerConfigDTO{Status: "stopped", AutoPingEnabled: true}) {
		t.Fatalf("shouldExposeServerLatencyOverview should be false for stopped servers")
	}
}

func TestLastKnownServerLatencyReturnsMostRecentPositive(t *testing.T) {
	globalConfig := config.DefaultGlobalConfig()
	globalConfig.LatencyHistoryMinIntervalMinutes = 0
	server := &APIServer{
		globalConfig:         globalConfig,
		serverLatencyHistory: newServerLatencyHistoryStore(globalConfig),
	}

	if _, ok := server.lastKnownServerLatency("srv1"); ok {
		t.Fatalf("expected no last-known latency for empty history")
	}

	// Space samples beyond the history min-interval so they are not coalesced.
	base := time.Now().Add(-40 * time.Minute)
	server.RecordServerLatency("srv1", base.UnixMilli(), 120, true, false, "auto_ping")
	server.RecordServerLatency("srv1", base.Add(15*time.Minute).UnixMilli(), 80, true, false, "auto_ping")
	// A later offline sample (latency 0) must not clobber the last positive value.
	server.RecordServerLatency("srv1", base.Add(30*time.Minute).UnixMilli(), 0, false, false, "auto_ping")

	got, ok := server.lastKnownServerLatency("srv1")
	if !ok || got != 80 {
		t.Fatalf("lastKnownServerLatency=%d ok=%v, want 80 true", got, ok)
	}
}

func TestApplyLastKnownLatencyFillsStuckDetecting(t *testing.T) {
	globalConfig := config.DefaultGlobalConfig()
	globalConfig.LatencyHistoryMinIntervalMinutes = 0
	server := &APIServer{
		globalConfig:         globalConfig,
		serverLatencyHistory: newServerLatencyHistoryStore(globalConfig),
	}
	server.RecordServerLatency("srv1", time.Now().Add(-time.Minute).UnixMilli(), 64, true, false, "auto_ping")

	// Online but no fresh latency: fallback fills last known value + tag.
	got := server.applyLastKnownLatency(map[string]interface{}{
		"server_id": "srv1",
		"online":    true,
		"latency":   int64(0),
	})
	if lat, _ := int64Value(got["latency"]); lat != 64 {
		t.Fatalf("expected fallback latency 64, got %v", got["latency"])
	}
	if stringValue(got["latency_source"]) != "history" {
		t.Fatalf("expected latency_source=history, got %q", stringValue(got["latency_source"]))
	}

	// Offline pings must not be rewritten with stale history.
	off := server.applyLastKnownLatency(map[string]interface{}{
		"server_id": "srv1",
		"online":    false,
		"latency":   int64(-1),
	})
	if lat, _ := int64Value(off["latency"]); lat != -1 {
		t.Fatalf("offline ping latency should stay -1, got %v", off["latency"])
	}
	if _, exists := off["latency_source"]; exists {
		t.Fatalf("offline ping should not be tagged as history")
	}
}

func TestRecordServerLatencyInfoSkipsHistorySourced(t *testing.T) {
	globalConfig := config.DefaultGlobalConfig()
	globalConfig.LatencyHistoryMinIntervalMinutes = 0
	server := &APIServer{
		globalConfig:         globalConfig,
		serverLatencyHistory: newServerLatencyHistoryStore(globalConfig),
	}
	server.RecordServerLatency("srv1", time.Now().Add(-time.Minute).UnixMilli(), 50, true, false, "auto_ping")
	before := len(server.serverLatencyHistory.History("srv1"))

	// A latency surfaced purely from history must not be re-recorded.
	server.recordServerLatencyInfo(map[string]interface{}{
		"server_id":      "srv1",
		"online":         true,
		"latency":        int64(50),
		"latency_source": "history",
	})
	if after := len(server.serverLatencyHistory.History("srv1")); after != before {
		t.Fatalf("history-sourced ping should not be recorded: before=%d after=%d", before, after)
	}

	// Online but zero latency (no fallback available) is not recorded either.
	server.recordServerLatencyInfo(map[string]interface{}{
		"server_id": "srv2",
		"online":    true,
		"latency":   int64(0),
	})
	if n := len(server.serverLatencyHistory.History("srv2")); n != 0 {
		t.Fatalf("online-but-zero-latency ping should not be recorded, got %d samples", n)
	}

	// A definite measurement is recorded.
	server.recordServerLatencyInfo(map[string]interface{}{
		"server_id": "srv3",
		"online":    true,
		"latency":   int64(42),
		"source":    "direct",
	})
	samples := server.serverLatencyHistory.History("srv3")
	if len(samples) != 1 || samples[0].LatencyMs != 42 {
		t.Fatalf("expected one recorded sample of 42ms, got %+v", samples)
	}
}
