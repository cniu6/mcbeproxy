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
