package config

import "testing"

func TestServerConfigAutoPingDefaults(t *testing.T) {
	cfg := &ServerConfig{}
	if got := cfg.GetAutoPingTopCandidates(); got != defaultAutoPingTopCandidates {
		t.Fatalf("GetAutoPingTopCandidates() = %d, want %d", got, defaultAutoPingTopCandidates)
	}
	if got := cfg.GetAutoPingFullScanMode(); got != AutoPingFullScanModeDisabled {
		t.Fatalf("GetAutoPingFullScanMode() = %q, want %q", got, AutoPingFullScanModeDisabled)
	}
	if got := cfg.GetAutoPingFullScanTime(); got != defaultAutoPingFullScanTime {
		t.Fatalf("GetAutoPingFullScanTime() = %q, want %q", got, defaultAutoPingFullScanTime)
	}
	if got := cfg.GetAutoPingFullScanIntervalHours(); got != defaultAutoPingFullScanIntervalHr {
		t.Fatalf("GetAutoPingFullScanIntervalHours() = %d, want %d", got, defaultAutoPingFullScanIntervalHr)
	}
}

func TestServerConfigValidateRejectsInvalidAutoPingFullScanTime(t *testing.T) {
	cfg := &ServerConfig{
		ID:                            "s1",
		Name:                          "demo",
		Target:                        "example.com",
		Port:                          19132,
		ListenAddr:                    "0.0.0.0:19132",
		Protocol:                      "raknet",
		Enabled:                       true,
		AutoPingFullScanMode:          AutoPingFullScanModeDaily,
		AutoPingFullScanTime:          "25:99",
		AutoPingFullScanIntervalHours: 24,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid auto_ping_full_scan_time to fail validation")
	}
}

func TestServerConfigValidateRejectsInvalidAutoPingFullScanMode(t *testing.T) {
	cfg := &ServerConfig{
		ID:                   "s1",
		Name:                 "demo",
		Target:               "example.com",
		Port:                 19132,
		ListenAddr:           "0.0.0.0:19132",
		Protocol:             "raknet",
		Enabled:              true,
		AutoPingFullScanMode: "weekly",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid auto_ping_full_scan_mode to fail validation")
	}
}

func TestProxyPortConfigAutoPingDefaults(t *testing.T) {
	cfg := &ProxyPortConfig{}
	cfg.ApplyDefaults()
	if got := cfg.GetAutoPingTopCandidates(); got != defaultAutoPingTopCandidates {
		t.Fatalf("GetAutoPingTopCandidates() = %d, want %d", got, defaultAutoPingTopCandidates)
	}
	if got := cfg.GetAutoPingFullScanMode(); got != AutoPingFullScanModeDisabled {
		t.Fatalf("GetAutoPingFullScanMode() = %q, want %q", got, AutoPingFullScanModeDisabled)
	}
	if got := cfg.GetAutoPingFullScanTime(); got != defaultAutoPingFullScanTime {
		t.Fatalf("GetAutoPingFullScanTime() = %q, want %q", got, defaultAutoPingFullScanTime)
	}
	if got := cfg.GetAutoPingFullScanIntervalHours(); got != defaultAutoPingFullScanIntervalHr {
		t.Fatalf("GetAutoPingFullScanIntervalHours() = %d, want %d", got, defaultAutoPingFullScanIntervalHr)
	}
}

func TestProxyPortConfigValidateRejectsInvalidAutoPingSettings(t *testing.T) {
	cfg := &ProxyPortConfig{
		ID:                            "p1",
		Name:                          "port-1",
		ListenAddr:                    "0.0.0.0:1080",
		Type:                          ProxyPortTypeHTTP,
		Enabled:                       true,
		AutoPingIntervalMinutes:       10,
		AutoPingTopCandidates:         10,
		AutoPingFullScanMode:          AutoPingFullScanModeDaily,
		AutoPingFullScanTime:          "24:61",
		AutoPingFullScanIntervalHours: 24,
		AllowList:                     []string{"0.0.0.0/0"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid auto_ping_full_scan_time to fail validation")
	}
}

func TestGlobalConfigAutoPingDefaults(t *testing.T) {
	cfg := DefaultGlobalConfig()
	if got := cfg.GetServerAutoPingIntervalMinutesDefault(); got != defaultAutoPingIntervalMinutes {
		t.Fatalf("GetServerAutoPingIntervalMinutesDefault() = %d, want %d", got, defaultAutoPingIntervalMinutes)
	}
	if got := cfg.GetServerAutoPingTopCandidatesDefault(); got != defaultAutoPingTopCandidates {
		t.Fatalf("GetServerAutoPingTopCandidatesDefault() = %d, want %d", got, defaultAutoPingTopCandidates)
	}
	if got := cfg.GetProxyPortAutoPingIntervalMinutesDefault(); got != defaultAutoPingIntervalMinutes {
		t.Fatalf("GetProxyPortAutoPingIntervalMinutesDefault() = %d, want %d", got, defaultAutoPingIntervalMinutes)
	}
	if got := cfg.GetProxyPortAutoPingTopCandidatesDefault(); got != defaultAutoPingTopCandidates {
		t.Fatalf("GetProxyPortAutoPingTopCandidatesDefault() = %d, want %d", got, defaultAutoPingTopCandidates)
	}
}

func TestGlobalConfigValidateRejectsInvalidAutoPingDefaults(t *testing.T) {
	cfg := DefaultGlobalConfig()
	cfg.ServerAutoPingFullScanModeDefault = AutoPingFullScanModeDaily
	cfg.ServerAutoPingFullScanTimeDefault = "99:99"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid server auto ping defaults to fail validation")
	}
}
