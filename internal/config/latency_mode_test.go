package config

import (
	"strings"
	"testing"
)

// baseValidServerConfig returns a ServerConfig that passes Validate() so tests
// can toggle a single field and assert on the exact validation outcome that
// the field change triggered. Using a UDP protocol by default lets latency
// mode / udp_speeder tests run without having to reset the protocol for each
// case.
func baseValidServerConfig() *ServerConfig {
	return &ServerConfig{
		ID:         "srv1",
		Name:       "srv1",
		Target:     "example.com",
		Port:       19132,
		ListenAddr: "0.0.0.0:19132",
		Protocol:   "raknet",
		Enabled:    true,
	}
}

func TestIsValidLatencyMode(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"normal", true},
		{"NORMAL", true},
		{"  aggressive  ", true},
		{"fec_tunnel", true},
		{"fec-tunnel", false},
		{"turbo", false},
	}
	for _, tc := range cases {
		if got := isValidLatencyMode(tc.in); got != tc.want {
			t.Errorf("isValidLatencyMode(%q)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeLatencyMode(t *testing.T) {
	cases := map[string]string{
		"":               LatencyModeNormal,
		"normal":         LatencyModeNormal,
		"  aggressive  ": LatencyModeAggressive,
		"FEC_TUNNEL":     LatencyModeFECTunnel,
		"bogus":          "bogus", // normalize does not silently repair bad input
	}
	for in, want := range cases {
		if got := normalizeLatencyMode(in); got != want {
			t.Errorf("normalizeLatencyMode(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestServerConfig_GetLatencyMode_DefaultsToNormal(t *testing.T) {
	var nilCfg *ServerConfig
	if got := nilCfg.GetLatencyMode(); got != LatencyModeNormal {
		t.Fatalf("nil cfg should default to normal, got %q", got)
	}

	cfg := baseValidServerConfig()
	// Explicitly invalid mode gets reported by Validate; the getter still
	// returns a safe default so hot paths never have to re-check.
	cfg.LatencyMode = "not-a-real-mode"
	if got := cfg.GetLatencyMode(); got != LatencyModeNormal {
		t.Fatalf("unknown mode should fall back to normal, got %q", got)
	}
	if cfg.IsAggressiveLatency() || cfg.IsFECTunnelLatency() {
		t.Fatal("fallback should not report any opt-in mode")
	}
}

func TestServerConfig_Validate_AcceptsKnownLatencyModes(t *testing.T) {
	for _, mode := range []string{"", LatencyModeNormal, LatencyModeAggressive} {
		cfg := baseValidServerConfig()
		cfg.LatencyMode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate(latency_mode=%q) unexpected error: %v", mode, err)
		}
	}
}

func TestServerConfig_Validate_RejectsUnknownLatencyMode(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.LatencyMode = "turbo"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unknown latency_mode")
	}
	if !strings.Contains(err.Error(), "latency_mode") {
		t.Fatalf("error should mention latency_mode, got %v", err)
	}
}

func TestServerConfig_Validate_RejectsAggressiveOnTCP(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.Protocol = "tcp"
	cfg.LatencyMode = LatencyModeAggressive
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error: aggressive is meaningless on pure TCP")
	}
	if !strings.Contains(err.Error(), "aggressive") {
		t.Fatalf("error should mention aggressive, got %v", err)
	}
}

func TestServerConfig_Validate_AggressiveAllowedOnTCPUDP(t *testing.T) {
	// Mixed tcp_udp has a UDP leg so aggressive DSCP on the UDP side is
	// still valuable; reject the combination only for pure "tcp".
	cfg := baseValidServerConfig()
	cfg.Protocol = "tcp_udp"
	cfg.LatencyMode = LatencyModeAggressive
	if err := cfg.Validate(); err != nil {
		t.Fatalf("aggressive should be allowed on tcp_udp, got %v", err)
	}
}

func TestServerConfig_Validate_FECTunnelRequiresUDPSpeeder(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.LatencyMode = LatencyModeFECTunnel
	err := cfg.Validate()
	if err == nil {
		t.Fatal("fec_tunnel without udp_speeder should fail validation")
	}
	if !strings.Contains(err.Error(), "udp_speeder") {
		t.Fatalf("error should mention udp_speeder, got %v", err)
	}
}

func TestServerConfig_Validate_FECTunnelRequiresSpeederEnabled(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.LatencyMode = LatencyModeFECTunnel
	cfg.UDPSpeeder = &UDPSpeederConfig{
		Enabled:    false, // configured but disabled = same as missing for fec_tunnel
		RemoteAddr: "127.0.0.1:4096",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("fec_tunnel with disabled speeder should fail validation")
	}
}

func TestServerConfig_Validate_FECTunnelWithValidSpeederPasses(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.LatencyMode = LatencyModeFECTunnel
	cfg.UDPSpeeder = &UDPSpeederConfig{
		Enabled:    true,
		RemoteAddr: "127.0.0.1:4096",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fec_tunnel with valid enabled speeder should pass, got %v", err)
	}
}

func TestServerConfig_Validate_FECTunnelRejectsTCPOnlyProtocol(t *testing.T) {
	for _, proto := range []string{"tcp", "tcp_udp"} {
		cfg := baseValidServerConfig()
		cfg.Protocol = proto
		cfg.LatencyMode = LatencyModeFECTunnel
		cfg.UDPSpeeder = &UDPSpeederConfig{
			Enabled:    true,
			RemoteAddr: "127.0.0.1:4096",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("fec_tunnel on protocol=%s should fail", proto)
		}
	}
}

func TestServerConfig_Normalize_ClearsProxyModeForNonRakNetProtocols(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "tcp_udp"} {
		cfg := baseValidServerConfig()
		cfg.Protocol = proto
		cfg.ProxyMode = ProxyModePassthrough
		cfg.Normalize()
		if cfg.ProxyMode != "" {
			t.Fatalf("Normalize(protocol=%s) should clear proxy_mode, got %q", proto, cfg.ProxyMode)
		}
		if got := cfg.GetProxyMode(); got != ProxyModeTransparent {
			t.Fatalf("GetProxyMode(protocol=%s) = %q, want %q", proto, got, ProxyModeTransparent)
		}
	}
}

func TestServerConfig_Normalize_PreservesRakNetProxyMode(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.Protocol = "raknet"
	cfg.ProxyMode = ProxyModePassthrough
	cfg.Normalize()
	if cfg.ProxyMode != ProxyModePassthrough {
		t.Fatalf("Normalize should preserve raknet proxy_mode, got %q", cfg.ProxyMode)
	}
}

func TestServerConfig_ToDTO_PropagatesLatencyMode(t *testing.T) {
	cfg := baseValidServerConfig()
	cfg.LatencyMode = LatencyModeAggressive
	dto := cfg.ToDTO("running", 0)
	if dto.LatencyMode != LatencyModeAggressive {
		t.Fatalf("ToDTO should propagate latency_mode, got %q", dto.LatencyMode)
	}
}

func TestServerConfig_ToDTO_NormalizesUnknownLatencyMode(t *testing.T) {
	// An already-persisted config with a bogus value should round-trip to
	// "normal" in the DTO so the UI never shows a broken state even if the
	// JSON on disk was hand-edited.
	cfg := baseValidServerConfig()
	cfg.LatencyMode = "not-real"
	dto := cfg.ToDTO("running", 0)
	if dto.LatencyMode != LatencyModeNormal {
		t.Fatalf("ToDTO should normalize unknown mode to normal, got %q", dto.LatencyMode)
	}
}

func TestServerConfig_JSONRoundtripPersistsLatencyMode(t *testing.T) {
	original := baseValidServerConfig()
	original.LatencyMode = LatencyModeAggressive
	data, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	parsed, err := ServerConfigFromJSON(data)
	if err != nil {
		t.Fatalf("ServerConfigFromJSON failed: %v", err)
	}
	if parsed.LatencyMode != LatencyModeAggressive {
		t.Fatalf("roundtrip lost latency_mode: got %q, want %q", parsed.LatencyMode, LatencyModeAggressive)
	}
	if err := parsed.Validate(); err != nil {
		t.Fatalf("roundtripped config failed validate: %v", err)
	}
}

func TestServerConfig_JSONOmitsLatencyModeWhenNormal(t *testing.T) {
	// We keep `omitempty` on the JSON tag so older files stay clean and the
	// default (empty == normal) keeps an empty string on disk instead of
	// polluting every existing config with redundant `"latency_mode":""`.
	cfg := baseValidServerConfig()
	cfg.LatencyMode = ""
	data, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if strings.Contains(string(data), `"latency_mode"`) {
		t.Fatalf("expected latency_mode to be omitted when empty, got %s", data)
	}
}
