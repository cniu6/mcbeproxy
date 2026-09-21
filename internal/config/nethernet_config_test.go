package config

import (
	"strings"
	"testing"
)

func TestNetherNetProxyModeRequiresExplicitTransportConfig(t *testing.T) {
	cfg := &ServerConfig{
		ID:         "nethernet-test",
		Name:       "NetherNet Test",
		Target:     "https://upstream.example",
		Port:       19132,
		ListenAddr: "0.0.0.0:19132",
		Protocol:   ProxyModeRakNet,
		ProxyMode:  ProxyModeNetherNet,
	}
	cfg.Normalize()
	if cfg.GetProxyMode() != ProxyModeNetherNet {
		t.Fatalf("proxy mode = %q, want %q", cfg.GetProxyMode(), ProxyModeNetherNet)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "nethernet_listen_addr") {
		t.Fatalf("Validate() error = %v, want missing NetherNet TLS configuration", err)
	}
}

func TestNetherNetNormalizeDisablesTrickleICE(t *testing.T) {
	cfg := &ServerConfig{
		ID: "nethernet-test", Name: "NetherNet Test", Target: "https://upstream.example", Port: 19132,
		ListenAddr: "0.0.0.0:19132", Protocol: ProxyModeRakNet, ProxyMode: ProxyModeNetherNet,
		NetherNetListenAddr: "0.0.0.0:19132", NetherNetCertFile: "server.crt", NetherNetKeyFile: "server.key",
		NetherNetUpstream: "https://upstream.example:19132", NetherNetDisableTrickleICE: false,
	}
	cfg.Normalize()
	if !cfg.NetherNetDisableTrickleICE {
		t.Fatal("NetherNet must disable trickle ICE with the current HTTP endpoint signaling")
	}
}

func TestNetherNetRelayRequiresICECredentials(t *testing.T) {
	cfg := &ServerConfig{
		ID: "nethernet-test", Name: "NetherNet Test", Target: "https://upstream.example", Port: 19132,
		ListenAddr: "0.0.0.0:19132", Protocol: ProxyModeRakNet, ProxyMode: ProxyModeNetherNet,
		NetherNetListenAddr: "0.0.0.0:19132", NetherNetCertFile: "server.crt", NetherNetKeyFile: "server.key",
		NetherNetUpstream: "https://upstream.example:19132", NetherNetICEGatherPolicy: "relay",
	}
	cfg.Normalize()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ice_servers") {
		t.Fatalf("Validate() error = %v, want missing ICE/TURN credentials", err)
	}
}

func TestNetherNetProxyModeAcceptsWithoutLegacyTargetFields(t *testing.T) {
	cfg := &ServerConfig{
		ID: "nethernet-test", Name: "NetherNet Test", Protocol: ProxyModeRakNet, ProxyMode: ProxyModeNetherNet,
		NetherNetListenAddr: "0.0.0.0:19132", NetherNetCertFile: "server.crt", NetherNetKeyFile: "server.key",
		NetherNetUpstream: "https://upstream.example:19132",
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestNetherNetProxyModeAcceptsCompleteTransportConfig(t *testing.T) {
	cfg := &ServerConfig{
		ID:                  "nethernet-test",
		Name:                "NetherNet Test",
		Target:              "https://upstream.example",
		Port:                19132,
		ListenAddr:          "0.0.0.0:19132",
		Protocol:            ProxyModeRakNet,
		ProxyMode:           ProxyModeNetherNet,
		NetherNetListenAddr: "0.0.0.0:19132",
		NetherNetCertFile:   "server.crt",
		NetherNetKeyFile:    "server.key",
		NetherNetUpstream:   "https://upstream.example:19132",
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
