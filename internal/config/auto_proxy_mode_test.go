package config

import (
	"encoding/json"
	"testing"
)

func TestAutoProxyModeRoundTripAndLegacy(t *testing.T) {
	for _, mode := range []string{"auto", "raw_udp", "", "transparent", "nethernet"} {
		c := ServerConfig{ID: "s", Name: "server", Protocol: "raknet", ProxyMode: mode, Target: "127.0.0.1", Port: 19132, ListenAddr: "127.0.0.1:19133"}
		c.Normalize()
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var next ServerConfig
		if err := json.Unmarshal(b, &next); err != nil {
			t.Fatal(err)
		}
		if next.GetProxyMode() != c.GetProxyMode() {
			t.Fatal("mode changed on round trip")
		}
		if next.SupportsNetherNetRelay() != (mode == "auto") {
			t.Fatalf("relay capability for %q", mode)
		}
		if next.UsesRawUDPTransport() != (mode == "auto" || mode == "raw_udp") {
			t.Fatalf("UDP capability for %q", mode)
		}
		if mode == "auto" {
			if err := next.Validate(); err != nil {
				t.Fatal(err)
			}
			if next.ToDTO("running", 0).ProxyMode != "auto" {
				t.Fatal("DTO lost auto")
			}
		}
		if mode == "" && next.GetProxyMode() != ProxyModeTransparent {
			t.Fatal("legacy default migrated")
		}
	}
}
