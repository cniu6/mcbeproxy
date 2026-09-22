package proxy

import (
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestMihomoProtocolMappingsConstruct(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.ProxyOutbound
	}{
		{
			name: "reality",
			cfg: &config.ProxyOutbound{
				Name: "reality", Type: config.ProtocolVLESS, Server: "example.com", Port: 443,
				UUID: "00000000-0000-0000-0000-000000000001", TLS: true, Reality: true, SNI: "tls.example.com",
				RealityPublicKey: "QdYs12kmf0mAXNOEPgMpLN5dbZUlgvRK2zCqynOmqBk", RealityShortID: "0123456789abcdef",
				ProviderOptions: map[string]interface{}{"type": "vless", "reality-opts": map[string]interface{}{"public-key": "QdYs12kmf0mAXNOEPgMpLN5dbZUlgvRK2zCqynOmqBk", "short-id": "0123456789abcdef"}},
			},
		},
		{
			name: "ssr",
			cfg: &config.ProxyOutbound{
				Name: "ssr", Type: config.ProtocolShadowsocksR, Server: "example.com", Port: 443,
				Password: "password", ProviderOptions: map[string]interface{}{"type": "ssr", "cipher": "aes-256-cfb", "protocol": "origin", "obfs": "plain"},
			},
		},
		{
			name: "tuic",
			cfg: &config.ProxyOutbound{
				Name: "tuic", Type: config.ProtocolTUIC, Server: "example.com", Port: 443,
				UUID: "00000000-0000-0000-0000-000000000001", Password: "password", TLS: true,
				ProviderOptions: map[string]interface{}{"type": "tuic", "uuid": "00000000-0000-0000-0000-000000000001", "password": "password"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outbound, err := newMihomoOutbound(tc.cfg)
			if err != nil {
				t.Fatalf("newMihomoOutbound: %v", err)
			}
			defer outbound.Close()
			if tc.name == "reality" {
				mapping := buildMihomoMapping(tc.cfg)
				if got, ok := mapping["servername"].(string); !ok || got != tc.cfg.SNI {
					t.Fatalf("servername = %v, want %q", mapping["servername"], tc.cfg.SNI)
				}
			}
		})
	}
}
