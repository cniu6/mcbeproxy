package proxy

import (
	"strings"
	"testing"

	"mcpeserverproxy/internal/config"
)

// TestProtocolCatalogConstructs asserts that every protocol advertised by the
// full build can be instantiated without touching a real server. It guards the
// protocol matrix (Hysteria2 / TUIC / WireGuard / SSR / AnyTLS / Reality /
// Vision) against accidental removal when dependencies are reorganised.
func TestProtocolCatalogConstructs(t *testing.T) {
	base := func(name, protocol string) *config.ProxyOutbound {
		return &config.ProxyOutbound{
			Name:    name,
			Type:    protocol,
			Server:  "127.0.0.1",
			Port:    443,
			Enabled: true,
		}
	}

	ss := base("ss", config.ProtocolShadowsocks)
	ss.Method = "aes-256-gcm"
	ss.Password = "pass"

	vmess := base("vmess", config.ProtocolVMess)
	vmess.UUID = "00000000-0000-0000-0000-000000000001"

	trojan := base("trojan", config.ProtocolTrojan)
	trojan.Password = "pass"
	trojan.TLS = true

	vision := base("vless-vision", config.ProtocolVLESS)
	vision.UUID = "00000000-0000-0000-0000-000000000001"
	vision.TLS = true
	vision.Flow = "xtls-rprx-vision"
	vision.SNI = "example.com"

	reality := base("vless-reality", config.ProtocolVLESS)
	reality.UUID = "00000000-0000-0000-0000-000000000001"
	reality.TLS = true
	reality.Reality = true
	reality.RealityPublicKey = "QdYs12kmf0mAXNOEPgMpLN5dbZUlgvRK2zCqynOmqBk"
	reality.RealityShortID = "0123456789abcdef"
	reality.SNI = "example.com"
	reality.ProviderOptions = map[string]interface{}{
		"type": "vless",
		"reality-opts": map[string]interface{}{
			"public-key": "QdYs12kmf0mAXNOEPgMpLN5dbZUlgvRK2zCqynOmqBk",
			"short-id":   "0123456789abcdef",
		},
	}

	hysteria := base("hysteria2", config.ProtocolHysteria2)
	hysteria.Password = "pass"

	hysteria1 := base("hysteria-v1", config.ProtocolHysteria)
	hysteria1.Password = "pass"
	hysteria1.TLS = true
	hysteria1.SNI = "example.com"
	hysteria1.UpMbps = 100
	hysteria1.DownMbps = 100

	snell := base("snell", config.ProtocolSnell)
	snell.Password = "psk"

	anytls := base("anytls", config.ProtocolAnyTLS)
	anytls.Password = "pass"
	anytls.TLS = true

	socks := base("socks5", config.ProtocolSOCKS5)

	ssr := base("ssr", config.ProtocolShadowsocksR)
	ssr.Password = "pass"
	ssr.ProviderOptions = map[string]interface{}{
		"type": "ssr", "cipher": "aes-256-cfb", "protocol": "origin", "obfs": "plain",
	}

	tuic := base("tuic", config.ProtocolTUIC)
	tuic.UUID = "00000000-0000-0000-0000-000000000001"
	tuic.Password = "pass"
	tuic.TLS = true
	tuic.ProviderOptions = map[string]interface{}{
		"type": "tuic", "uuid": tuic.UUID, "password": "pass",
	}

	wireguard := base("wireguard", config.ProtocolWireGuard)
	wireguard.Port = 51820
	wireguard.ProviderOptions = map[string]interface{}{
		"type":        "wireguard",
		"private-key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
		"public-key":  "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"ip":          "10.0.0.2",
		"udp":         true,
	}

	cases := []struct {
		name string
		cfg  *config.ProxyOutbound
	}{
		{"shadowsocks", ss},
		{"vmess", vmess},
		{"trojan", trojan},
		{"vless-vision", vision},
		{"vless-reality", reality},
		{"hysteria2", hysteria},
		{"hysteria-v1", hysteria1},
		{"snell", snell},
		{"anytls", anytls},
		{"socks5", socks},
		{"ssr", ssr},
		{"tuic", tuic},
		{"wireguard", wireguard},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outbound, err := CreateSingboxOutbound(tc.cfg)
			if err != nil {
				t.Fatalf("create %s: %v", tc.name, err)
			}
			if outbound == nil {
				t.Fatalf("create %s returned nil outbound", tc.name)
			}
			_ = outbound.Close()
		})
	}

	// NaiveProxy is a TCP-only CONNECT protocol and therefore cannot carry
	// MCPE's UDP traffic. It must fail with a clear explanation, not silently.
	naive := base("naive", config.ProtocolNaive)
	naive.Username = "user"
	naive.Password = "pass"
	naive.TLS = true
	if _, err := CreateSingboxOutbound(naive); err == nil {
		t.Fatal("NaiveProxy must be rejected for UDP proxying")
	} else if !strings.Contains(err.Error(), "TCP") {
		t.Fatalf("NaiveProxy error should explain the TCP-only limitation, got: %v", err)
	}
}
