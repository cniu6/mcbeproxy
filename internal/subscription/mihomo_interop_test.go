package subscription

import (
	"encoding/base64"
	"testing"

	"github.com/metacubex/mihomo/common/convert"
	"mcpeserverproxy/internal/config"
)

// 互操作：把本项目导出的链接交给 mihomo 自己的 v2ray 订阅转换器读取。
// 这里不再用本项目的解析器“自证”，而是检验 mihomo（Clash.Meta 内核）是否按我们的意图理解。
func TestMihomoConvertsExportedLinks(t *testing.T) {
	cases := []struct {
		name string
		link string
		want map[string]any
	}{
		{
			name: "socks5 带账号",
			link: config.BuildPortShareLink(config.PortShareSpec{Type: "socks5", Server: "203.0.113.9", Port: 1080, Username: "alice", Password: "pass123456", Name: "s5"}),
			want: map[string]any{"type": "socks5", "server": "203.0.113.9", "username": "alice", "password": "pass123456"},
		},
		{
			name: "https 入口 → http+tls",
			link: config.BuildPortShareLink(config.PortShareSpec{Type: "https", Server: "proxy.example.com", Port: 8443, Username: "bob", Password: "secret123456", Name: "h", ServerName: "proxy.example.com"}),
			want: map[string]any{"type": "http", "server": "proxy.example.com", "username": "bob", "password": "secret123456", "tls": true},
		},
		{
			name: "hy2 入口 user:pass 与 pinSHA256",
			link: config.BuildHysteria2Link("hk.example.com", 18443, "vip:longpassword123456", "hy2", config.Hysteria2LinkOptions{
				SNI: "abc.proxy.internal", CertFingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
			}),
			want: map[string]any{"type": "hysteria2", "server": "hk.example.com", "password": "vip:longpassword123456", "fingerprint": "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726"},
		},
		{
			name: "vless reality",
			link: mustShareLink(t, &config.ProxyOutbound{
				Name: "vr", Type: config.ProtocolVLESS, Server: "1.2.3.4", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
				Flow: "xtls-rprx-vision", TLS: true, Reality: true, RealityPublicKey: "pbk-abc", RealityShortID: "sid01", SNI: "www.microsoft.com", Fingerprint: "chrome",
			}),
			want: map[string]any{"type": "vless", "server": "1.2.3.4", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxies, err := convert.ConvertsV2Ray([]byte(tc.link))
			if err != nil {
				t.Fatalf("mihomo rejected link %q: %v", tc.link, err)
			}
			if len(proxies) != 1 {
				t.Fatalf("mihomo produced %d proxies for %q", len(proxies), tc.link)
			}
			got := proxies[0]
			for k, v := range tc.want {
				if !sameValue(got[k], v) {
					t.Fatalf("mihomo field %q = %v, want %v (link %s)", k, got[k], v, tc.link)
				}
			}
		})
	}
}

// 整体 base64 订阅同样要被 mihomo 接收（v2rayN 通用订阅格式）。
func TestMihomoConvertsBase64Subscription(t *testing.T) {
	links := config.BuildPortShareLink(config.PortShareSpec{Type: "socks5", Server: "1.1.1.1", Port: 1080, Name: "a"}) + "\n" +
		config.BuildPortShareLink(config.PortShareSpec{Type: "http", Server: "2.2.2.2", Port: 8080, Username: "u", Password: "p1234567", Name: "b"}) + "\n"
	sub := base64.StdEncoding.EncodeToString([]byte(links))
	proxies, err := convert.ConvertsV2Ray([]byte(sub))
	if err != nil || len(proxies) != 2 {
		t.Fatalf("mihomo subscription parse: n=%d err=%v", len(proxies), err)
	}
}

func TestPortSubscriptionPreservesEscapedCredentials(t *testing.T) {
	const username, password = "alice@local", "pass word+%"
	plain := config.BuildPortShareLink(config.PortShareSpec{
		Type: "socks5", Server: "2001:db8::1", Port: 1080, Username: username, Password: password, Name: "家用 01",
	})
	link, err := config.SubscriptionShareLink(plain)
	if err != nil {
		t.Fatal(err)
	}
	content := config.ExportShareSubscription([]string{link})
	proxies, err := convert.ConvertsV2Ray([]byte(content))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("mihomo parse: n=%d err=%v", len(proxies), err)
	}
	if proxies[0]["username"] != username || proxies[0]["password"] != password {
		t.Fatal("mihomo lost credentials")
	}
	items, err := ParseSubscriptionContent([]byte(content))
	if err != nil || len(items) != 1 || items[0].Outbound.Username != username || items[0].Outbound.Password != password {
		t.Fatal("mcbeproxy lost credentials on import")
	}
}

func mustShareLink(t *testing.T, p *config.ProxyOutbound) string {
	t.Helper()
	link, err := config.ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	return link
}

func sameValue(got any, want any) bool {
	switch w := want.(type) {
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	case string:
		g, ok := got.(string)
		return ok && g == w
	}
	return false
}
