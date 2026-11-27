package subscription

import (
	"encoding/base64"
	"strings"
	"testing"

	"mcpeserverproxy/internal/config"
)

// 普通端口导出 → 导入器读回，验证 socks5 / http / https 的用户名、密码、地址、TLS 不丢失。
// 同时验证 v2ray base64 订阅整体能被 ParseSubscriptionContent 识别。

func TestRoundTripPortShareSocks5(t *testing.T) {
	link := config.BuildPortShareLink(config.PortShareSpec{
		Type: "socks5", Server: "203.0.113.9", Port: 1080, Username: "alice", Password: "pa:ss word", Name: "家用",
	})
	parsed, ok := parseLink(link)
	if !ok || parsed.Outbound == nil {
		t.Fatalf("socks5 link not parseable: %s", link)
	}
	got := parsed.Outbound
	if got.Type != config.ProtocolSOCKS5 || got.Server != "203.0.113.9" || got.Port != 1080 ||
		got.Username != "alice" || got.Password != "pa:ss word" || got.Name != "家用" {
		t.Fatalf("socks5 roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripPortShareHTTPSWithSNI(t *testing.T) {
	link := config.BuildPortShareLink(config.PortShareSpec{
		Type: "https", Server: "proxy.example.com", Port: 8443, Username: "bob", Password: "secret", Name: "https入口", ServerName: "proxy.example.com",
	})
	parsed, ok := parseLink(link)
	if !ok || parsed.Outbound == nil {
		t.Fatalf("https link not parseable: %s", link)
	}
	got := parsed.Outbound
	if got.Type != config.ProtocolHTTP || !got.TLS || got.SNI != "proxy.example.com" ||
		got.Username != "bob" || got.Password != "secret" || got.Port != 8443 {
		t.Fatalf("https roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripPortShareBase64Subscription(t *testing.T) {
	links := []string{
		config.BuildPortShareLink(config.PortShareSpec{Type: "socks5", Server: "1.1.1.1", Port: 1080, Name: "a"}),
		config.BuildPortShareLink(config.PortShareSpec{Type: "http", Server: "2.2.2.2", Port: 8080, Username: "u", Password: "p", Name: "b"}),
	}
	sub := config.ExportShareSubscription(links)
	if _, err := base64.StdEncoding.DecodeString(sub); err != nil {
		t.Fatalf("subscription must be base64: %v", err)
	}
	parsed, err := ParseSubscriptionContent([]byte(sub))
	if err != nil {
		t.Fatalf("base64 subscription not parseable: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 nodes from subscription, got %d", len(parsed))
	}
}

func TestRoundTripPortShareClashYAML(t *testing.T) {
	item, err := config.ExportPortClashProxy(config.PortShareSpec{
		Type: "socks5", Server: "203.0.113.9", Port: 1080, Username: "alice", Password: "secret", Name: "clash-s5",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := config.MarshalClashYAML([]map[string]interface{}{item})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseClashLikeYAML(string(raw))
	if len(parsed) != 1 {
		t.Fatalf("exported socks5 yaml not parseable: %s", raw)
	}
	got := parsed[0].Outbound
	if got.Type != config.ProtocolSOCKS5 || got.Username != "alice" || got.Password != "secret" || got.Port != 1080 {
		t.Fatalf("clash socks5 roundtrip mismatch: %+v", got)
	}
}

// HY2 入口：认证串 "用户名:密码" 导出后，导入器读回的 password 必须完整保留冒号与后半段。
func TestRoundTripHy2EntryAuthKeepsUserPass(t *testing.T) {
	link := config.BuildHysteria2Link("hk.example.com", 18443, "vip:longpassword123456", "hy2入口", config.Hysteria2LinkOptions{
		SNI: "abc.proxy.internal", CertFingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
	})
	parsed, ok := parseLink(link)
	if !ok {
		t.Fatalf("hy2 link not parseable: %s", link)
	}
	if parsed.Outbound.Password != "vip:longpassword123456" {
		t.Fatalf("hy2 auth lost user:pass form: got %q", parsed.Outbound.Password)
	}
	if !strings.Contains(link, "pinSHA256=") || parsed.Outbound.CertFingerprint == "" {
		t.Fatalf("hy2 pin lost: %+v", parsed.Outbound)
	}
}
