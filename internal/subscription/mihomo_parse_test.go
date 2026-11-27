package subscription

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"mcpeserverproxy/internal/config"
)

// 互操作的最强检验：导出的 Clash YAML 项，交给 mihomo 的 ParseProxy 真正构造出站对象。
// 字段拼错、类型不对、缺必填项（如 mieru 的 transport/username/password）都会在这里失败。
func TestMihomoParseProxyAcceptsExportedClashItems(t *testing.T) {
	items := map[string]map[string]any{}

	s5, err := config.ExportPortClashProxy(config.PortShareSpec{Type: "socks5", Server: "203.0.113.9", Port: 1080, Username: "alice", Password: "pass123456", Name: "clash-s5"})
	if err != nil {
		t.Fatal(err)
	}
	items["socks5"] = s5

	https, err := config.ExportPortClashProxy(config.PortShareSpec{Type: "https", Server: "proxy.example.com", Port: 8443, Username: "bob", Password: "secret123456", Name: "clash-https", ServerName: "proxy.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	items["https"] = https

	items["mieru"] = config.ExportMieruClashProxy("clash-mieru", "203.0.113.9", 19443, "vip-user", "mieru-pass-123456")

	items["hysteria2"] = mustClashItem(t, &config.ProxyOutbound{
		Name: "clash-hy2", Type: config.ProtocolHysteria2, Server: "hk.example.com", Port: 18443,
		Password: "vip:longpassword123456", SNI: "abc.proxy.internal",
		CertFingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
	})
	items["hysteria2-bandwidth"] = mustClashItem(t, &config.ProxyOutbound{
		Name: "clash-hy2-bw", Type: config.ProtocolHysteria2, Server: "hk.example.com", Port: 18443,
		Password: "vip:longpassword123456", SNI: "abc.proxy.internal", UpMbps: 100, DownMbps: 200,
		Obfs: "salamander", ObfsPassword: "obfspw123456",
	})
	items["mieru-node"] = mustClashItem(t, &config.ProxyOutbound{
		Name: "clash-mieru-node", Type: config.ProtocolMieru, Server: "203.0.113.9", Port: 19443,
		Username: "vip-user", Password: "mieru-pass-123456",
	})
	items["vmess-ws"] = mustClashItem(t, &config.ProxyOutbound{
		Name: "clash-vmess", Type: config.ProtocolVMess, Server: "us.example.com", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Security: "auto", TLS: true, SNI: "cdn.example.com",
		Network: "ws", WSPath: "/ray", WSHost: "cdn.example.com",
	})
	items["vless-reality"] = mustClashItem(t, &config.ProxyOutbound{
		Name: "clash-vless", Type: config.ProtocolVLESS, Server: "1.2.3.4", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Flow: "xtls-rprx-vision", TLS: true, Reality: true,
		RealityPublicKey: validRealityKeyForTest(t), RealityShortID: "0a1b2c3d", SNI: "www.microsoft.com", Fingerprint: "chrome",
	})

	for name, item := range items {
		t.Run(name, func(t *testing.T) {
			proxy, err := adapter.ParseProxy(item)
			if err != nil {
				t.Fatalf("mihomo ParseProxy rejected %s: %v\nitem=%v", name, err, item)
			}
			if proxy == nil || proxy.Addr() == "" {
				t.Fatalf("mihomo built no usable outbound for %s", name)
			}
			_ = proxy.Close()
		})
	}
}

func mustClashItem(t *testing.T, p *config.ProxyOutbound) map[string]any {
	t.Helper()
	item, err := config.ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func validRealityKeyForTest(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}
