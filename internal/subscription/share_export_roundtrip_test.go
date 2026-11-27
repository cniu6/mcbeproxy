package subscription

import (
	"testing"

	"mcpeserverproxy/internal/config"
)

// 导出 → 导入的往返一致性：ExportShareLink 生成的链接必须能被 parseLink 读回，
// 关键字段不丢失。第三方客户端标准之外，这是本项目自用互导的保障。

func roundTripLink(t *testing.T, p *config.ProxyOutbound) ParsedOutbound {
	t.Helper()
	link, err := config.ExportShareLink(p)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}
	parsed, ok := parseLink(link)
	if !ok || parsed.Outbound == nil {
		t.Fatalf("exported link not parseable: %s", link)
	}
	return parsed
}

func TestRoundTripSS(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "ss-node", Type: config.ProtocolShadowsocks, Server: "1.2.3.4", Port: 8388,
		Method: "2022-blake3-aes-256-gcm", Password: "secretpw123456",
	}
	got := roundTripLink(t, src).Outbound
	if got.Type != config.ProtocolShadowsocks || got.Server != src.Server || got.Port != src.Port ||
		got.Method != src.Method || got.Password != src.Password {
		t.Fatalf("ss roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripVMessWS(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "vmess-ws", Type: config.ProtocolVMess, Server: "us.example.com", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Security: "auto",
		TLS: true, SNI: "cdn.example.com", Network: "ws", WSPath: "/ray", WSHost: "cdn.example.com",
	}
	got := roundTripLink(t, src).Outbound
	if got.Type != config.ProtocolVMess || got.UUID != src.UUID || got.Network != "ws" ||
		got.WSPath != "/ray" || got.WSHost != "cdn.example.com" || !got.TLS || got.SNI != "cdn.example.com" {
		t.Fatalf("vmess roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripTrojan(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "trojan-grpc", Type: config.ProtocolTrojan, Server: "t.example.com", Port: 443,
		Password: "tr0janpw", TLS: true, SNI: "t.example.com",
		Network: "grpc", GRPCServiceName: "svc",
	}
	got := roundTripLink(t, src).Outbound
	if got.Type != config.ProtocolTrojan || got.Password != src.Password || got.Network != "grpc" ||
		got.GRPCServiceName != "svc" {
		t.Fatalf("trojan roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripVLESSReality(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "reality", Type: config.ProtocolVLESS, Server: "1.2.3.4", Port: 443,
		UUID: "uuid-1", Flow: "xtls-rprx-vision",
		TLS: true, Reality: true, RealityPublicKey: "pbk-abc", RealityShortID: "sid01",
		SNI: "www.microsoft.com", Fingerprint: "chrome",
	}
	got := roundTripLink(t, src).Outbound
	if got.Type != config.ProtocolVLESS || got.UUID != src.UUID || !got.Reality ||
		got.RealityPublicKey != src.RealityPublicKey || got.Flow != src.Flow ||
		got.Fingerprint != src.Fingerprint {
		t.Fatalf("vless roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripHysteria2(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "hy2", Type: config.ProtocolHysteria2, Server: "hy.example.com", Port: 8443,
		Password: "secretpass", Obfs: "salamander", ObfsPassword: "obfspw",
		PortHopping: "20000-25000", SNI: "hy.example.com",
		CertFingerprint: "abcdef1234567890abcdef1234567890",
		UpMbps:          100, DownMbps: 200,
	}
	got := roundTripLink(t, src).Outbound
	if got.Type != config.ProtocolHysteria2 || got.Password != src.Password ||
		got.Obfs != src.Obfs || got.ObfsPassword != src.ObfsPassword ||
		got.PortHopping != src.PortHopping || got.CertFingerprint != src.CertFingerprint {
		t.Fatalf("hy2 roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripAnyTLS(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "anytls", Type: config.ProtocolAnyTLS, Server: "a.example.com", Port: 8443,
		Password: "anypass123", TLS: true, SNI: "a.example.com",
	}
	got := roundTripLink(t, src).Outbound
	if got.Type != config.ProtocolAnyTLS || got.Password != src.Password || got.SNI != src.SNI {
		t.Fatalf("anytls roundtrip mismatch: %+v", got)
	}
}

func TestRoundTripTUIC(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "tuic", Type: config.ProtocolTUIC, Server: "t.example.com", Port: 10443,
		UUID: "uuid-t", Password: "tuicpass", TLS: true, SNI: "t.example.com",
	}
	got := roundTripLink(t, src).Outbound
	if got.Type != config.ProtocolTUIC || got.UUID != src.UUID || got.Password != src.Password {
		t.Fatalf("tuic roundtrip mismatch: %+v", got)
	}
}

// Clash YAML 往返：导出 YAML 后 parseClashLikeYAML 能读回关键字段。
func TestRoundTripClashYAML(t *testing.T) {
	src := &config.ProxyOutbound{
		Name: "yaml-hy2", Type: config.ProtocolHysteria2, Server: "hy.example.com", Port: 8443,
		Password: "secretpass", Obfs: "salamander", ObfsPassword: "obfspw",
		PortHopping: "20000-25000", SNI: "hy.example.com", UpMbps: 100, DownMbps: 200,
	}
	item, err := config.ExportClashProxy(src)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := config.MarshalClashYAML([]map[string]interface{}{item})
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseClashLikeYAML(string(raw))
	if len(parsed) != 1 {
		t.Fatalf("exported yaml not parseable: %q", raw)
	}
	got := parsed[0].Outbound
	if got.Type != config.ProtocolHysteria2 || got.Password != src.Password ||
		got.Obfs != src.Obfs || got.PortHopping != src.PortHopping ||
		got.UpMbps != src.UpMbps || got.DownMbps != src.DownMbps {
		t.Fatalf("clash yaml roundtrip mismatch: %+v", got)
	}
}
