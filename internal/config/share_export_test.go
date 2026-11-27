package config

import (
	"strings"
	"testing"
)

func TestExportShareLinkShadowsocks(t *testing.T) {
	p := &ProxyOutbound{
		Name: "HK-01", Type: ProtocolShadowsocks, Server: "1.2.3.4", Port: 8388,
		Method: "aes-256-gcm", Password: "pass:word",
	}
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "ss://") || !strings.Contains(link, "@1.2.3.4:8388#HK-01") {
		t.Fatalf("bad ss link: %s", link)
	}
	// method:password 必须 base64 编码（SIP002）
	if strings.Contains(link, "pass") {
		t.Fatalf("ss link leaked plaintext password: %s", link)
	}
}

func TestExportShareLinkVMessRoundTripFields(t *testing.T) {
	p := &ProxyOutbound{
		Name: "美西 WSS", Type: ProtocolVMess, Server: "us.example.com", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", AlterID: 0, Security: "auto",
		TLS: true, SNI: "cdn.example.com", Network: "ws", WSPath: "/ray", WSHost: "cdn.example.com",
	}
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "vmess://") {
		t.Fatalf("bad vmess link: %s", link)
	}
}

func TestExportShareLinkVLESSReality(t *testing.T) {
	p := &ProxyOutbound{
		Name: "reality-node", Type: ProtocolVLESS, Server: "1.2.3.4", Port: 443,
		UUID: "uuid-1", Flow: "xtls-rprx-vision",
		TLS: true, Reality: true, RealityPublicKey: "pbk123", RealityShortID: "sid01",
		SNI: "www.microsoft.com", Fingerprint: "chrome",
	}
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vless://uuid-1@1.2.3.4:443?", "security=reality", "pbk=pbk123", "sid=sid01", "flow=xtls-rprx-vision", "fp=chrome", "#reality-node"} {
		if !strings.Contains(link, want) {
			t.Fatalf("vless link missing %q: %s", want, link)
		}
	}
	if strings.Contains(link, "allowInsecure") {
		t.Fatalf("reality link must not carry allowInsecure: %s", link)
	}
}

func TestExportShareLinkHysteria2(t *testing.T) {
	p := &ProxyOutbound{
		Name: "hy2", Type: ProtocolHysteria2, Server: "hy.example.com", Port: 8443,
		Password: "secretpass", Obfs: "salamander", ObfsPassword: "obfspw",
		PortHopping: "20000-25000", UpMbps: 100, DownMbps: 200,
		SNI: "hy.example.com", CertFingerprint: "abcdef1234567890",
	}
	link, err := ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hysteria2://", "obfs=salamander", "obfs-password=obfspw", "mport=20000-25000", "pinSHA256=abcdef1234567890", "up=100", "down=200", "#hy2"} {
		if !strings.Contains(link, want) {
			t.Fatalf("hy2 link missing %q: %s", want, link)
		}
	}
}

func TestBuildHysteria2LinkPinSHA256(t *testing.T) {
	link := BuildHysteria2Link("proxy.example.com", 18443, "password-with:colon", "我的线路", Hysteria2LinkOptions{
		SNI:             "abc.proxy.internal",
		CertFingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
	})
	if !strings.Contains(link, "pinSHA256=65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726") {
		t.Fatalf("missing pinSHA256: %s", link)
	}
	if !strings.HasPrefix(link, "hysteria2://") || !strings.Contains(link, "@proxy.example.com:18443") {
		t.Fatalf("bad structure: %s", link)
	}
	if !strings.HasSuffix(link, "#%E6%88%91%E7%9A%84%E7%BA%BF%E8%B7%AF") {
		t.Fatalf("fragment not percent-encoded: %s", link)
	}
	// 自签证书导出不能带 insecure=1，否则等于放弃验证
	if strings.Contains(link, "insecure=1") {
		t.Fatalf("pinned link should not skip verification: %s", link)
	}
}

func TestExportClashProxyHysteria2SecureUpstream(t *testing.T) {
	p := &ProxyOutbound{
		Name: "secure-entry", Type: ProtocolHysteria2, Server: "1.2.3.4", Port: 18443,
		Username: "user1", Password: "password123456",
		SecureUpstream: &SecureUpstream{
			Type: "hysteria2", Server: "1.2.3.4", Port: 18443,
			Username: "user1", Password: "password123456",
			ServerName: "x.proxy.internal", CertSHA256: "deadbeef",
		},
	}
	item, err := ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	if item["type"] != "hysteria2" || item["fingerprint"] != "deadbeef" || item["sni"] != "x.proxy.internal" {
		t.Fatalf("bad secure hy2 clash item: %v", item)
	}
	if _, bad := item["skip-cert-verify"]; bad {
		t.Fatalf("pinned export must not skip verification: %v", item)
	}
}

func TestExportClashProxyVMessWS(t *testing.T) {
	p := &ProxyOutbound{
		Name: "ws-node", Type: ProtocolVMess, Server: "s.example.com", Port: 443,
		UUID: "u-1", AlterID: 0, Security: "auto",
		TLS: true, SNI: "cdn.example.com", Network: "ws", WSPath: "/vmess", WSHost: "cdn.example.com",
	}
	item, err := ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	if item["type"] != "vmess" || item["network"] != "ws" || item["tls"] != true {
		t.Fatalf("bad vmess clash item: %v", item)
	}
	ws, ok := item["ws-opts"].(map[string]interface{})
	if !ok || ws["path"] != "/vmess" {
		t.Fatalf("missing ws-opts: %v", item)
	}
	headers, ok := ws["headers"].(map[string]interface{})
	if !ok || headers["Host"] != "cdn.example.com" {
		t.Fatalf("missing ws host header: %v", item)
	}
}

func TestMarshalClashYAMLOrderAndValid(t *testing.T) {
	items := []map[string]interface{}{
		{"name": "n1", "type": "ss", "server": "1.1.1.1", "port": 8388, "cipher": "aes-256-gcm", "password": "pw"},
	}
	raw, err := MarshalClashYAML(items)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasPrefix(text, "proxies:") {
		t.Fatalf("yaml must start with proxies key: %q", text)
	}
	if !strings.Contains(text, "name: n1") || !strings.Contains(text, "cipher: aes-256-gcm") {
		t.Fatalf("yaml missing fields: %q", text)
	}
	// name 应在 type 之前（键序稳定）
	if strings.Index(text, "name:") > strings.Index(text, "type:") {
		t.Fatalf("key order unstable: %q", text)
	}
}

func TestExportShareSubscriptionBase64(t *testing.T) {
	out := ExportShareSubscription([]string{"ss://aaa", "vmess://bbb"})
	if out == "" || strings.Contains(out, "ss://") {
		t.Fatalf("subscription must be base64 encoded, got %q", out)
	}
}

func TestExportShareLinkChainRejected(t *testing.T) {
	p := &ProxyOutbound{Name: "chain-node", Type: ProtocolChain, Chain: []string{"a", "b"}}
	if _, err := ExportShareLink(p); err == nil {
		t.Fatal("chain node must not export as share link")
	}
	if CanExportShare(p) {
		t.Fatal("chain must not be share-exportable")
	}
}
