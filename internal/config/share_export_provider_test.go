package config

import "testing"

// 订阅导入的节点带着完整 mihomo 原始项（ss 插件、ssr 混淆与协议参数）。
// 重新导出为 Clash 时这些参数必须保留，否则节点在目标客户端里不可用。
func TestExportClashKeepsImportedProviderOnlyFields(t *testing.T) {
	ssr := &ProxyOutbound{
		Name: "ssr-imported", Type: ProtocolShadowsocksR, Server: "1.2.3.4", Port: 8388,
		Method: "aes-256-cfb", Password: "pw123456",
		ProviderOptions: map[string]interface{}{
			"type": "ssr", "obfs": "tls1.2_ticket_auth", "protocol": "auth_aes128_md5", "obfs-param": "cdn.example.com",
		},
	}
	item, err := ExportClashProxy(ssr)
	if err != nil {
		t.Fatal(err)
	}
	if item["type"] != "ssr" || item["obfs"] != "tls1.2_ticket_auth" || item["protocol"] != "auth_aes128_md5" {
		t.Fatalf("ssr provider fields lost: %v", item)
	}

	ss := &ProxyOutbound{
		Name: "ss-plugin", Type: ProtocolShadowsocks, Server: "5.6.7.8", Port: 443,
		Method: "aes-128-gcm", Password: "pw123456",
		ProviderOptions: map[string]interface{}{
			"type": "ss", "plugin": "v2ray-plugin",
			"plugin-opts": map[string]interface{}{"mode": "websocket", "tls": true},
		},
	}
	item, err = ExportClashProxy(ss)
	if err != nil {
		t.Fatal(err)
	}
	if item["plugin"] != "v2ray-plugin" {
		t.Fatalf("ss plugin lost: %v", item)
	}
	if _, ok := item["plugin-opts"].(map[string]interface{}); !ok {
		t.Fatalf("ss plugin-opts lost: %v", item)
	}
}

// 结构化字段是用户最新编辑的值，覆盖原始项里的同名字段。
func TestExportClashStructFieldsOverrideProviderOptions(t *testing.T) {
	p := &ProxyOutbound{
		Name: "edited", Type: ProtocolShadowsocks, Server: "9.9.9.9", Port: 8388,
		Method: "aes-256-gcm", Password: "new-password",
		ProviderOptions: map[string]interface{}{"type": "ss", "password": "old-password", "server": "old.example.com"},
	}
	item, err := ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	if item["password"] != "new-password" || item["server"] != "9.9.9.9" {
		t.Fatalf("edited struct fields must win over provider options: %v", item)
	}
}

// 内部内核提示（core）不是 mihomo 字段，节点的 provider_options 含它时不能回放。
func TestExportClashIgnoresInternalProviderHints(t *testing.T) {
	p := &ProxyOutbound{
		Name: "hint", Type: ProtocolShadowsocks, Server: "9.9.9.9", Port: 8388,
		Method: "aes-256-gcm", Password: "pw123456",
		ProviderOptions: map[string]interface{}{"core": "mihomo", "transport": "TCP"},
	}
	item, err := ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, bad := item["core"]; bad {
		t.Fatalf("internal hint leaked into clash item: %v", item)
	}
}

func TestExportClashClearsStaleStructuredProviderFields(t *testing.T) {
	p := &ProxyOutbound{
		Name: "edited", Type: ProtocolVLESS, Server: "new.example.com", Port: 443,
		UUID: "new-uuid", TLS: false, Network: "tcp",
		ProviderOptions: map[string]interface{}{
			"type": "vless", "uuid": "old-uuid", "flow": "old-flow", "tls": true,
			"sni": "old.example.com", "network": "ws", "ws-opts": map[string]interface{}{"path": "/old"},
			"provider-only-option": "keep-me",
		},
	}
	item, err := ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"flow", "tls", "sni", "servername", "network", "ws-opts"} {
		if _, exists := item[key]; exists {
			t.Fatalf("stale structured option %q was exported: %v", key, item)
		}
	}
	if item["uuid"] != "new-uuid" || item["provider-only-option"] != "keep-me" {
		t.Fatalf("edited structured field or unknown provider option lost: %v", item)
	}
}

func TestExportClashTLSProxyUsesMihomoServerNameFields(t *testing.T) {
	socks, err := ExportClashProxy(&ProxyOutbound{
		Name: "socks-tls", Type: ProtocolSOCKS5, Server: "socks.example.com", Port: 1080,
		TLS: true, SNI: "socks.example.com", Fingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
	})
	if err != nil {
		t.Fatal(err)
	}
	if socks["tls"] != true || socks["name-cert-verify"] != "socks.example.com" || socks["fingerprint"] != "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726" {
		t.Fatalf("bad mihomo SOCKS TLS fields: %v", socks)
	}
	if _, exists := socks["sni"]; exists {
		t.Fatalf("mihomo SOCKS uses name-cert-verify, not sni: %v", socks)
	}

	httpProxy, err := ExportClashProxy(&ProxyOutbound{
		Name: "http-tls", Type: ProtocolHTTP, Server: "http.example.com", Port: 8443,
		TLS: true, SNI: "http.example.com", Fingerprint: "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726",
	})
	if err != nil {
		t.Fatal(err)
	}
	if httpProxy["type"] != "http" || httpProxy["tls"] != true || httpProxy["sni"] != "http.example.com" || httpProxy["fingerprint"] != "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726" {
		t.Fatalf("bad mihomo HTTP TLS fields: %v", httpProxy)
	}
}

func TestExportClashPreservesUnmodeledTransportOptions(t *testing.T) {
	p := &ProxyOutbound{
		Name: "edited-ws", Type: ProtocolVLESS, Server: "node.example.com", Port: 443,
		UUID: "new-uuid", Network: "ws", WSPath: "/new", WSHost: "new.example.com",
		ProviderOptions: map[string]interface{}{
			"type": "vless", "network": "ws",
			"ws-opts": map[string]interface{}{
				"path": "/old", "max-early-data": 2048,
				"headers": map[string]interface{}{"Host": "old.example.com", "X-Extra": "keep"},
			},
			"reality-opts": map[string]interface{}{"public-key": "old-key", "support-x25519mlkem768": true},
		},
	}
	item, err := ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	ws := item["ws-opts"].(map[string]interface{})
	maxEarlyData, ok := ws["max-early-data"].(float64)
	if ws["path"] != "/new" || !ok || maxEarlyData != 2048 {
		t.Fatalf("updated WS fields or provider-specific options lost: %v", ws)
	}
	headers := ws["headers"].(map[string]interface{})
	if headers["Host"] != "new.example.com" || headers["X-Extra"] != "keep" {
		t.Fatalf("WS headers did not merge safely: %v", headers)
	}

	p.Reality = true
	p.RealityPublicKey = "new-key"
	item, err = ExportClashProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	reality := item["reality-opts"].(map[string]interface{})
	if reality["public-key"] != "new-key" || reality["support-x25519mlkem768"] != true {
		t.Fatalf("Reality model fields or provider-specific options lost: %v", reality)
	}
}

func TestExportClashRejectsUnrepresentableGRPCAuthority(t *testing.T) {
	_, err := ExportClashProxy(&ProxyOutbound{
		Name: "grpc", Type: ProtocolVLESS, Server: "node.example.com", Port: 443,
		UUID: "uuid", Network: "grpc", GRPCServiceName: "svc", GRPCAuthority: "authority.example.com",
	})
	if err == nil {
		t.Fatal("mihomo YAML must not silently discard the gRPC authority")
	}
}
