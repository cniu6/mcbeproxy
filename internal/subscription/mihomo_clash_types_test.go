package subscription

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"

	"mcpeserverproxy/internal/config"
)

// 每个结构化协议的 Clash 导出项都必须被 mihomo 的 ParseProxy 构造成出站对象。
// 覆盖 ss / ssr / vmess / vless / trojan / hysteria / hysteria2 / tuic / anytls /
// socks5 / http / snell / mieru。
func TestMihomoParseProxyAcceptsEveryClashExportType(t *testing.T) {
	nodes := []*config.ProxyOutbound{
		{Name: "ss", Type: config.ProtocolShadowsocks, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pw123456"},
		{Name: "ssr", Type: config.ProtocolShadowsocksR, Server: "1.2.3.4", Port: 8388, Method: "aes-256-cfb", Password: "pw123456",
			ProviderOptions: map[string]interface{}{"type": "ssr", "obfs": "plain", "protocol": "origin"}},
		{Name: "vmess", Type: config.ProtocolVMess, Server: "us.example.com", Port: 443, UUID: matrixUUID, Security: "auto",
			TLS: true, SNI: "cdn.example.com", Network: "ws", WSPath: "/ray", WSHost: "cdn.example.com"},
		{Name: "vless", Type: config.ProtocolVLESS, Server: "1.2.3.4", Port: 443, UUID: matrixUUID, TLS: true, SNI: "www.example.com"},
		{Name: "trojan", Type: config.ProtocolTrojan, Server: "t.example.com", Port: 443, Password: "tr0jan-pass",
			TLS: true, SNI: "t.example.com", Network: "grpc", GRPCServiceName: "svc"},
		{Name: "hysteria2", Type: config.ProtocolHysteria2, Server: "hy.example.com", Port: 8443, Password: "vip:longpassword123456",
			SNI: "hy.example.com", UpMbps: 100, DownMbps: 200, Obfs: "salamander", ObfsPassword: "obfspw123456"},
		{Name: "hysteria", Type: config.ProtocolHysteria, Server: "h1.example.com", Port: 8443, Password: "auth-pass-123",
			SNI: "h1.example.com", UpMbps: 50, DownMbps: 100},
		{Name: "tuic", Type: config.ProtocolTUIC, Server: "t.example.com", Port: 10443, UUID: matrixUUID, Password: "tuicpass",
			TLS: true, SNI: "t.example.com"},
		{Name: "anytls", Type: config.ProtocolAnyTLS, Server: "a.example.com", Port: 8443, Password: "anypass123", TLS: true, SNI: "a.example.com"},
		{Name: "socks5", Type: config.ProtocolSOCKS5, Server: "203.0.113.9", Port: 1080, Username: "alice", Password: "pass123456"},
		{Name: "http", Type: config.ProtocolHTTP, Server: "203.0.113.9", Port: 8080, Username: "bob", Password: "secret123"},
		{Name: "snell", Type: config.ProtocolSnell, Server: "s.example.com", Port: 8388, Password: "snellpsk123456"},
		{Name: "mieru", Type: config.ProtocolMieru, Server: "203.0.113.9", Port: 19443, Username: "vip-user", Password: "mieru-pass-123456"},
	}
	for _, node := range nodes {
		t.Run(node.Name, func(t *testing.T) {
			item, err := config.ExportClashProxy(node)
			if err != nil {
				t.Fatalf("export failed: %v", err)
			}
			proxy, err := adapter.ParseProxy(item)
			if err != nil {
				t.Fatalf("mihomo ParseProxy rejected %s: %v\nitem=%v", node.Name, err, item)
			}
			if proxy == nil {
				t.Fatalf("mihomo built no outbound for %s", node.Name)
			}
			_ = proxy.Close()
		})
	}
}
