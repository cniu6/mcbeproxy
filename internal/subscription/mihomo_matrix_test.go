package subscription

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"

	"mcpeserverproxy/internal/config"
)

const matrixUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// 全协议矩阵：本项目导出的每条分享链接，必须先被 mihomo 的 v2ray 订阅转换器接受，
// 转换出的服务器、端口、账号密码与原节点一致，再能被 mihomo 的 ParseProxy 构造成出站对象。
// 密码含冒号的 socks/http 账号不在矩阵内：mihomo 的链接解析器按冒号切分且不解码百分号，
// 这类账号应使用 Clash YAML 导出。
func TestMihomoAcceptsEveryExportedShareLink(t *testing.T) {
	cases := []struct {
		node     *config.ProxyOutbound
		wantUser string
		wantPass string
	}{
		{node: &config.ProxyOutbound{Name: "香港 01", Type: config.ProtocolShadowsocks, Server: "1.2.3.4", Port: 8388, Method: "aes-256-gcm", Password: "pass/word+x=y"}, wantPass: "pass/word+x=y"},
		{node: &config.ProxyOutbound{Name: "vmess-ws-tls", Type: config.ProtocolVMess, Server: "us.example.com", Port: 443, UUID: matrixUUID, Security: "auto", TLS: true, SNI: "cdn.example.com", Network: "ws", WSPath: "/ray", WSHost: "cdn.example.com"}},
		{node: &config.ProxyOutbound{Name: "vmess-tcp", Type: config.ProtocolVMess, Server: "us.example.com", Port: 80, UUID: matrixUUID, Security: "auto"}},
		{node: &config.ProxyOutbound{Name: "trojan-tls", Type: config.ProtocolTrojan, Server: "t.example.com", Port: 443, Password: "tr0jan-pass", TLS: true, SNI: "t.example.com"}, wantPass: "tr0jan-pass"},
		{node: &config.ProxyOutbound{Name: "trojan-grpc", Type: config.ProtocolTrojan, Server: "t.example.com", Port: 443, Password: "tr0jan-pass", TLS: true, SNI: "t.example.com", Network: "grpc", GRPCServiceName: "svc"}, wantPass: "tr0jan-pass"},
		{node: &config.ProxyOutbound{Name: "vless-tls", Type: config.ProtocolVLESS, Server: "v.example.com", Port: 443, UUID: matrixUUID, TLS: true, SNI: "v.example.com"}},
		{node: &config.ProxyOutbound{Name: "anytls", Type: config.ProtocolAnyTLS, Server: "a.example.com", Port: 8443, Password: "anypass123", TLS: true, SNI: "a.example.com"}, wantPass: "anypass123"},
		{node: &config.ProxyOutbound{Name: "tuic", Type: config.ProtocolTUIC, Server: "t.example.com", Port: 10443, UUID: matrixUUID, Password: "tuicpass", TLS: true, SNI: "t.example.com"}, wantPass: "tuicpass"},
		{node: &config.ProxyOutbound{Name: "socks5-auth", Type: config.ProtocolSOCKS5, Server: "203.0.113.9", Port: 1080, Username: "alice", Password: "Ab_cD-eF123"}, wantUser: "alice", wantPass: "Ab_cD-eF123"},
		{node: &config.ProxyOutbound{Name: "http-auth", Type: config.ProtocolHTTP, Server: "203.0.113.9", Port: 8080, Username: "bob", Password: "secret123"}, wantUser: "bob", wantPass: "secret123"},
		{node: &config.ProxyOutbound{Name: "https-auth", Type: config.ProtocolHTTP, Server: "proxy.example.com", Port: 8443, Username: "bob", Password: "secret123", TLS: true, SNI: "proxy.example.com"}, wantUser: "bob", wantPass: "secret123"},
		{node: &config.ProxyOutbound{Name: "hy2", Type: config.ProtocolHysteria2, Server: "hy.example.com", Port: 8443, Password: "vip:longpassword123456", SNI: "hy.example.com"}, wantPass: "vip:longpassword123456"},
	}
	for _, tc := range cases {
		p := tc.node
		t.Run(p.Name, func(t *testing.T) {
			link, err := config.ExportShareLink(p)
			if err != nil {
				t.Fatalf("export failed: %v", err)
			}
			proxies, err := convert.ConvertsV2Ray([]byte(link))
			if err != nil || len(proxies) != 1 {
				t.Fatalf("mihomo convert rejected %q: n=%d err=%v", link, len(proxies), err)
			}
			m := proxies[0]
			if fmt.Sprint(m["server"]) != p.Server || fmt.Sprint(m["port"]) != strconv.Itoa(p.Port) {
				t.Errorf("server/port: mihomo gave %v:%v, want %s:%d", m["server"], m["port"], p.Server, p.Port)
			}
			if tc.wantUser != "" && fmt.Sprint(m["username"]) != tc.wantUser {
				t.Errorf("username: mihomo gave %q, want %q", m["username"], tc.wantUser)
			}
			if tc.wantPass != "" && fmt.Sprint(m["password"]) != tc.wantPass {
				t.Errorf("password: mihomo gave %q, want %q (link %s)", m["password"], tc.wantPass, link)
			}
			outbound, err := adapter.ParseProxy(m)
			if err != nil {
				t.Fatalf("mihomo ParseProxy rejected %q: %v", link, err)
			}
			_ = outbound.Close()
		})
	}
}
