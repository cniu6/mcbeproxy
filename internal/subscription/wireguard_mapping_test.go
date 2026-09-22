package subscription

import (
	"net/url"
	"testing"

	"mcpeserverproxy/internal/proxy"
)

func TestWireGuardURIConstructsRuntime(t *testing.T) {
	q := url.Values{}
	q.Set("privatekey", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
	q.Set("publickey", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
	q.Set("address", "10.0.0.2/32,fd00::2/128")
	q.Set("reserved", "1,2,3")
	q.Set("mtu", "1280")
	nodes, err := ParseSubscriptionContent([]byte("wireguard://127.0.0.1:51820?" + q.Encode()))
	if err != nil || len(nodes) != 1 {
		t.Fatalf("public parser: %v", err)
	}
	parsed := nodes[0]
	opts := parsed.Outbound.ProviderOptions
	if opts["ip"] != "10.0.0.2/32" || opts["ipv6"] != "fd00::2/128" {
		t.Fatalf("wrong local addresses: %v / %v", opts["ip"], opts["ipv6"])
	}
	// 验证持久化和克隆后的参数也能构造运行时，而不只验证解析成功。
	node := parsed.Outbound.Clone()
	dialer, err := proxy.CreateSingboxDialer(node)
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	q.Set("address", "not-an-address")
	if _, ok := parseWireGuard("wireguard://127.0.0.1:51820?" + q.Encode()); ok {
		t.Fatal("invalid address accepted")
	}
}
