package subscription

import (
	"path/filepath"
	"testing"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

func TestActiveSubscriptionConnectionsIncludesChainOnlyForOwner(t *testing.T) {
	nodes := config.NewProxyOutboundConfigManager(filepath.Join(t.TempDir(), "nodes.json"))
	runtime := proxy.NewOutboundManager(nil)
	for _, node := range []*config.ProxyOutbound{
		{Name: "a", SubscriptionID: "sub-a", Type: config.ProtocolSOCKS5, Server: "127.0.0.1", Port: 1080, Enabled: true},
		{Name: "b", SubscriptionID: "sub-b", Type: config.ProtocolSOCKS5, Server: "127.0.0.1", Port: 1081, Enabled: true},
		{Name: "chain", Type: config.ProtocolChain, Chain: []string{"a"}, Enabled: true},
		{Name: "nested", Type: config.ProtocolChain, Chain: []string{"chain"}, Enabled: true},
	} {
		if err := nodes.AddOutbound(node); err != nil {
			t.Fatal(err)
		}
		if err := runtime.AddOutbound(node); err != nil {
			t.Fatal(err)
		}
	}
	// 活跃连接挂在链式容器上，而不是它引用的订阅节点上。
	node, _ := runtime.GetOutbound("nested")
	node.IncrConnCount()
	defer node.DecrConnCount()
	service := NewService(nodes, runtime)
	if got := service.ActiveSubscriptionConnections(&config.ProxySubscription{ID: "sub-a"}); got != 1 {
		t.Fatalf("遗漏链式引用连接: %d", got)
	}
	if got := service.ActiveSubscriptionConnections(&config.ProxySubscription{ID: "sub-b"}); got != 0 {
		t.Fatalf("其他订阅错误受阻: %d", got)
	}
}
