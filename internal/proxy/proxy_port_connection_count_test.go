package proxy

import (
	"context"
	"testing"

	"mcpeserverproxy/internal/config"
)

// TCP 代理端口也必须参与订阅的连接保护，重复 Close 不能提前释放别的连接。
func TestProxyPortTCPCountsNodeConnections(t *testing.T) {
	factory := &countingFactory{}
	manager := NewOutboundManagerWithSingboxFactory(nil, factory)
	if err := manager.AddOutbound(&config.ProxyOutbound{Name: "node", Type: config.ProtocolSOCKS5, Server: "127.0.0.1", Port: 1080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	pool := newProxyPortDialerPool(factory)
	defer pool.CloseAll()
	listener := newProxyPortListener(&config.ProxyPortConfig{ID: "port"}, manager, pool)
	route := proxyPortRoute{outbound: "node"}
	first, _, err := listener.dialRoute(context.Background(), route, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, _, err := listener.dialRoute(context.Background(), route, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := manager.GetOutboundConnectionCount("node"); got != 2 {
		t.Fatalf("TCP连接未计入节点: %d", got)
	}
	_ = first.Close()
	_ = first.Close()
	if got := manager.GetOutboundConnectionCount("node"); got != 1 {
		t.Fatalf("重复Close错误释放连接计数: %d", got)
	}
	_ = second.Close()
	if got := manager.GetOutboundConnectionCount("node"); got != 0 {
		t.Fatalf("TCP关闭后计数未归零: %d", got)
	}
}
