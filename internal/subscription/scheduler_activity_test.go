package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

// A 订阅有人使用，不能阻止没有连接的 B 自动更新。
func TestSchedulerScopesBusySubscription(t *testing.T) {
	mgr := config.NewProxySubscriptionConfigManager(filepath.Join(t.TempDir(), "subscriptions.json"))
	for _, id := range []string{"a", "b"} {
		if err := mgr.AddSubscription(&config.ProxySubscription{ID: id, Name: id, URL: "https://example.com/sub", Enabled: true, AutoUpdateTime: "04:00"}); err != nil {
			t.Fatal(err)
		}
	}
	updater := &fakeSubscriptionUpdater{}
	busy := true
	scheduler := NewScheduler(mgr, updater, func(sub *config.ProxySubscription) int {
		if sub.ID == "a" && busy {
			return 1
		}
		return 0
	})
	scheduler.now = func() time.Time { return time.Date(2026, 11, 4, 4, 1, 0, 0, time.UTC) }
	scheduler.runOnce(context.Background())
	if len(updater.calls) != 1 || updater.calls[0].ID != "b" {
		t.Fatalf("A有连接时B仍应更新: calls=%v", updater.calls)
	}
	busy = false
	scheduler.runOnce(context.Background())
	if len(updater.calls) != 2 || updater.calls[1].ID != "a" {
		t.Fatalf("A空闲后应补更新且B不重复: calls=%v", updater.calls)
	}
}

type activityTestManager struct {
	proxy.OutboundManager
	active  atomic.Int64
	updates int
}

func (m *activityTestManager) GetOutboundConnectionCount(string) int64 { return m.active.Load() }
func (m *activityTestManager) UpdateOutbound(string, *config.ProxyOutbound) error {
	m.updates++
	return nil
}

// 下载订阅过程中有人接入时，不能继续替换本订阅的节点配置。
func TestSchedulerDefersIfConnectionArrivesDuringFetch(t *testing.T) {
	runtime := &activityTestManager{}
	connectDuringFetch := true
	body := "proxies:\n  - name: node\n    type: socks5\n    server: new.example.com\n    port: 1080\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if connectDuringFetch {
			runtime.active.Store(1)
		}
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	dir := t.TempDir()
	nodes := config.NewProxyOutboundConfigManager(filepath.Join(dir, "nodes.json"))
	parsed, err := ParseSubscriptionContent([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	node := parsed[0].Outbound.Clone()
	node.Name = "node"
	node.Server = "old.example.com"
	node.Enabled = true
	node.SubscriptionID = "a"
	node.SubscriptionNodeID = parsed[0].SourceKey
	if err := nodes.AddOutbound(node); err != nil {
		t.Fatal(err)
	}
	mgr := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "subscriptions.json"))
	if err := mgr.AddSubscription(&config.ProxySubscription{ID: "a", Name: "a", URL: server.URL, Enabled: true, AutoUpdateTime: "04:00"}); err != nil {
		t.Fatal(err)
	}
	service := NewService(nodes, runtime)
	scheduler := NewScheduler(mgr, service, func(_ *config.ProxySubscription) int { return int(runtime.active.Load()) })
	scheduler.now = func() time.Time { return time.Date(2026, 11, 4, 4, 1, 0, 0, time.UTC) }
	scheduler.runOnce(context.Background())
	got, _ := nodes.GetOutbound("node")
	if got.Server != "old.example.com" || runtime.updates != 0 {
		t.Fatalf("下载期间接入仍替换节点: server=%s updates=%d", got.Server, runtime.updates)
	}
	sub, _ := mgr.GetSubscription("a")
	if !sub.AutoUpdateLastAttemptAt.IsZero() || sub.LastError != "" {
		t.Fatal("连接延期不应被记作执行或失败")
	}
	connectDuringFetch = false
	runtime.active.Store(0)
	scheduler.runOnce(context.Background())
	got, _ = nodes.GetOutbound("node")
	if got.Server != "new.example.com" || runtime.updates != 1 {
		t.Fatalf("空闲后未真正应用订阅: server=%s updates=%d", got.Server, runtime.updates)
	}
}
