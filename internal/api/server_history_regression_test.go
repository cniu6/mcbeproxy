package api

import (
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

type historyCacheController struct{ mockProxyController }

func (*historyCacheController) GetServerLatencyInfoRaw(id string) (int64, bool, string, bool) {
	if id == "cached" {
		return 81, true, "", true
	}
	return 0, false, "", false
}

func TestServerHistoryContinuousSamplesAccumulate(t *testing.T) {
	store := newServerLatencyHistoryStore(nil)
	base := time.Now().Add(-31 * time.Minute)
	for i := 0; i <= 30; i++ {
		store.Record("cached", ServerLatencyHistorySample{Timestamp: base.Add(time.Duration(i) * time.Minute).UnixMilli(), LatencyMs: int64(50 + i), Online: true}, 0)
	}
	samples := store.History("cached")
	if len(samples) != 4 {
		t.Fatalf("连续31分钟采样应跨过4个固定采样窗口，实际%d点: %+v", len(samples), samples)
	}
	if samples[len(samples)-1].LatencyMs != 80 {
		t.Fatal("当前窗口未保留最新实测值")
	}
}

func TestServerHistoryOverviewSeedsKnownCacheOnlyOnce(t *testing.T) {
	a := &APIServer{proxyController: &historyCacheController{}, serverLatencyHistory: newServerLatencyHistoryStore(nil)}
	servers := []config.ServerConfigDTO{{ID: "cached", Status: "running"}, {ID: "unknown", Status: "running"}}
	a.buildServerLatencyOverview(servers, 10)
	first := a.serverLatencyHistory.History("cached")
	if len(first) != 1 || first[0].LatencyMs != 81 {
		t.Fatalf("概览已有有效缓存却没有初始历史点: %+v", first)
	}
	time.Sleep(time.Millisecond)
	a.buildServerLatencyOverview(servers, 10)
	second := a.serverLatencyHistory.History("cached")
	if len(second) != 1 || second[0].Timestamp != first[0].Timestamp {
		t.Fatal("只读刷新把同一缓存伪造为新测量")
	}
	if samples := a.serverLatencyHistory.History("unknown"); len(samples) != 0 {
		t.Fatalf("没有实测值的服务器不应制造离线样本: %+v", samples)
	}
}
