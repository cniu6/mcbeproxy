package subscription

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// 没有尝试时间的旧订阅也必须能启动间隔更新，不能永远等不到首次调度。
func TestSchedulerIntervalWithoutBaselineRecovers(t *testing.T) {
	mgr := config.NewProxySubscriptionConfigManager(filepath.Join(t.TempDir(), "subscriptions.json"))
	if err := mgr.AddSubscription(&config.ProxySubscription{
		ID: "legacy", Name: "Legacy", URL: "https://example.com/sub", Enabled: true,
		AutoUpdateMode: config.ProxySubscriptionAutoUpdateModeInterval, AutoUpdateIntervalDays: 1,
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	updater := &fakeSubscriptionUpdater{}
	scheduler := NewScheduler(mgr, updater, func(_ *config.ProxySubscription) int { return 0 })
	scheduler.now = func() time.Time { return now }
	scheduler.runOnce(context.Background())
	if len(updater.calls) != 1 {
		t.Fatalf("首次间隔更新未触发：calls=%d, want 1", len(updater.calls))
	}
	scheduler.runOnce(context.Background())
	if len(updater.calls) != 1 {
		t.Fatalf("同一间隔内重复执行：calls=%d", len(updater.calls))
	}
	stored, _ := mgr.GetSubscription("legacy")
	if !stored.LastUpdatedAt.Equal(now) {
		t.Fatalf("未持久化成功时间: %v", stored.LastUpdatedAt)
	}
}

func TestNextAutoUpdateAtMatchesSchedule(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.FixedZone("CST", 8*3600))
	off := false
	cases := []struct {
		name string
		sub  config.ProxySubscription
		want time.Time
	}{
		{"daily-before", config.ProxySubscription{Enabled: true, AutoUpdateTime: "13:00"}, now.Add(time.Hour)},
		{"daily-after-attempt", config.ProxySubscription{Enabled: true, AutoUpdateTime: "04:00", AutoUpdateLastAttemptAt: now}, now.Add(16 * time.Hour)},
		{"daily-overdue", config.ProxySubscription{Enabled: true, AutoUpdateTime: "04:00", AutoUpdateLastAttemptAt: now.Add(-48 * time.Hour)}, now},
		{"disabled", config.ProxySubscription{Enabled: true, AutoUpdateEnabled: &off}, time.Time{}},
		{"interval-new", config.ProxySubscription{Enabled: true, AutoUpdateMode: "interval"}, now},
		{"interval-last-success", config.ProxySubscription{Enabled: true, AutoUpdateMode: "interval", LastUpdatedAt: now.Add(-time.Hour)}, now.Add(23 * time.Hour)},
		{"retry", config.ProxySubscription{Enabled: true, AutoUpdateLastAttemptAt: now.Add(-time.Minute), LastError: "temporary"}, now.Add(14 * time.Minute)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NextAutoUpdateAt(&tc.sub, now)
			if err != nil || !got.Equal(tc.want) {
				t.Fatalf("got %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}

// 每日任务到点有玩家时延期；连接跨过午夜才清空也必须补执行，而非等下一天。
func TestSchedulerDailyDeferredAcrossMidnightRecovers(t *testing.T) {
	mgr := config.NewProxySubscriptionConfigManager(filepath.Join(t.TempDir(), "subscriptions.json"))
	now := time.Date(2026, 11, 4, 23, 59, 0, 0, time.UTC)
	if err := mgr.AddSubscription(&config.ProxySubscription{
		ID: "daily", Name: "Daily", URL: "https://example.com/sub", Enabled: true,
		AutoUpdateMode: config.ProxySubscriptionAutoUpdateModeDaily, AutoUpdateTime: "23:59",
		AutoUpdateLastAttemptAt: now.Add(-24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	active := 1
	updater := &fakeSubscriptionUpdater{}
	scheduler := NewScheduler(mgr, updater, func(_ *config.ProxySubscription) int { return active })
	scheduler.now = func() time.Time { return now }
	scheduler.runOnce(context.Background())
	if len(updater.calls) != 0 {
		t.Fatal("有连接时不应更新")
	}
	now = now.Add(2 * time.Minute)
	active = 0
	scheduler.runOnce(context.Background())
	if len(updater.calls) != 1 {
		t.Fatalf("跨午夜延期任务丢失：calls=%d, want 1", len(updater.calls))
	}
	scheduler.runOnce(context.Background())
	if len(updater.calls) != 1 {
		t.Fatal("补更新不应重复执行")
	}
}
