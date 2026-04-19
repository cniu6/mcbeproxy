package subscription

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

type fakeSubscriptionUpdater struct {
	calls []*config.ProxySubscription
	err   error
}

func (f *fakeSubscriptionUpdater) UpdateSubscription(_ context.Context, sub *config.ProxySubscription) (*UpdateResult, error) {
	f.calls = append(f.calls, sub.Clone())
	if f.err != nil {
		return nil, f.err
	}
	return &UpdateResult{NodeCount: 3, AddedCount: 1, UpdatedCount: 1, RemovedCount: 0}, nil
}

func TestSubscriptionAutoUpdateDueDaily(t *testing.T) {
	now := time.Date(2026, 4, 18, 4, 30, 0, 0, time.Local)
	sub := &config.ProxySubscription{
		ID:             "sub-1",
		Name:           "Daily",
		URL:            "https://example.com/sub",
		Enabled:        true,
		AutoUpdateMode: config.ProxySubscriptionAutoUpdateModeDaily,
		AutoUpdateTime: "04:00",
	}

	due, reason, err := subscriptionAutoUpdateDue(sub, now)
	if err != nil {
		t.Fatalf("subscriptionAutoUpdateDue returned error: %v", err)
	}
	if !due {
		t.Fatal("expected daily subscription to be due")
	}
	if reason != "daily@04:00" {
		t.Fatalf("reason = %q, want daily@04:00", reason)
	}

	sub.AutoUpdateLastAttemptAt = now
	due, _, err = subscriptionAutoUpdateDue(sub, now)
	if err != nil {
		t.Fatalf("subscriptionAutoUpdateDue returned error: %v", err)
	}
	if due {
		t.Fatal("expected same-day daily subscription attempt not to be due twice")
	}
}

func TestSubscriptionAutoUpdateDueInterval(t *testing.T) {
	now := time.Date(2026, 4, 18, 4, 30, 0, 0, time.Local)
	sub := &config.ProxySubscription{
		ID:                      "sub-1",
		Name:                    "Interval",
		URL:                     "https://example.com/sub",
		Enabled:                 true,
		AutoUpdateMode:          config.ProxySubscriptionAutoUpdateModeInterval,
		AutoUpdateIntervalDays:  2,
		AutoUpdateLastAttemptAt: now.Add(-49 * time.Hour),
	}

	due, reason, err := subscriptionAutoUpdateDue(sub, now)
	if err != nil {
		t.Fatalf("subscriptionAutoUpdateDue returned error: %v", err)
	}
	if !due {
		t.Fatal("expected interval subscription to be due")
	}
	if reason != "interval/2d" {
		t.Fatalf("reason = %q, want interval/2d", reason)
	}

	sub.AutoUpdateLastAttemptAt = now.Add(-47 * time.Hour)
	due, _, err = subscriptionAutoUpdateDue(sub, now)
	if err != nil {
		t.Fatalf("subscriptionAutoUpdateDue returned error: %v", err)
	}
	if due {
		t.Fatal("expected interval subscription not to be due before full interval")
	}
}

func TestSchedulerRunOnceSkipsWhenSessionsActive(t *testing.T) {
	dir := t.TempDir()
	mgr := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "proxy_subscriptions.json"))
	sub := &config.ProxySubscription{
		ID:             "sub-1",
		Name:           "Daily",
		URL:            "https://example.com/sub",
		Enabled:        true,
		AutoUpdateMode: config.ProxySubscriptionAutoUpdateModeDaily,
		AutoUpdateTime: "04:00",
	}
	if err := mgr.AddSubscription(sub); err != nil {
		t.Fatalf("AddSubscription returned error: %v", err)
	}

	updater := &fakeSubscriptionUpdater{}
	now := time.Date(2026, 4, 18, 4, 30, 0, 0, time.Local)
	scheduler := NewScheduler(mgr, updater, func() int { return 2 })
	scheduler.now = func() time.Time { return now }

	scheduler.runOnce(context.Background())

	if len(updater.calls) != 0 {
		t.Fatalf("expected no update attempts while sessions active, got %d", len(updater.calls))
	}
}

func TestSchedulerRunOncePersistsAttemptAndError(t *testing.T) {
	dir := t.TempDir()
	mgr := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "proxy_subscriptions.json"))
	sub := &config.ProxySubscription{
		ID:             "sub-1",
		Name:           "Daily",
		URL:            "https://example.com/sub",
		Enabled:        true,
		AutoUpdateMode: config.ProxySubscriptionAutoUpdateModeDaily,
		AutoUpdateTime: "04:00",
	}
	if err := mgr.AddSubscription(sub); err != nil {
		t.Fatalf("AddSubscription returned error: %v", err)
	}

	updater := &fakeSubscriptionUpdater{err: errors.New("boom")}
	now := time.Date(2026, 4, 18, 4, 30, 0, 0, time.Local)
	scheduler := NewScheduler(mgr, updater, func() int { return 0 })
	scheduler.now = func() time.Time { return now }

	scheduler.runOnce(context.Background())

	if len(updater.calls) != 1 {
		t.Fatalf("expected one update attempt, got %d", len(updater.calls))
	}
	updated, ok := mgr.GetSubscription("sub-1")
	if !ok {
		t.Fatal("expected subscription to exist after scheduler run")
	}
	if updated.AutoUpdateLastAttemptAt.IsZero() {
		t.Fatal("expected auto update last attempt timestamp to be persisted")
	}
	if updated.LastError != "boom" {
		t.Fatalf("LastError = %q, want boom", updated.LastError)
	}
}

func TestSchedulerRunOnceInvokesAfterUpdateHook(t *testing.T) {
	dir := t.TempDir()
	mgr := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "proxy_subscriptions.json"))
	sub := &config.ProxySubscription{
		ID:             "sub-1",
		Name:           "Daily",
		URL:            "https://example.com/sub",
		Enabled:        true,
		AutoUpdateMode: config.ProxySubscriptionAutoUpdateModeDaily,
		AutoUpdateTime: "04:00",
	}
	if err := mgr.AddSubscription(sub); err != nil {
		t.Fatalf("AddSubscription returned error: %v", err)
	}

	updater := &fakeSubscriptionUpdater{}
	now := time.Date(2026, 4, 18, 4, 30, 0, 0, time.Local)
	scheduler := NewScheduler(mgr, updater, func() int { return 0 })
	scheduler.now = func() time.Time { return now }

	var hookCalls int
	scheduler.SetAfterUpdateHook(func(sub *config.ProxySubscription, result *UpdateResult) {
		if sub == nil || result == nil {
			t.Fatal("after update hook received nil payload")
		}
		hookCalls++
	})

	scheduler.runOnce(context.Background())

	if hookCalls != 1 {
		t.Fatalf("expected after update hook once, got %d", hookCalls)
	}
}
