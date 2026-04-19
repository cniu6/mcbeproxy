package config

import "testing"

func TestProxySubscriptionDefaultsAndValidation(t *testing.T) {
	sub := &ProxySubscription{
		ID:   "sub-1",
		Name: "Demo",
		URL:  "https://example.com/sub",
	}

	if err := sub.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !sub.IsAutoUpdateEnabled() {
		t.Fatalf("expected auto update to default enabled")
	}
	if got := sub.GetAutoUpdateMode(); got != ProxySubscriptionAutoUpdateModeDaily {
		t.Fatalf("GetAutoUpdateMode() = %q, want %q", got, ProxySubscriptionAutoUpdateModeDaily)
	}
	if got := sub.GetAutoUpdateTime(); got != defaultProxySubscriptionAutoUpdateTime {
		t.Fatalf("GetAutoUpdateTime() = %q, want %q", got, defaultProxySubscriptionAutoUpdateTime)
	}
	if got := sub.GetAutoUpdateIntervalDays(); got != defaultProxySubscriptionAutoUpdateIntervalDays {
		t.Fatalf("GetAutoUpdateIntervalDays() = %d, want %d", got, defaultProxySubscriptionAutoUpdateIntervalDays)
	}
}

func TestProxySubscriptionValidateRejectsBadAutoUpdateTime(t *testing.T) {
	sub := &ProxySubscription{
		ID:             "sub-1",
		Name:           "Demo",
		URL:            "https://example.com/sub",
		AutoUpdateMode: ProxySubscriptionAutoUpdateModeDaily,
		AutoUpdateTime: "25:99",
	}

	if err := sub.Validate(); err == nil {
		t.Fatal("expected invalid auto_update_time to fail validation")
	}
}

func TestProxySubscriptionValidateRejectsBadMode(t *testing.T) {
	sub := &ProxySubscription{
		ID:             "sub-1",
		Name:           "Demo",
		URL:            "https://example.com/sub",
		AutoUpdateMode: "weekly",
	}

	if err := sub.Validate(); err == nil {
		t.Fatal("expected invalid auto_update_mode to fail validation")
	}
}

func TestProxySubscriptionValidateAppliesIntervalDefault(t *testing.T) {
	sub := &ProxySubscription{
		ID:             "sub-1",
		Name:           "Demo",
		URL:            "https://example.com/sub",
		AutoUpdateMode: ProxySubscriptionAutoUpdateModeInterval,
	}

	if err := sub.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if got := sub.GetAutoUpdateIntervalDays(); got != 1 {
		t.Fatalf("GetAutoUpdateIntervalDays() = %d, want 1", got)
	}
}
