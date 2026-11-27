package api

import (
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func TestBulkShareExpandsActivePortUsers(t *testing.T) {
	router, _ := newShareTestRouter(t)
	ports := []config.ProxyPortConfig{
		{
			ID: "with-default", Name: "主入口", ListenAddr: "0.0.0.0:1080", Type: "socks5", Enabled: true,
			Username: "owner", Password: "owner-password",
			Users: []config.ProxyPortUser{
				{Username: "guest", Password: "guest-password"},
				{Username: "disabled", Password: "disabled-password", Disabled: true},
				{Username: "expired", Password: "expired-password", ExpireAt: time.Now().Add(-time.Hour).Format(time.RFC3339)},
			},
		},
		{
			ID: "users-only", Name: "多用户入口", ListenAddr: "0.0.0.0:1081", Type: "http", Enabled: true,
			Users: []config.ProxyPortUser{{Username: "alice", Password: "alice-password"}},
		},
	}
	for _, port := range ports {
		if w := postJSON(router, "/ports", port); w.Code != 200 {
			t.Fatalf("create port %s: %d %s", port.ID, w.Code, w.Body.String())
		}
	}

	w := postJSON(router, "/ports/bulk-share", map[string]any{
		"ids": []string{"with-default", "users-only"}, "format": "clash", "host": "203.0.113.9",
	})
	resp := decodeShare(t, w)
	if w.Code != 200 || resp.Data.Count != 3 {
		t.Fatalf("expected three active credentials, got %d: %d %s", resp.Data.Count, w.Code, w.Body.String())
	}
	for _, want := range []string{"owner-password", "guest-password", "alice-password"} {
		if !strings.Contains(resp.Data.Content, want) {
			t.Fatalf("bulk export missing active credential %q:\n%s", want, resp.Data.Content)
		}
	}
	for _, forbidden := range []string{"disabled-password", "expired-password"} {
		if strings.Contains(resp.Data.Content, forbidden) {
			t.Fatalf("bulk export leaked disabled/expired credential %q", forbidden)
		}
	}
}
