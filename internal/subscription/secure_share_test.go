package subscription

import (
	"mcpeserverproxy/internal/config"
	"testing"
)

func TestSecureShareImport(t *testing.T) {
	profile := config.SecureProfile{Name: "香港主力 · 自定义", Version: 1, Upstream: config.SecureUpstream{Type: "mieru", Server: "127.0.0.1", Port: 18443, Username: "guest", Password: "fixture-password-123456"}}
	link, err := profile.ShareLink()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSubscriptionContent([]byte(link))
	if err != nil || len(parsed) != 1 {
		t.Fatalf("import failed: %v", err)
	}
	out := parsed[0].Outbound
	if out.Name != profile.Name || out.Type != "mieru" || out.Username != profile.Upstream.Username || out.Password != profile.Upstream.Password || out.ProviderOptions["transport"] != "TCP" {
		t.Fatal("import lost Mieru authentication or transport")
	}
	if err := out.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSubscriptionContent([]byte("mcproxy://not-valid!")); err == nil {
		t.Fatal("malformed link accepted")
	}
}
