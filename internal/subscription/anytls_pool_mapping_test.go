package subscription

import "testing"

func TestAnyTLSClashPoolOptions(t *testing.T) {
	parsed, err := ParseSubscriptionContent([]byte(`proxies:
  - name: anytls-pool-fixture
    type: anytls
    server: 127.0.0.1
    port: 443
    password: fixture
    idle-session-check-interval: 45
    idle-session-timeout: 90
    min-idle-session: 2
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 1 {
		t.Fatalf("nodes=%d", len(parsed))
	}
	cfg := parsed[0].Outbound
	if cfg.IdleSessionCheckInterval != 45 || cfg.IdleSessionTimeout != 90 || cfg.MinIdleSession != 2 {
		t.Fatalf("pool options lost: check=%d timeout=%d min=%d", cfg.IdleSessionCheckInterval, cfg.IdleSessionTimeout, cfg.MinIdleSession)
	}
}
