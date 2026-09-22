package subscription

import "testing"

func TestClashRealityUsesServername(t *testing.T) {
	item := map[string]interface{}{
		"name": "reality", "type": "vless", "server": "127.0.0.1", "port": 443,
		"uuid": "00000000-0000-0000-0000-000000000001",
		"sni":  "wrong.example", "servername": "correct.example", "skip-cert-verify": false,
		"reality-opts": map[string]interface{}{"public-key": "QdYs12kmf0mAXNOEPgMpLN5dbZUlgvRK2zCqynOmqBk", "short-id": "0123456789abcdef"},
	}
	parsed, ok := parseClashProxy(item)
	if !ok {
		t.Fatal("valid node rejected")
	}
	if parsed.Outbound.SNI != "correct.example" {
		t.Fatalf("wrong SNI: %q", parsed.Outbound.SNI)
	}
	if parsed.Outbound.Insecure {
		t.Fatal("Reality must not force skip-cert-verify")
	}
}
