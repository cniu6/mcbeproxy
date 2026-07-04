package proxy

import (
	"encoding/base64"
	"strings"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestEffectiveRealityServerName(t *testing.T) {
	t.Parallel()

	cfg := &config.ProxyOutbound{
		Server: "aws-de1.b.f.0.0.9.1.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
		SNI:    "download-porter.hoyoverse.com",
	}
	got, err := effectiveRealityServerName(cfg)
	if err != nil {
		t.Fatalf("effectiveRealityServerName returned error: %v", err)
	}
	if got != "download-porter.hoyoverse.com" {
		t.Fatalf("expected camouflage SNI, got %q", got)
	}

	cfg = &config.ProxyOutbound{
		Server: "aws-de1.b.f.0.0.9.1.0.0.0.7.4.0.1.0.0.2.ip6.arpa",
	}
	if _, err := effectiveRealityServerName(cfg); err == nil {
		t.Fatal("expected error when only encoded server hostname is available")
	}

	cfg = &config.ProxyOutbound{
		Server: "node.example.com",
		SNI:    "node.example.com",
	}
	got, err = effectiveRealityServerName(cfg)
	if err != nil || got != "node.example.com" {
		t.Fatalf("expected normal domain fallback, got %q err=%v", got, err)
	}
}

func TestDecodeRealityPublicKeyValue(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}

	for _, encoded := range []string{
		base64.RawURLEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
	} {
		decoded, err := decodeRealityPublicKeyValue(encoded)
		if err != nil {
			t.Fatalf("decodeRealityPublicKeyValue(%q) failed: %v", encoded, err)
		}
		if len(decoded) != 32 {
			t.Fatalf("decodeRealityPublicKeyValue(%q) len=%d", encoded, len(decoded))
		}
	}

	if _, err := decodeRealityPublicKeyValue(""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty key error, got %v", err)
	}
}

func TestEffectiveRealitySpiderX(t *testing.T) {
	t.Parallel()

	if got := effectiveRealitySpiderX(nil); got != "/" {
		t.Fatalf("expected default /, got %q", got)
	}
	if got := effectiveRealitySpiderX(&config.ProxyOutbound{RealitySpiderX: "/chat"}); got != "/chat" {
		t.Fatalf("expected /chat, got %q", got)
	}
}
