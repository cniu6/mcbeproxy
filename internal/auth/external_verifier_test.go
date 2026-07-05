package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExternalVerifierVerifySplitsIPv6ClientAddress(t *testing.T) {
	var got VerifyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode request failed: %v", err)
		}
		_ = json.NewEncoder(w).Encode(VerifyResponse{Code: 0, Msg: "ok"})
	}))
	defer server.Close()

	verifier := NewExternalVerifier(true, server.URL, 1)
	allowed, reason := verifier.doVerify("xuid", "uuid", "player", "srv", net.JoinHostPort("2001:db8::1", "54321"))
	if !allowed || reason != "ok" {
		t.Fatalf("doVerify() = (%v, %q), want (true, ok)", allowed, reason)
	}
	if got.ClientIP != "2001:db8::1" {
		t.Fatalf("ClientIP = %q, want IPv6 host without brackets", got.ClientIP)
	}
	if got.ClientPort != "54321" {
		t.Fatalf("ClientPort = %q, want 54321", got.ClientPort)
	}
}

func TestExternalVerifierVerifyFallsBackForAddressWithoutPort(t *testing.T) {
	var got VerifyRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode request failed: %v", err)
		}
		_ = json.NewEncoder(w).Encode(VerifyResponse{Code: 0, Msg: "ok"})
	}))
	defer server.Close()

	verifier := NewExternalVerifier(true, server.URL, 1)
	allowed, reason := verifier.doVerify("xuid", "uuid", "player", "srv", "2001:db8::1")
	if !allowed || reason != "ok" {
		t.Fatalf("doVerify() = (%v, %q), want (true, ok)", allowed, reason)
	}
	if got.ClientIP != "2001:db8::1" {
		t.Fatalf("ClientIP = %q, want fallback address", got.ClientIP)
	}
	if got.ClientPort != "" {
		t.Fatalf("ClientPort = %q, want empty fallback port", got.ClientPort)
	}
}
