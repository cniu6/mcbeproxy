package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// Regression: a subscription URL whose certificate is not trusted must fail the
// fetch. The previous code accepted any certificate, so a spoofed host could
// feed arbitrary node lists into the import.
func TestFetchContentRejectsUntrustedSubscriptionCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vmess://ignored"))
	}))
	defer srv.Close()

	svc := NewService(nil, nil)
	sub := &config.ProxySubscription{ID: "untrusted", Name: "untrusted", URL: srv.URL, Enabled: true}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := svc.FetchContent(ctx, sub)
	if err == nil {
		t.Fatal("untrusted subscription certificate was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "certificate") && !strings.Contains(strings.ToLower(err.Error()), "x509") {
		t.Fatalf("expected a certificate verification error, got: %v", err)
	}
}
