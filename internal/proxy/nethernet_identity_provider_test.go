package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func serverURL(raw string) (*url.URL, error) { return url.Parse(raw) }

func TestNetherNetIdentityTransportUnavailableCooldown(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var retry atomic.Int64
	client := &http.Client{Transport: netherNetIdentityTransport{ctx: ctx, inner: http.DefaultTransport, retryAt: &retry}, Timeout: time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if retry.Load() <= time.Now().UnixNano() {
		t.Fatal("unavailable response not classified")
	}
	if response, err = client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("cooldown did not bound network retries")
	}
	if requests.Load() != 1 {
		t.Fatal("unavailable service retried on every offer")
	}
	retry.Store(0)
	cancel()
	if response, err = client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("provider shutdown did not cancel HTTP")
	}
}

func TestNetherNetIdentityProviderCooldownAndCancel(t *testing.T) {
	p := newNetherNetIdentityProvider(context.Background(), nil)
	var calls atomic.Int32
	p.initialize = func(context.Context) (netherNetTokenVerifier, string, error) {
		calls.Add(1)
		return nil, "", errors.New("offline")
	}
	for i := 0; i < 10; i++ {
		_, _, err := p.tokenVerifier(context.Background())
		if err == nil {
			t.Fatal("offline accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("discovery storm: %d", calls.Load())
	}
	p.mu.Lock()
	p.retryAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	_, _, _ = p.tokenVerifier(context.Background())
	if calls.Load() != 2 {
		t.Fatal("failure cached permanently")
	}
	p.Close()
	_, _, err := p.tokenVerifier(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatal("provider revived after close")
	}
}
