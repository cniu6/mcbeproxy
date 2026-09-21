package proxy

import (
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func TestRawUDPIdleTimeoutMinusOneKeepsSessionAfterReadTimeout(t *testing.T) {
	proxy := NewRawUDPProxy("test", &config.ServerConfig{IdleTimeout: -1}, nil, nil)
	proxy.updateTimeouts()
	if got := proxy.effectiveClientDisconnectTimeout(); got != 0 {
		t.Fatalf("effective timeout = %v, want 0", got)
	}

	lastClientPacket := time.Now().Add(-time.Hour)
	effectiveTimeout := proxy.effectiveClientDisconnectTimeout()
	if effectiveTimeout > 0 && time.Since(lastClientPacket) > effectiveTimeout {
		t.Fatal("idle_timeout=-1 should not trigger the client-silent timeout")
	}
}

func TestRawUDPPositiveIdleTimeoutStillExpires(t *testing.T) {
	proxy := NewRawUDPProxy("test", &config.ServerConfig{IdleTimeout: 60}, nil, nil)
	proxy.updateTimeouts()
	if got := proxy.effectiveClientDisconnectTimeout(); got != 60*time.Second {
		t.Fatalf("effective timeout = %v, want 60s", got)
	}

	lastClientPacket := time.Now().Add(-time.Minute - time.Second)
	effectiveTimeout := proxy.effectiveClientDisconnectTimeout()
	if !(effectiveTimeout > 0 && time.Since(lastClientPacket) > effectiveTimeout) {
		t.Fatal("positive idle_timeout should trigger after the configured interval")
	}
}
