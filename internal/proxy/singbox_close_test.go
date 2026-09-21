package proxy

import (
	"context"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestSingboxOutboundCloseNilReceiver(t *testing.T) {
	var outbound *SingboxOutbound
	if err := outbound.Close(); err != nil {
		t.Fatalf("nil outbound Close() returned error: %v", err)
	}
}

func TestSingboxCoreFactoryDoesNotReturnTypedNil(t *testing.T) {
	factory := NewSingboxCoreFactory()
	outbound, err := factory.CreateUDPOutbound(context.Background(), &config.ProxyOutbound{Type: "unsupported"})
	if err == nil {
		t.Fatal("expected outbound creation error")
	}
	if outbound != nil {
		t.Fatalf("expected a nil interface, got %T", outbound)
	}
}
