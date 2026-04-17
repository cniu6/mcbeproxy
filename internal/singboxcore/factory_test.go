package singboxcore

import (
	"context"
	"errors"
	"net"
	"testing"

	"mcpeserverproxy/internal/config"
)

type testUDPOutbound struct{}

func (testUDPOutbound) ListenPacket(context.Context, string) (net.PacketConn, error) { return nil, nil }
func (testUDPOutbound) Close() error                                                 { return nil }

type testDialer struct{}

func (testDialer) DialContext(context.Context, string, string) (net.Conn, error) { return nil, nil }
func (testDialer) Close() error                                                  { return nil }

func TestFactoryFuncsDelegates(t *testing.T) {
	cfg := &config.ProxyOutbound{Name: "node-a"}
	var udpCalled bool
	var dialerCalled bool

	factory := FactoryFuncs{
		CreateUDPOutboundFunc: func(ctx context.Context, gotCfg *config.ProxyOutbound) (UDPOutbound, error) {
			udpCalled = ctx != nil && gotCfg == cfg
			return testUDPOutbound{}, nil
		},
		CreateDialerFunc: func(ctx context.Context, gotCfg *config.ProxyOutbound) (Dialer, error) {
			dialerCalled = ctx != nil && gotCfg == cfg
			return testDialer{}, nil
		},
	}

	udpOutbound, err := factory.CreateUDPOutbound(context.Background(), cfg)
	if err != nil {
		t.Fatalf("CreateUDPOutbound returned error: %v", err)
	}
	if !udpCalled {
		t.Fatal("expected CreateUDPOutboundFunc to be called")
	}
	if _, ok := udpOutbound.(testUDPOutbound); !ok {
		t.Fatalf("unexpected UDPOutbound type: %T", udpOutbound)
	}

	dialer, err := factory.CreateDialer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("CreateDialer returned error: %v", err)
	}
	if !dialerCalled {
		t.Fatal("expected CreateDialerFunc to be called")
	}
	if _, ok := dialer.(testDialer); !ok {
		t.Fatalf("unexpected Dialer type: %T", dialer)
	}
}

func TestFactoryFuncsMissingHandlers(t *testing.T) {
	factory := FactoryFuncs{}
	if _, err := factory.CreateUDPOutbound(context.Background(), &config.ProxyOutbound{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented from CreateUDPOutbound, got %v", err)
	}
	if _, err := factory.CreateDialer(context.Background(), &config.ProxyOutbound{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented from CreateDialer, got %v", err)
	}
}

func TestPlaceholderFactoryNotImplemented(t *testing.T) {
	factory := NewPlaceholderFactory()
	if _, err := factory.CreateUDPOutbound(context.Background(), &config.ProxyOutbound{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented from CreateUDPOutbound, got %v", err)
	}
	if _, err := factory.CreateDialer(context.Background(), &config.ProxyOutbound{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected ErrNotImplemented from CreateDialer, got %v", err)
	}
}
