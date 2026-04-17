package singboxcore

import (
	"context"
	"errors"
	"net"

	"mcpeserverproxy/internal/config"
)

var ErrNotImplemented = errors.New("singboxcore: not implemented")

type UDPOutbound interface {
	ListenPacket(ctx context.Context, destination string) (net.PacketConn, error)
	Close() error
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Close() error
}

type Factory interface {
	CreateUDPOutbound(ctx context.Context, cfg *config.ProxyOutbound) (UDPOutbound, error)
	CreateDialer(ctx context.Context, cfg *config.ProxyOutbound) (Dialer, error)
}

type FactoryFuncs struct {
	CreateUDPOutboundFunc func(ctx context.Context, cfg *config.ProxyOutbound) (UDPOutbound, error)
	CreateDialerFunc      func(ctx context.Context, cfg *config.ProxyOutbound) (Dialer, error)
}

func (f FactoryFuncs) CreateUDPOutbound(ctx context.Context, cfg *config.ProxyOutbound) (UDPOutbound, error) {
	if f.CreateUDPOutboundFunc == nil {
		return nil, ErrNotImplemented
	}
	return f.CreateUDPOutboundFunc(ctx, cfg)
}

func (f FactoryFuncs) CreateDialer(ctx context.Context, cfg *config.ProxyOutbound) (Dialer, error) {
	if f.CreateDialerFunc == nil {
		return nil, ErrNotImplemented
	}
	return f.CreateDialerFunc(ctx, cfg)
}

type PlaceholderFactory struct{}

func NewPlaceholderFactory() *PlaceholderFactory {
	return &PlaceholderFactory{}
}

func (f *PlaceholderFactory) CreateUDPOutbound(context.Context, *config.ProxyOutbound) (UDPOutbound, error) {
	return nil, ErrNotImplemented
}

func (f *PlaceholderFactory) CreateDialer(context.Context, *config.ProxyOutbound) (Dialer, error) {
	return nil, ErrNotImplemented
}

var _ Factory = FactoryFuncs{}
var _ Factory = (*PlaceholderFactory)(nil)
