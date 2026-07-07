package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/singboxcore"
)

type runtimeTestFactory struct {
	mu        sync.Mutex
	outbounds []*runtimeTestUDPOutbound
}

func (f *runtimeTestFactory) CreateUDPOutbound(ctx context.Context, cfg *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	outbound := &runtimeTestUDPOutbound{id: len(f.outbounds) + 1}
	f.outbounds = append(f.outbounds, outbound)
	return outbound, nil
}

func (f *runtimeTestFactory) CreateDialer(ctx context.Context, cfg *config.ProxyOutbound) (singboxcore.Dialer, error) {
	return nil, singboxcore.ErrNotImplemented
}

func (f *runtimeTestFactory) created() []*runtimeTestUDPOutbound {
	f.mu.Lock()
	defer f.mu.Unlock()
	outbounds := make([]*runtimeTestUDPOutbound, len(f.outbounds))
	copy(outbounds, f.outbounds)
	return outbounds
}

type runtimeTestUDPOutbound struct {
	mu          sync.Mutex
	id          int
	listenCalls int
	failOnCall  map[int]error
	closed      bool
	closeCount  int
	conns       []*runtimeTestPacketConn
}

func (o *runtimeTestUDPOutbound) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.listenCalls++
	if err := o.failOnCall[o.listenCalls]; err != nil {
		return nil, err
	}
	if o.closed {
		return nil, errors.New("outbound closed")
	}
	conn := newRuntimeTestPacketConn(o.id)
	o.conns = append(o.conns, conn)
	return conn, nil
}

func (o *runtimeTestUDPOutbound) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	o.closeCount++
	conns := make([]*runtimeTestPacketConn, len(o.conns))
	copy(conns, o.conns)
	o.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return nil
}

func (o *runtimeTestUDPOutbound) setFailOnCall(call int, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failOnCall == nil {
		o.failOnCall = make(map[int]error)
	}
	o.failOnCall[call] = err
}

func (o *runtimeTestUDPOutbound) closeCountValue() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closeCount
}

type runtimeTestPacketConn struct {
	id     int
	closed chan struct{}
	once   sync.Once
}

func newRuntimeTestPacketConn(id int) *runtimeTestPacketConn {
	return &runtimeTestPacketConn{id: id, closed: make(chan struct{})}
}

func (c *runtimeTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, errors.New("closed")
	case <-time.After(10 * time.Millisecond):
		return 0, nil, timeoutErr{}
	}
}

func (c *runtimeTestPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, errors.New("closed")
	default:
		return len(p), nil
	}
}

func (c *runtimeTestPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *runtimeTestPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *runtimeTestPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *runtimeTestPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *runtimeTestPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func testRuntimeOutboundConfig(name string) *config.ProxyOutbound {
	return &config.ProxyOutbound{
		Name:    name,
		Type:    config.ProtocolSOCKS5,
		Server:  "127.0.0.1",
		Port:    1080,
		Enabled: true,
	}
}

func TestUpdateOutboundNoChangeKeepsActiveSingboxRuntime(t *testing.T) {
	factory := &runtimeTestFactory{}
	mgr := NewOutboundManagerWithSingboxFactory(nil, factory).(*outboundManagerImpl)
	cfg := testRuntimeOutboundConfig("node-a")
	if err := mgr.AddOutbound(cfg); err != nil {
		t.Fatalf("AddOutbound failed: %v", err)
	}

	conn, err := mgr.DialPacketConnNoRetry(context.Background(), cfg.Name, "127.0.0.1:19132")
	if err != nil {
		t.Fatalf("DialPacketConnNoRetry failed: %v", err)
	}
	defer conn.Close()

	if err := mgr.UpdateOutbound(cfg.Name, cfg.Clone()); err != nil {
		t.Fatalf("UpdateOutbound failed: %v", err)
	}
	created := factory.created()
	if len(created) != 1 {
		t.Fatalf("expected no-op update to reuse runtime, got %d runtimes", len(created))
	}
	if got := created[0].closeCountValue(); got != 0 {
		t.Fatalf("expected active runtime to remain open after no-op update, close count=%d", got)
	}

	conn2, err := mgr.DialPacketConnNoRetry(context.Background(), cfg.Name, "127.0.0.1:19132")
	if err != nil {
		t.Fatalf("second DialPacketConnNoRetry failed: %v", err)
	}
	defer conn2.Close()
	if len(factory.created()) != 1 {
		t.Fatalf("expected second dial after no-op update to reuse runtime, got %d runtimes", len(factory.created()))
	}
}

func TestRecreateSingboxRuntimeDoesNotCloseOlderActivePacketConn(t *testing.T) {
	factory := &runtimeTestFactory{}
	mgr := NewOutboundManagerWithSingboxFactory(nil, factory).(*outboundManagerImpl)
	cfg := testRuntimeOutboundConfig("node-a")
	if err := mgr.AddOutbound(cfg); err != nil {
		t.Fatalf("AddOutbound failed: %v", err)
	}

	conn, err := mgr.DialPacketConnNoRetry(context.Background(), cfg.Name, "127.0.0.1:19132")
	if err != nil {
		t.Fatalf("first DialPacketConnNoRetry failed: %v", err)
	}

	created := factory.created()
	if len(created) != 1 {
		t.Fatalf("expected first dial to create one runtime, got %d", len(created))
	}
	created[0].setFailOnCall(2, errors.New("connection closed"))

	conn2, err := mgr.DialPacketConnNoRetry(context.Background(), cfg.Name, "127.0.0.1:19132")
	if err != nil {
		t.Fatalf("second DialPacketConnNoRetry after recreate failed: %v", err)
	}
	defer conn2.Close()

	created = factory.created()
	if len(created) != 2 {
		t.Fatalf("expected failed dial to recreate runtime, got %d runtimes", len(created))
	}
	if got := created[0].closeCountValue(); got != 0 {
		t.Fatalf("old runtime closed while first PacketConn is still active, close count=%d", got)
	}
	if _, err := conn.WriteTo([]byte("still-open"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}); err != nil {
		t.Fatalf("first PacketConn was closed by recreate: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("closing first PacketConn failed: %v", err)
	}
	if got := created[0].closeCountValue(); got != 1 {
		t.Fatalf("old runtime should close after its last PacketConn closes, close count=%d", got)
	}
}
