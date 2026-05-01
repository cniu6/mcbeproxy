package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/singboxcore"
)

type countingFactory struct {
	udpCreateCount    int
	dialerCreateCount int
	lastUDP           *countingUDPOutbound
	lastDialer        *countingDialer
}

func (f *countingFactory) CreateUDPOutbound(context.Context, *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
	f.udpCreateCount++
	outbound := &countingUDPOutbound{}
	f.lastUDP = outbound
	return outbound, nil
}

func (f *countingFactory) CreateDialer(context.Context, *config.ProxyOutbound) (singboxcore.Dialer, error) {
	f.dialerCreateCount++
	dialer := &countingDialer{}
	f.lastDialer = dialer
	return dialer, nil
}

type countingUDPOutbound struct {
	listenPacketCalls int
	lastDestination   string
	closeCalls        int
}

func (o *countingUDPOutbound) ListenPacket(_ context.Context, destination string) (net.PacketConn, error) {
	o.listenPacketCalls++
	o.lastDestination = destination
	return &stubPacketConn{}, nil
}

func (o *countingUDPOutbound) Close() error {
	o.closeCalls++
	return nil
}

type countingDialer struct {
	dialCalls   int
	lastNetwork string
	lastAddress string
	closeCalls  int
}

func (d *countingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.dialCalls++
	d.lastNetwork = network
	d.lastAddress = address
	return &stubConn{}, nil
}

func (d *countingDialer) Close() error {
	d.closeCalls++
	return nil
}

type stubPacketConn struct{}

func (c *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, &net.UDPAddr{}, nil }
func (c *stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *stubPacketConn) Close() error                              { return nil }
func (c *stubPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *stubPacketConn) SetDeadline(time.Time) error               { return nil }
func (c *stubPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (c *stubPacketConn) SetWriteDeadline(time.Time) error          { return nil }

type stubConn struct{}

func (c *stubConn) Read([]byte) (int, error)         { return 0, nil }
func (c *stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stubConn) Close() error                     { return nil }
func (c *stubConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stubConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedUDPFactory struct {
	outbounds   []singboxcore.UDPOutbound
	createCount int
}

func (f *scriptedUDPFactory) CreateUDPOutbound(context.Context, *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
	if f.createCount >= len(f.outbounds) {
		return &stubPacketConnOutbound{}, nil
	}
	outbound := f.outbounds[f.createCount]
	f.createCount++
	return outbound, nil
}

func (f *scriptedUDPFactory) CreateDialer(context.Context, *config.ProxyOutbound) (singboxcore.Dialer, error) {
	return &countingDialer{}, nil
}

type stubPacketConnOutbound struct{}

func (o *stubPacketConnOutbound) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return &stubPacketConn{}, nil
}

func (o *stubPacketConnOutbound) Close() error { return nil }

type scriptedUDPOutbound struct {
	errs        []error
	listenCalls int
	closeCalls  int
}

func (o *scriptedUDPOutbound) ListenPacket(context.Context, string) (net.PacketConn, error) {
	o.listenCalls++
	if len(o.errs) > 0 {
		err := o.errs[0]
		o.errs = o.errs[1:]
		return nil, err
	}
	return &stubPacketConn{}, nil
}

func (o *scriptedUDPOutbound) Close() error {
	o.closeCalls++
	return nil
}

func testFactoryOutboundConfig() *config.ProxyOutbound {
	return &config.ProxyOutbound{
		Name:    "node-a",
		Type:    config.ProtocolSOCKS5,
		Server:  "127.0.0.1",
		Port:    1080,
		Enabled: true,
	}
}

func TestOutboundManagerWithSingboxFactoryUsesInjectedUDPFactory(t *testing.T) {
	factory := &countingFactory{}
	manager := NewOutboundManagerWithSingboxFactory(nil, factory)
	cfg := testFactoryOutboundConfig()
	if err := manager.AddOutbound(cfg); err != nil {
		t.Fatalf("AddOutbound returned error: %v", err)
	}

	conn, err := manager.DialPacketConn(context.Background(), cfg.Name, "example.com:19132")
	if err != nil {
		t.Fatalf("DialPacketConn returned error: %v", err)
	}
	_ = conn.Close()

	conn, err = manager.DialPacketConn(context.Background(), cfg.Name, "example.com:19132")
	if err != nil {
		t.Fatalf("DialPacketConn second call returned error: %v", err)
	}
	_ = conn.Close()

	if factory.udpCreateCount != 1 {
		t.Fatalf("expected UDP factory to be called once, got %d", factory.udpCreateCount)
	}
	if factory.lastUDP == nil {
		t.Fatal("expected lastUDP to be recorded")
	}
	if factory.lastUDP.listenPacketCalls != 2 {
		t.Fatalf("expected cached outbound ListenPacket twice, got %d", factory.lastUDP.listenPacketCalls)
	}
	if factory.lastUDP.lastDestination != "example.com:19132" {
		t.Fatalf("unexpected last destination: %q", factory.lastUDP.lastDestination)
	}
}

func TestOutboundManagerRecreatesAnyTLSUDPOutboundOnClosedError(t *testing.T) {
	first := &scriptedUDPOutbound{errs: []error{errors.New("connection closed")}}
	second := &scriptedUDPOutbound{}
	factory := &scriptedUDPFactory{outbounds: []singboxcore.UDPOutbound{first, second}}
	manager := NewOutboundManagerWithSingboxFactory(nil, factory)
	cfg := &config.ProxyOutbound{
		Name:     "anytls-a",
		Type:     config.ProtocolAnyTLS,
		Server:   "127.0.0.1",
		Port:     443,
		Enabled:  true,
		Password: "password",
		TLS:      true,
	}
	if err := manager.AddOutbound(cfg); err != nil {
		t.Fatalf("AddOutbound returned error: %v", err)
	}

	conn, err := manager.DialPacketConn(context.Background(), cfg.Name, "example.com:19132")
	if err != nil {
		t.Fatalf("DialPacketConn returned error: %v", err)
	}
	_ = conn.Close()

	if factory.createCount != 2 {
		t.Fatalf("expected factory to recreate UDP outbound, got createCount=%d", factory.createCount)
	}
	if first.closeCalls != 1 {
		t.Fatalf("expected stale outbound to be closed once, got %d", first.closeCalls)
	}
	if first.listenCalls != 1 || second.listenCalls != 1 {
		t.Fatalf("unexpected listen calls: first=%d second=%d", first.listenCalls, second.listenCalls)
	}
	status := manager.GetHealthStatus(cfg.Name)
	if status == nil || !status.Healthy || status.LastError != "" {
		t.Fatalf("expected outbound healthy after recreate, got %+v", status)
	}
}

func TestOutboundManagerWithSingboxFactoryUsesInjectedDialerFactory(t *testing.T) {
	factory := &countingFactory{}
	manager := NewOutboundManagerWithSingboxFactory(nil, factory)
	cfg := testFactoryOutboundConfig()
	if err := manager.AddOutbound(cfg); err != nil {
		t.Fatalf("AddOutbound returned error: %v", err)
	}

	if err := manager.CheckHealth(context.Background(), cfg.Name); err != nil {
		t.Fatalf("CheckHealth returned error: %v", err)
	}
	if factory.dialerCreateCount != 1 {
		t.Fatalf("expected dialer factory to be called once, got %d", factory.dialerCreateCount)
	}
	if factory.lastDialer == nil {
		t.Fatal("expected lastDialer to be recorded")
	}
	if factory.lastDialer.dialCalls != 1 {
		t.Fatalf("expected DialContext to be called once, got %d", factory.lastDialer.dialCalls)
	}
	if factory.lastDialer.lastNetwork != "tcp" || factory.lastDialer.lastAddress != "1.1.1.1:443" {
		t.Fatalf("unexpected health-check dial target: %s %s", factory.lastDialer.lastNetwork, factory.lastDialer.lastAddress)
	}
}

func TestProxyPortDialerPoolUsesFactoryAndCachesDialers(t *testing.T) {
	factory := &countingFactory{}
	pool := newProxyPortDialerPool(factory)
	cfg := testFactoryOutboundConfig()

	dialer1, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	dialer2, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get second call returned error: %v", err)
	}
	if dialer1 != dialer2 {
		t.Fatal("expected dialer pool to return cached dialer instance")
	}
	if factory.dialerCreateCount != 1 {
		t.Fatalf("expected factory dialer creation once, got %d", factory.dialerCreateCount)
	}
}

func TestProxyPortDialerPoolRecreatesDialerWhenSameNameConfigChanges(t *testing.T) {
	factory := &countingFactory{}
	pool := newProxyPortDialerPool(factory)
	cfg := testFactoryOutboundConfig()

	dialer1, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	updated := *cfg
	updated.Server = "127.0.0.2"
	dialer2, err := pool.Get(&updated)
	if err != nil {
		t.Fatalf("Get updated returned error: %v", err)
	}
	dialer3, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get original returned error: %v", err)
	}

	if dialer1 == dialer2 {
		t.Fatal("expected changed config to create a different dialer")
	}
	if dialer1 != dialer3 {
		t.Fatal("expected unchanged original config to reuse original dialer")
	}
	if factory.dialerCreateCount != 2 {
		t.Fatalf("expected two dialer creations, got %d", factory.dialerCreateCount)
	}
}

func TestWSConnRead_RejectsOversizedFrame(t *testing.T) {
	frame := bytes.NewBuffer(nil)
	frame.WriteByte(0x82)
	frame.WriteByte(127)
	var lengthBuf [8]byte
	binary.BigEndian.PutUint64(lengthBuf[:], uint64(maxWebSocketFramePayload+1))
	frame.Write(lengthBuf[:])

	conn := &wsConn{reader: bufio.NewReader(bytes.NewReader(frame.Bytes()))}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected oversized frame error, got nil")
	}
	if !strings.Contains(err.Error(), "websocket frame too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWSConnRead_SkipsControlFramesAndReturnsNextDataFrame(t *testing.T) {
	frame := bytes.NewBuffer(nil)
	frame.Write([]byte{0x89, 0x00})
	frame.Write([]byte{0x82, 0x05})
	frame.WriteString("hello")

	conn := &wsConn{reader: bufio.NewReader(bytes.NewReader(frame.Bytes()))}
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("unexpected payload: %q", got)
	}
}
