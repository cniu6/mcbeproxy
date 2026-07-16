// Package proxy - tests for the Hysteria2 port-hopping PacketConn wrapper.
//
// portHoppingPacketConn must not implement quic-go's OOBCapablePacketConn on Linux,
// or ipv4.NewPacketConn will panic because the wrapper is not a net.Conn.
package proxy

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUDPLikeConn is a minimal net.PacketConn for WriteTo forwarding tests.
type fakeUDPLikeConn struct {
	writeToCalls int32
	lastWriteDst *net.UDPAddr
}

func (f *fakeUDPLikeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (f *fakeUDPLikeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	atomic.AddInt32(&f.writeToCalls, 1)
	if udp, ok := addr.(*net.UDPAddr); ok {
		f.lastWriteDst = udp
	}
	return len(p), nil
}

func (f *fakeUDPLikeConn) Close() error                       { return nil }
func (f *fakeUDPLikeConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (f *fakeUDPLikeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeUDPLikeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeUDPLikeConn) SetWriteDeadline(t time.Time) error { return nil }

// TestPortHoppingPacketConn_DoesNotExposeOOBCapable verifies we do not satisfy
// quic-go OOBCapablePacketConn, avoiding ipv4.NewPacketConn panic on Linux.
func TestPortHoppingPacketConn_DoesNotExposeOOBCapable(t *testing.T) {
	fake := &fakeUDPLikeConn{}
	wrapper := &portHoppingPacketConn{
		PacketConn:  fake,
		serverIP:    net.IPv4(10, 0, 0, 1),
		portStart:   50000,
		portEnd:     50010,
		hopInterval: 24 * time.Hour,
		currentPort: 50000,
		lastHop:     time.Now(),
	}

	if _, ok := interface{}(wrapper).(interface {
		ReadMsgUDP([]byte, []byte) (int, int, int, *net.UDPAddr, error)
	}); ok {
		t.Fatal("portHoppingPacketConn must not expose ReadMsgUDP (quic-go OOB path panics on Linux)")
	}
	if _, ok := interface{}(wrapper).(interface {
		SyscallConn() (interface{}, error)
	}); ok {
		t.Fatal("portHoppingPacketConn must not expose SyscallConn for OOB quic-go path")
	}
}

// TestPortHoppingPacketConn_WriteToRewritesPort verifies WriteTo rewrites
// the destination to the currently selected hopping port.
func TestPortHoppingPacketConn_WriteToRewritesPort(t *testing.T) {
	fake := &fakeUDPLikeConn{}
	wrapper := &portHoppingPacketConn{
		PacketConn:  fake,
		serverIP:    net.IPv4(10, 0, 0, 1),
		portStart:   50000,
		portEnd:     50010,
		hopInterval: 24 * time.Hour,
		currentPort: 50007,
		lastHop:     time.Now(),
	}

	payload := []byte("hello")
	callerAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1}
	if _, err := wrapper.WriteTo(payload, callerAddr); err != nil {
		t.Fatalf("WriteTo returned error: %v", err)
	}
	if fake.lastWriteDst == nil {
		t.Fatal("WriteTo did not reach underlying conn")
	}
	if !fake.lastWriteDst.IP.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("WriteTo did not rewrite destination IP: got %s", fake.lastWriteDst.IP)
	}
	if fake.lastWriteDst.Port != 50007 {
		t.Fatalf("WriteTo did not use currentPort: got %d, want %d", fake.lastWriteDst.Port, 50007)
	}
}