// Package proxy - tests for the Hysteria2 port-hopping PacketConn wrapper.
//
// These tests guard the pass-through contract between portHoppingPacketConn
// and quic-go's sys_conn_buffers.go probing. quic-go uses interface type
// assertions to decide whether to bump the UDP socket receive/send buffer
// up to ~7 MiB and whether to probe DF/ECN/GSO via SyscallConn. When the
// wrapper does not satisfy these assertions, we silently fall back to the
// tiny default OS buffer (8 KiB on Windows) and drop QUIC handshake
// packets on higher-RTT Hysteria2 paths.
package proxy

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeUDPLikeConn is a minimal net.PacketConn that exposes the same
// optimization methods quic-go looks for on *net.UDPConn. It records which
// methods were called so we can assert portHoppingPacketConn forwards them.
type fakeUDPLikeConn struct {
	setReadCalls  int32
	setWriteCalls int32
	syscallCalls  int32
	readMsgCalls  int32
	writeMsgCalls int32
	writeToCalls  int32

	lastReadBuf  int
	lastWriteBuf int
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

func (f *fakeUDPLikeConn) SetReadBuffer(bytes int) error {
	atomic.AddInt32(&f.setReadCalls, 1)
	f.lastReadBuf = bytes
	return nil
}

func (f *fakeUDPLikeConn) SetWriteBuffer(bytes int) error {
	atomic.AddInt32(&f.setWriteCalls, 1)
	f.lastWriteBuf = bytes
	return nil
}

func (f *fakeUDPLikeConn) SyscallConn() (syscall.RawConn, error) {
	atomic.AddInt32(&f.syscallCalls, 1)
	// Return nil RawConn; quic-go tolerates the nil + error case by falling
	// back to non-DF probing. For the test we only care the method was
	// invoked on the wrapper.
	return nil, errors.New("not implemented")
}

func (f *fakeUDPLikeConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	atomic.AddInt32(&f.readMsgCalls, 1)
	return 0, 0, 0, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}, errors.New("not implemented")
}

func (f *fakeUDPLikeConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	atomic.AddInt32(&f.writeMsgCalls, 1)
	f.lastWriteDst = addr
	return len(b), 0, nil
}

// TestPortHoppingPacketConn_ForwardsUDPOptimizations verifies the wrapper
// satisfies the interface type assertions quic-go performs in
// sys_conn_buffers.go and sys_conn.go. Missing any of these forwards
// regresses Hysteria2 QUIC handshake reliability under load.
func TestPortHoppingPacketConn_ForwardsUDPOptimizations(t *testing.T) {
	fake := &fakeUDPLikeConn{}
	wrapper := &portHoppingPacketConn{
		PacketConn:  fake,
		serverIP:    net.IPv4(10, 0, 0, 1),
		portStart:   50000,
		portEnd:     50010,
		hopInterval: 24 * time.Hour, // never hop during the test
		currentPort: 50000,
		lastHop:     time.Now(),
	}

	// SetReadBuffer / SetWriteBuffer must type-assert successfully against
	// interface{ SetReadBuffer(int) error } and reach the underlying conn.
	if _, ok := interface{}(wrapper).(interface {
		SetReadBuffer(int) error
	}); !ok {
		t.Fatal("portHoppingPacketConn does not expose SetReadBuffer; quic-go buffer tuning will be skipped")
	}
	if _, ok := interface{}(wrapper).(interface {
		SetWriteBuffer(int) error
	}); !ok {
		t.Fatal("portHoppingPacketConn does not expose SetWriteBuffer; quic-go buffer tuning will be skipped")
	}
	if _, ok := interface{}(wrapper).(interface {
		SyscallConn() (syscall.RawConn, error)
	}); !ok {
		t.Fatal("portHoppingPacketConn does not expose SyscallConn; quic-go DF/ECN probing will be skipped")
	}

	if err := wrapper.SetReadBuffer(7 * 1024 * 1024); err != nil {
		t.Fatalf("SetReadBuffer returned error: %v", err)
	}
	if err := wrapper.SetWriteBuffer(7 * 1024 * 1024); err != nil {
		t.Fatalf("SetWriteBuffer returned error: %v", err)
	}
	if _, err := wrapper.SyscallConn(); err == nil {
		t.Fatal("expected SyscallConn to surface underlying error, got nil")
	}

	if atomic.LoadInt32(&fake.setReadCalls) != 1 {
		t.Fatalf("SetReadBuffer not forwarded: calls=%d", fake.setReadCalls)
	}
	if atomic.LoadInt32(&fake.setWriteCalls) != 1 {
		t.Fatalf("SetWriteBuffer not forwarded: calls=%d", fake.setWriteCalls)
	}
	if atomic.LoadInt32(&fake.syscallCalls) != 1 {
		t.Fatalf("SyscallConn not forwarded: calls=%d", fake.syscallCalls)
	}
	if fake.lastReadBuf != 7*1024*1024 || fake.lastWriteBuf != 7*1024*1024 {
		t.Fatalf("buffer size not forwarded verbatim: read=%d write=%d", fake.lastReadBuf, fake.lastWriteBuf)
	}
}

// TestPortHoppingPacketConn_WriteToRewritesPort verifies WriteTo rewrites
// the destination to the currently selected hopping port so the outbound
// actually hops and doesn't just send to whatever address the caller
// supplied (which for QUIC would short-circuit the hopping feature).
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

// TestPortHoppingPacketConn_WriteMsgUDPPreservesHopping ensures the
// OOB-capable write path also funnels through the hopping port. Without
// this forwarding, quic-go's GSO batch-send path would bypass hopping.
func TestPortHoppingPacketConn_WriteMsgUDPPreservesHopping(t *testing.T) {
	fake := &fakeUDPLikeConn{}
	wrapper := &portHoppingPacketConn{
		PacketConn:  fake,
		serverIP:    net.IPv4(10, 0, 0, 2),
		portStart:   60000,
		portEnd:     60005,
		hopInterval: 24 * time.Hour,
		currentPort: 60003,
		lastHop:     time.Now(),
	}

	payload := []byte("quic-batch")
	callerAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 0, 1), Port: 1}
	n, _, err := wrapper.WriteMsgUDP(payload, nil, callerAddr)
	if err != nil {
		t.Fatalf("WriteMsgUDP error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteMsgUDP short write: got %d, want %d", n, len(payload))
	}
	if atomic.LoadInt32(&fake.writeMsgCalls) != 1 {
		t.Fatalf("WriteMsgUDP not forwarded: calls=%d", fake.writeMsgCalls)
	}
	if fake.lastWriteDst == nil ||
		!fake.lastWriteDst.IP.Equal(net.IPv4(10, 0, 0, 2)) ||
		fake.lastWriteDst.Port != 60003 {
		t.Fatalf("WriteMsgUDP did not rewrite destination to hopping target: got %+v", fake.lastWriteDst)
	}
}
