// Tests for hysteria2PacketConn.ReadFrom's reused-timer logic (see
// singbox_factory.go). Before this change, ReadFrom allocated a brand new
// timer via time.After on every single call, which on a long-lived,
// high-packet-rate MC session adds steady timer/GC churn. The fix reuses one
// *time.Timer per connection via Reset/Stop, which only works correctly if
// the timer's channel is properly drained across the "success" and "timeout"
// branches per Go's documented Timer.Reset contract. These tests exercise
// exactly that: repeated timeout/success cycles on the same connection.
package proxy

import (
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// hy2FakeMsg is one queued Receive() result for fakeHy2UDPConn.
type hy2FakeMsg struct {
	data []byte
	addr string
}

// fakeHy2UDPConn is a minimal hy2.HyUDPConn (Receive/Send/Close) fake that
// lets tests control exactly when data becomes available, without a real
// Hysteria2/QUIC connection.
type fakeHy2UDPConn struct {
	mu     sync.Mutex
	closed bool
	dataCh chan hy2FakeMsg
}

func newFakeHy2UDPConn() *fakeHy2UDPConn {
	return &fakeHy2UDPConn{dataCh: make(chan hy2FakeMsg, 4)}
}

func (f *fakeHy2UDPConn) Receive() ([]byte, string, error) {
	msg, ok := <-f.dataCh
	if !ok {
		return nil, "", errHy2FakeClosed
	}
	return msg.data, msg.addr, nil
}

func (f *fakeHy2UDPConn) Send([]byte, string) error { return nil }

func (f *fakeHy2UDPConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.dataCh)
	}
	return nil
}

type hy2FakeClosedErr struct{}

func (hy2FakeClosedErr) Error() string { return "fake hy2 conn closed" }

var errHy2FakeClosed = hy2FakeClosedErr{}

// TestHysteria2PacketConn_ReadFrom_ReusesTimerAcrossCycles drives several
// timeout/success cycles on the same hysteria2PacketConn and checks each one
// behaves correctly. A buggy Reset-without-drain would manifest as either a
// read returning immediately with a stale timeout, or a panic/hang.
func TestHysteria2PacketConn_ReadFrom_ReusesTimerAcrossCycles(t *testing.T) {
	fake := newFakeHy2UDPConn()
	c := &hysteria2PacketConn{
		conn:        fake,
		destination: M.ParseSocksaddr("127.0.0.1:19132"),
	}
	defer c.Close()

	buf := make([]byte, 1500)

	// Cycle 1: no data ready, short deadline — must time out.
	assertHy2Timeout(t, c, buf, "cycle 1 (initial timeout)")

	// Cycle 2: data already queued, longer deadline — must succeed and
	// correctly stop the timer it just reused from cycle 1.
	fake.dataCh <- hy2FakeMsg{data: []byte("hello"), addr: "127.0.0.1:19132"}
	assertHy2Success(t, c, buf, "hello", "cycle 2 (first success)")

	// Cycle 3: no data again — proves Reset() after a successful read (which
	// took the recvCh branch, not the timer branch) is still safe.
	assertHy2Timeout(t, c, buf, "cycle 3 (timeout after success)")

	// Cycle 4: data queued again — proves the timer keeps working correctly
	// across repeated timeout->success->timeout transitions, not just once.
	fake.dataCh <- hy2FakeMsg{data: []byte("world"), addr: "127.0.0.1:19132"}
	assertHy2Success(t, c, buf, "world", "cycle 4 (second success)")

	// Cycle 5: back-to-back timeouts — the timer must be safely re-armable
	// even when it fires and is never drained by a competing recvCh send.
	assertHy2Timeout(t, c, buf, "cycle 5 (timeout again)")
	assertHy2Timeout(t, c, buf, "cycle 6 (timeout again)")
}

// TestHysteria2PacketConn_ReadFrom_NoDeadlineUsesDefaultTimeout verifies the
// no-deadline-set default (30s) path also goes through the reused timer
// without special-casing it into a bug (e.g. forgetting to Reset before use).
// We can't wait 30s in a test, so we only check that data delivered promptly
// is returned promptly, proving the default branch doesn't itself block.
func TestHysteria2PacketConn_ReadFrom_NoDeadlineUsesDefaultTimeout(t *testing.T) {
	fake := newFakeHy2UDPConn()
	c := &hysteria2PacketConn{
		conn:        fake,
		destination: M.ParseSocksaddr("127.0.0.1:19132"),
	}
	defer c.Close()

	fake.dataCh <- hy2FakeMsg{data: []byte("no-deadline"), addr: "127.0.0.1:19132"}
	buf := make([]byte, 1500)
	assertHy2Success(t, c, buf, "no-deadline", "no read deadline set")
}

// TestHysteria2PacketConn_Close_StopsTimerWithoutPanic ensures Close() can
// run even while a timer exists (created by a prior ReadFrom), and that a
// ReadFrom racing with/after Close() fails cleanly instead of panicking.
func TestHysteria2PacketConn_Close_StopsTimerWithoutPanic(t *testing.T) {
	fake := newFakeHy2UDPConn()
	c := &hysteria2PacketConn{
		conn:        fake,
		destination: M.ParseSocksaddr("127.0.0.1:19132"),
	}

	assertHy2Timeout(t, c, make([]byte, 64), "pre-close timeout")

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close should be idempotent, got: %v", err)
	}

	if _, _, err := c.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("expected ReadFrom after Close to return an error")
	}
}

func assertHy2Timeout(t *testing.T, c *hysteria2PacketConn, buf []byte, label string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	done := make(chan struct{})
	var n int
	var err error
	go func() {
		defer close(done)
		n, _, err = c.ReadFrom(buf)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: ReadFrom did not return within 2s", label)
	}
	if err == nil {
		t.Fatalf("%s: expected timeout error, got n=%d err=nil", label, n)
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("%s: expected a timeout net.Error, got %v (%T)", label, err, err)
	}
}

func assertHy2Success(t *testing.T, c *hysteria2PacketConn, buf []byte, want string, label string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("%s: expected successful read, got err=%v", label, err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("%s: got %q, want %q", label, got, want)
	}
}
