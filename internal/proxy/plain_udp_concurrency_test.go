package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// TestPlainUDPProxy_NewClientSlowDialDoesNotBlockExistingClients guards
// against the same head-of-line-blocking class of bug fixed in RawUDPProxy:
// getOrCreateClient runs on PlainUDPProxy's single hot receive-loop
// goroutine (see Listen()), so a synchronous proxy dial for a brand new
// player must not stall traffic for every other already-connected player on
// the same server. New clients are dialed asynchronously whenever at least
// one other client is already active; the triggering packet (and any
// retries that arrive while still connecting) must be buffered, not lost,
// and a duplicate/retry packet while pending must not trigger a second dial.
func TestPlainUDPProxy_NewClientSlowDialDoesNotBlockExistingClients(t *testing.T) {
	fastConnA := newCountingPacketConn()
	slowConnB := newCountingPacketConn()
	var connMu sync.Mutex
	callCount := 0

	mgr := &countingRawUDPOutboundManager{
		connFactory: func() *countingPacketConn {
			connMu.Lock()
			defer connMu.Unlock()
			callCount++
			if callCount == 1 {
				return fastConnA
			}
			return slowConnB
		},
	}
	dialStarted := make(chan struct{}, 4)
	releaseDial := make(chan struct{})
	mgr.dialStartedCh = dialStarted
	mgr.releaseDialCh = releaseDial

	cfg := &config.ServerConfig{
		ID:            "plain-async-dial-test",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:0",
		ProxyOutbound: "node-a",
		IdleTimeout:   300,
	}
	p := NewPlainUDPProxy("plain-async-dial-test", cfg)
	p.SetOutboundManager(mgr)
	p.UpdateConfig(cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start plain udp proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Listen(ctx) }()

	cleanup := func() {
		cancel() // unblocks any goroutine parked on mgr's ctx.Done() branch.
		_ = p.Stop()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Fatal("Listen did not exit during cleanup")
		}
	}
	defer cleanup()

	// Client A connects first, while the mock isn't delaying dials yet, so it
	// takes the existing synchronous fast path and becomes fully active.
	clientA, err := net.DialUDP("udp", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial proxy listener (A): %v", err)
	}
	defer clientA.Close()
	clientAKey := clientA.LocalAddr().String()
	if _, err := clientA.Write([]byte{0x01}); err != nil {
		t.Fatalf("client A send: %v", err)
	}
	waitUntil(t, time.Second, func() bool {
		val, ok := p.clients.Load(clientAKey)
		ci, isCI := val.(*plainUDPClient)
		return ok && isCI && !ci.pending.Load() && ci.targetConn != nil
	}, "client A never became active")

	// Now make any further dial stall until releaseDial is closed, so client
	// B's connection attempt gets stuck mid-dial.
	mgr.mu.Lock()
	mgr.delayDials = true
	mgr.mu.Unlock()

	clientB, err := net.DialUDP("udp", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial proxy listener (B): %v", err)
	}
	defer clientB.Close()
	clientBKey := clientB.LocalAddr().String()
	if _, err := clientB.Write([]byte{0x02}); err != nil {
		t.Fatalf("client B send: %v", err)
	}

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("client B dial never started")
	}

	// Client B must show up as a pending placeholder immediately, without
	// waiting for its stuck dial.
	waitUntil(t, time.Second, func() bool {
		val, ok := p.clients.Load(clientBKey)
		ci, isCI := val.(*plainUDPClient)
		return ok && isCI && ci.pending.Load()
	}, "client B was not registered as a pending placeholder")

	// While B's dial is stuck, client A's traffic must keep flowing through
	// the hot loop (and its async writer) with low latency — proving the
	// loop isn't blocked on B.
	start := time.Now()
	if _, err := clientA.Write([]byte{0x03}); err != nil {
		t.Fatalf("client A second send: %v", err)
	}
	waitUntil(t, time.Second, func() bool {
		fastConnA.mu.Lock()
		defer fastConnA.mu.Unlock()
		return fastConnA.writes >= 2
	}, "client A's second packet was not forwarded while client B's dial was stuck")
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("client A traffic delayed by client B's slow dial: %v", elapsed)
	}

	// A retry/duplicate packet from client B while still pending must be
	// buffered silently — no panic, and critically no second dial attempt.
	if _, err := clientB.Write([]byte{0x04}); err != nil {
		t.Fatalf("client B retry send: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	// Release the stuck dial; client B should finish connecting normally and
	// its buffered packets should flush through to its target connection.
	close(releaseDial)
	waitUntil(t, 2*time.Second, func() bool {
		val, ok := p.clients.Load(clientBKey)
		ci, isCI := val.(*plainUDPClient)
		return ok && isCI && !ci.pending.Load() && ci.targetConn != nil
	}, "client B never finished connecting after dial release")

	waitUntil(t, time.Second, func() bool {
		slowConnB.mu.Lock()
		defer slowConnB.mu.Unlock()
		return slowConnB.writes >= 2
	}, "client B's buffered packets (initial + retry) were not flushed after connecting")

	if dials, _ := mgr.counts(); dials != 2 {
		t.Fatalf("expected exactly 2 real dials (A and B); retries while pending must not trigger extra dials, got %d", dials)
	}
}

// TestPlainUDPProxy_StopDoesNotHangWithPendingOrActiveClients guards against
// a goroutine leak: Stop() must wake up every client's forwardUpstreamWrites
// goroutine (via stopUpstreamWriter) before p.wg.Wait(), otherwise a writer
// idling on an empty channel with no way to observe shutdown would hang
// Stop() forever. Also covers a placeholder still mid-dial at Stop() time.
func TestPlainUDPProxy_StopDoesNotHangWithPendingOrActiveClients(t *testing.T) {
	mgr := &countingRawUDPOutboundManager{}
	dialStarted := make(chan struct{}, 4)
	releaseDial := make(chan struct{})
	mgr.dialStartedCh = dialStarted
	mgr.releaseDialCh = releaseDial

	cfg := &config.ServerConfig{
		ID:            "plain-stop-hang-test",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:0",
		ProxyOutbound: "node-a",
		IdleTimeout:   300,
	}
	p := NewPlainUDPProxy("plain-stop-hang-test", cfg)
	p.SetOutboundManager(mgr)
	p.UpdateConfig(cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("start plain udp proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Listen(ctx) }()
	defer cancel()

	clientA, err := net.DialUDP("udp", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial proxy listener (A): %v", err)
	}
	defer clientA.Close()
	clientAKey := clientA.LocalAddr().String()
	if _, err := clientA.Write([]byte{0x01}); err != nil {
		t.Fatalf("client A send: %v", err)
	}
	waitUntil(t, time.Second, func() bool {
		val, ok := p.clients.Load(clientAKey)
		ci, isCI := val.(*plainUDPClient)
		return ok && isCI && !ci.pending.Load() && ci.targetConn != nil
	}, "client A never became active")

	mgr.mu.Lock()
	mgr.delayDials = true
	mgr.mu.Unlock()

	clientB, err := net.DialUDP("udp", nil, p.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial proxy listener (B): %v", err)
	}
	defer clientB.Close()
	if _, err := clientB.Write([]byte{0x02}); err != nil {
		t.Fatalf("client B send: %v", err)
	}
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("client B dial never started")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- p.Stop() }()

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() hung — likely a leaked forwardUpstreamWrites/dial goroutine")
	}

	close(releaseDial)
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not exit after Stop")
	}
}
