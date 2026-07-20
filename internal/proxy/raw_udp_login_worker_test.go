// Tests for the raw_udp login-parse shard worker pool introduced to keep a
// slow/CPU-heavy Login+ACL check for one client from stalling packet
// delivery for every other player on the same raw_udp server (see
// startRawUDPLoginWorkers / dispatchLoginPhasePacket / processLoginPhasePacket
// in raw_udp_proxy.go). getOrCreateClient itself intentionally still runs on
// the single hot-loop goroutine and is not covered here — see
// raw_udp_concurrency_test.go for that guarantee.
package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	"mcpeserverproxy/internal/session"
)

// slowACLManager is a fake ACLManager whose CheckAccessWithError call for a
// specific player name blocks until release is closed, letting tests
// simulate a slow ACL database lookup for exactly one client without a real
// database. All calls for other player names return immediately.
type slowACLManager struct {
	targetPlayer string
	checkStarted chan struct{}
	release      chan struct{}
}

func (m *slowACLManager) CheckAccess(_, _ string) (bool, string) { return true, "" }

func (m *slowACLManager) CheckAccessWithError(playerName, _ string) (bool, string, error) {
	if playerName == m.targetPlayer {
		if m.checkStarted != nil {
			select {
			case m.checkStarted <- struct{}{}:
			default:
			}
		}
		if m.release != nil {
			<-m.release
		}
	}
	return true, "", nil
}

func (m *slowACLManager) IsBlacklisted(_, _ string) (bool, *db.BlacklistEntry) { return false, nil }

func (m *slowACLManager) GetSettings(_ string) (*db.ACLSettings, error) {
	return db.DefaultACLSettings(), nil
}

// TestRawUDPLoginShardIndex_StableAndDistributes verifies rawUDPLoginShardIndex
// (a) always returns the same shard for the same address, which is what
// keeps one client's packets processed in order, and (b) actually spreads
// different addresses across more than one shard, which is what makes the
// worker pool useful at all.
func TestRawUDPLoginShardIndex_StableAndDistributes(t *testing.T) {
	shardCount := 8
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}

	first := rawUDPLoginShardIndex(addr, shardCount)
	for i := 0; i < 10; i++ {
		if got := rawUDPLoginShardIndex(addr, shardCount); got != first {
			t.Fatalf("shard index not stable for the same address: %d vs %d", got, first)
		}
	}
	if first < 0 || first >= shardCount {
		t.Fatalf("shard index %d out of range [0,%d)", first, shardCount)
	}

	seen := make(map[int]bool)
	for port := 40000; port < 40000+128; port++ {
		a := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
		seen[rawUDPLoginShardIndex(a, shardCount)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected client addresses to spread across multiple shards, all 128 landed on %d shard(s)", len(seen))
	}

	if got := rawUDPLoginShardIndex(addr, 1); got != 0 {
		t.Fatalf("shardCount=1 must always return 0, got %d", got)
	}
	if got := rawUDPLoginShardIndex(nil, shardCount); got != 0 {
		t.Fatalf("nil address must return 0, got %d", got)
	}
}

// newRawUDPTestClient builds a minimal rawUDPClientInfo suitable for driving
// dispatchLoginPhasePacket/processLoginPhasePacket directly in unit tests,
// without going through Listen()'s real UDP socket.
func newRawUDPTestClient(p *RawUDPProxy, clientAddr *net.UDPAddr, targetConn net.PacketConn) *rawUDPClientInfo {
	return &rawUDPClientInfo{
		clientAddr:      clientAddr,
		targetConn:      targetConn,
		targetAddr:      &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132},
		upstreamWriteCh: make(chan []byte, RawUDPUpstreamWriteQueueSize),
		upstreamDone:    make(chan struct{}),
		startTime:       time.Now(),
		sessionKey:      p.makeSessionKey(clientAddr),
	}
}

// TestDispatchLoginPhasePacket_SyncFallbackWhenWorkersNotStarted verifies
// that calling dispatchLoginPhasePacket before startRawUDPLoginWorkers has
// ever run (p.loginJobChans is nil/empty) falls back to processing the
// packet synchronously instead of silently dropping it.
func TestDispatchLoginPhasePacket_SyncFallbackWhenWorkersNotStarted(t *testing.T) {
	p := &RawUDPProxy{serverID: "sync-fallback-test"}
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51000}
	pc := newCountingPacketConn()
	client := newRawUDPTestClient(p, clientAddr, pc)

	packet := rawUDPClonePacket([]byte{0x80, 0x00, 0x00, 0x00, 0xfe})
	p.dispatchLoginPhasePacket(client, packet, clientAddr)

	select {
	case got := <-client.upstreamWriteCh:
		if len(got) == 0 {
			t.Fatal("expected a non-empty packet queued upstream via synchronous fallback")
		}
	case <-time.After(time.Second):
		t.Fatal("packet was not processed when login workers were never started")
	}
}

// TestDispatchLoginPhasePacket_SyncFallbackWhenShardFull verifies that a
// full shard queue does not block the caller (the hot loop) and does not
// drop the packet — it must fall back to processing it synchronously right
// there, exactly like the "workers not started" case above.
func TestDispatchLoginPhasePacket_SyncFallbackWhenShardFull(t *testing.T) {
	p := &RawUDPProxy{serverID: "shard-full-test"}
	shardCount := rawUDPLoginWorkerCount()
	p.loginJobChans = make([]chan *rawUDPLoginJob, shardCount)
	for i := range p.loginJobChans {
		p.loginJobChans[i] = make(chan *rawUDPLoginJob, rawUDPLoginJobQueueSize)
	}

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 52000}
	idx := rawUDPLoginShardIndex(clientAddr, shardCount)

	// Fill the target shard to capacity with nobody draining it, simulating
	// a worker stuck on other slow work.
	for i := 0; i < rawUDPLoginJobQueueSize; i++ {
		p.loginJobChans[idx] <- &rawUDPLoginJob{}
	}

	pc := newCountingPacketConn()
	client := newRawUDPTestClient(p, clientAddr, pc)
	packet := rawUDPClonePacket([]byte{0x80, 0x00, 0x00, 0x00, 0xfe})

	done := make(chan struct{})
	go func() {
		p.dispatchLoginPhasePacket(client, packet, clientAddr)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatch blocked instead of falling back to synchronous processing when its shard is full")
	}

	select {
	case <-client.upstreamWriteCh:
	case <-time.After(time.Second):
		t.Fatal("expected the packet to still be queued upstream via the synchronous fallback")
	}
}

// TestStartRawUDPLoginWorkers_ShutsDownCleanly verifies the shard workers
// exit promptly once their channels are closed (the pattern Listen() uses in
// its defer), so restarting/stopping a server does not leak goroutines.
func TestStartRawUDPLoginWorkers_ShutsDownCleanly(t *testing.T) {
	p := &RawUDPProxy{serverID: "shutdown-test"}
	wg := p.startRawUDPLoginWorkers()
	if len(p.loginJobChans) == 0 {
		t.Fatal("expected login job shards to be created")
	}

	for _, ch := range p.loginJobChans {
		close(ch)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("login shard workers did not exit after their channels were closed")
	}
}

// TestRawUDPLoginWorkers_PreserveOrderPerClient dispatches several packets
// for the same client back-to-back (as the single hot-loop goroutine would)
// and verifies they are still enqueued upstream in the exact order sent,
// even though they're processed by a pooled worker rather than inline. This
// is the ordering guarantee that split-packet reassembly and the Login
// state machine depend on. The packet count here is kept comfortably under
// rawUDPLoginJobQueueSize (32) so every packet fits in the shard's channel
// buffer and none of them can take the synchronous-fallback path, which
// (intentionally) does not preserve ordering — see
// TestRawUDPLoginWorkers_ShardOverflowCanReorderSyncFallback below.
func TestRawUDPLoginWorkers_PreserveOrderPerClient(t *testing.T) {
	p := &RawUDPProxy{serverID: "order-test"}
	wg := p.startRawUDPLoginWorkers()
	defer func() {
		for _, ch := range p.loginJobChans {
			close(ch)
		}
		wg.Wait()
	}()

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}
	pc := newCountingPacketConn()
	client := newRawUDPTestClient(p, clientAddr, pc)

	const n = rawUDPLoginJobQueueSize / 2
	for i := 0; i < n; i++ {
		// Non-Login reliable frames: cheap to parse and keep loginParseDone
		// false long enough (best-effort budget) that dispatch keeps routing
		// through the shard worker for most/all of these, rather than
		// short-circuiting to the fast post-login path.
		packet := rawUDPClonePacket([]byte{0x80, byte(i >> 8), byte(i), 0x00, 0xfe, byte(i)})
		p.dispatchLoginPhasePacket(client, packet, clientAddr)
	}

	for i := 0; i < n; i++ {
		select {
		case got := <-client.upstreamWriteCh:
			if len(got) == 0 || got[len(got)-1] != byte(i) {
				t.Fatalf("packet %d arrived out of order (marker=%v)", i, got)
			}
			putRawUDPBuffer(got)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for packet %d", i)
		}
	}
}

// TestRawUDPLoginWorkers_ShardOverflowCanReorderSyncFallback documents and
// pins down a known, accepted trade-off: dispatchLoginPhasePacket's
// full-shard fallback processes the packet synchronously on the caller's
// goroutine instead of blocking for queue space (see comment on
// dispatchLoginPhasePacket). That keeps the hot loop from ever stalling or
// dropping a packet, but it means a packet that overflows a full shard can
// be enqueued upstream *ahead of* packets already sitting in that shard's
// channel. This test proves that specific, bounded behavior deterministically
// (by pre-filling the channel to capacity with a blocked worker) rather than
// leaving it as an unverified implicit assumption.
func TestRawUDPLoginWorkers_ShardOverflowCanReorderSyncFallback(t *testing.T) {
	p := &RawUDPProxy{serverID: "overflow-order-test"}
	shardCount := rawUDPLoginWorkerCount()
	p.loginJobChans = make([]chan *rawUDPLoginJob, shardCount)
	for i := range p.loginJobChans {
		p.loginJobChans[i] = make(chan *rawUDPLoginJob, rawUDPLoginJobQueueSize)
	}

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54000}
	idx := rawUDPLoginShardIndex(clientAddr, shardCount)
	pc := newCountingPacketConn()
	client := newRawUDPTestClient(p, clientAddr, pc)

	// Fill the shard to capacity with nobody draining it (no worker
	// started), so every job's clientInfo/packet is "packet #0..31 queued
	// but not yet processed" — mirroring a shard genuinely jammed by slow
	// work for this or another client on the same shard.
	for i := 0; i < rawUDPLoginJobQueueSize; i++ {
		packet := rawUDPClonePacket([]byte{0x80, 0x00, byte(i), 0x00, 0xfe, byte(i)})
		p.loginJobChans[idx] <- &rawUDPLoginJob{clientInfo: client, packet: packet, clientAddr: clientAddr}
	}

	// One more dispatch call: the shard is full, so this must fall back to
	// synchronous processing and land upstream immediately...
	overflow := rawUDPClonePacket([]byte{0x80, 0x00, 0xff, 0x00, 0xfe, 0xff})
	p.dispatchLoginPhasePacket(client, overflow, clientAddr)

	select {
	case got := <-client.upstreamWriteCh:
		if len(got) == 0 || got[len(got)-1] != 0xff {
			t.Fatalf("expected the overflow packet (marker=0xff) to be forwarded first via synchronous fallback, got %v", got)
		}
		putRawUDPBuffer(got)
	case <-time.After(time.Second):
		t.Fatal("overflow packet was not processed synchronously when its shard was full")
	}

	// ...strictly before any of the 32 packets still sitting in the shard
	// channel, which haven't been touched at all (no worker is draining
	// them in this test).
	select {
	case <-client.upstreamWriteCh:
		t.Fatal("no queued packet should have been processed yet — nothing is draining the shard in this test")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestRawUDPProxy_SlowLoginACLCheckDoesNotBlockOtherClients is the core
// regression test for this change: it proves that a real ACL database call
// stuck for one connecting player (client B) does not stall Login/ACL
// processing for a different player (client A) already going through the
// same server's login phase concurrently. Before the shard worker pool,
// both would have shared the single hot-loop goroutine and A would have had
// to wait for B's ACL check to finish.
func TestRawUDPProxy_SlowLoginACLCheckDoesNotBlockOtherClients(t *testing.T) {
	slowACL := &slowACLManager{
		targetPlayer: "SlowPlayer",
		checkStarted: make(chan struct{}, 1),
		release:      make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseSlowACL := func() { releaseOnce.Do(func() { close(slowACL.release) }) }

	mgr := &countingRawUDPOutboundManager{}
	cfg := &config.ServerConfig{
		ID:            "login-worker-parallel-test",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:0",
		ProxyMode:     "raw_udp",
		ProxyOutbound: "node-a",
		IdleTimeout:   300,
	}
	p := NewRawUDPProxy(cfg.ID, cfg, nil, session.NewSessionManager(time.Hour))
	p.SetOutboundManager(mgr)
	p.aclManager = slowACL
	if err := p.Start(); err != nil {
		t.Fatalf("start raw udp proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Listen(ctx) }()

	cleanup := func() {
		cancel()
		releaseSlowACL()
		_ = p.Stop()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Fatal("Listen did not exit during cleanup")
		}
	}
	defer cleanup()

	listenerAddr := p.listener.LocalAddr().(*net.UDPAddr)
	shardCount := rawUDPLoginWorkerCount()

	// Client B will send the stalling Login packet. Dial it first so we can
	// then pick a client A address guaranteed to land on a *different*
	// shard — proving cross-client parallelism deterministically instead of
	// hoping for a lucky hash spread.
	clientB, err := net.DialUDP("udp", nil, listenerAddr)
	if err != nil {
		t.Fatalf("dial proxy listener (B): %v", err)
	}
	defer clientB.Close()
	shardB := rawUDPLoginShardIndex(clientB.LocalAddr().(*net.UDPAddr), shardCount)

	var clientA *net.UDPConn
	for attempt := 0; attempt < 200; attempt++ {
		candidate, dialErr := net.DialUDP("udp", nil, listenerAddr)
		if dialErr != nil {
			t.Fatalf("dial candidate A: %v", dialErr)
		}
		if rawUDPLoginShardIndex(candidate.LocalAddr().(*net.UDPAddr), shardCount) != shardB {
			clientA = candidate
			break
		}
		candidate.Close()
	}
	if clientA == nil {
		t.Fatal("could not find a client A address landing on a different login shard than client B")
	}
	defer clientA.Close()
	clientAKey := clientA.LocalAddr().String()
	clientBKey := clientB.LocalAddr().String()

	// Client B sends a real, parseable Login packet for "SlowPlayer" — its
	// ACL check will block on slowACL.release.
	chainJWT := buildChainJWT(t, slowACL.targetPlayer, testPlayerUUID, testPlayerXUID)
	chainData := buildStandardChainJSON(t, []string{chainJWT})
	connReq := buildConnectionRequestBytes(chainData, []byte(buildClientDataJWT(t, "ignored")))
	batch := buildLoginBatch(connReq)
	loginGamePacket := wrapGamePacket(t, 0xff, batch)
	loginFrame := wrapRakNetReliablePayloadForRawUDPTest(loginGamePacket)

	if _, err := clientB.Write(loginFrame); err != nil {
		t.Fatalf("client B send login: %v", err)
	}

	select {
	case <-slowACL.checkStarted:
	case <-time.After(time.Second):
		t.Fatal("client B's ACL check never started")
	}

	// Client A connects while B is already active, so its dial itself goes
	// through the existing async-dial path (unrelated to this change — see
	// TestRawUDPProxy_NewClientSlowDialDoesNotBlockExistingClients). Since
	// our outbound mock isn't slowed down for A, that finishes almost
	// immediately; wait for it so the next packet exercises the normal
	// fast path instead of the pending-buffer path.
	if _, err := clientA.Write([]byte{0x80, 0x00, 0x00, 0x00, 0xfe}); err != nil {
		t.Fatalf("client A send: %v", err)
	}
	waitUntil(t, time.Second, func() bool {
		val, ok := p.clients.Load(clientAKey)
		ci, isCI := val.(*rawUDPClientInfo)
		return ok && isCI && !ci.pending.Load() && ci.targetConn != nil
	}, "client A never finished connecting (async dial) while client B's ACL check was stuck")

	// Now that A is fully connected, its *next* packet goes through the
	// normal per-packet path (hot loop -> dispatchLoginPhasePacket -> A's
	// own shard worker). It must be accepted by the hot loop and fully
	// processed (forwarded upstream) promptly, proving A's shard worker
	// runs independently of B's shard worker, which is still stuck in its
	// ACL check.
	start := time.Now()
	if _, err := clientA.Write([]byte{0x80, 0x00, 0x00, 0x01, 0xfe}); err != nil {
		t.Fatalf("client A second send: %v", err)
	}
	waitUntil(t, time.Second, func() bool {
		val, ok := p.clients.Load(clientAKey)
		ci, isCI := val.(*rawUDPClientInfo)
		// packetsUp only counts packets that went through the hot loop's
		// normal per-packet stats code (line ~1369); A's first packet took
		// the async-dial buffered path instead (see getOrCreateClient),
		// so this is the first packet expected to bump it.
		return ok && isCI && ci.packetsUp.Load() >= 1
	}, "client A's second packet never reached the hot loop while client B's ACL check was stuck")
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("client A's second packet reached the hot loop too slowly (%v) while client B's ACL check was stuck", elapsed)
	}

	waitUntil(t, time.Second, func() bool {
		val, ok := p.clients.Load(clientAKey)
		ci, isCI := val.(*rawUDPClientInfo)
		if !ok || !isCI {
			return false
		}
		conn, isConn := ci.targetConn.(*countingPacketConn)
		if !isConn {
			return false
		}
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.writes >= 2 // 1 buffered pre-dial packet + the dispatched one above
	}, "client A's packets were never forwarded upstream while client B's ACL check was stuck")

	// Sanity check: the stall was real, not a no-op — client B has not
	// completed its login yet at this point (still parked on release).
	valB, ok := p.clients.Load(clientBKey)
	if !ok {
		t.Fatal("client B disappeared from the client table")
	}
	ciB := valB.(*rawUDPClientInfo)
	connB, isConn := ciB.targetConn.(*countingPacketConn)
	if !isConn {
		t.Fatalf("client B targetConn has unexpected type %T", ciB.targetConn)
	}
	connB.mu.Lock()
	writesBeforeRelease := connB.writes
	connB.mu.Unlock()
	if writesBeforeRelease != 0 {
		t.Fatalf("client B's login packet was forwarded before its ACL check was released (writes=%d) — the stall was not real", writesBeforeRelease)
	}

	// Release the stuck ACL check; client B's login must complete afterward.
	releaseSlowACL()
	waitUntil(t, 2*time.Second, func() bool {
		connB.mu.Lock()
		defer connB.mu.Unlock()
		return connB.writes >= 1
	}, "client B's login packet was never forwarded upstream after releasing the stuck ACL check")
}
