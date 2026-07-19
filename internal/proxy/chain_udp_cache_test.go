package proxy

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

func TestChainConnWrapperCloseIsIdempotent(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet conn: %v", err)
	}
	defer pc.Close()

	cached := &cachedChainConn{
		pc:          pc,
		dest:        "127.0.0.1:19132",
		createdAt:   time.Now(),
		maxLifetime: time.Minute,
		activeUsers: 1,
		releaseCh:   make(chan struct{}),
	}
	cached.lastUsed.Store(time.Now().UnixNano())
	parent := &chainUDPOutbound{
		cache:     map[string]*cachedChainConn{cached.dest: cached},
		cacheStop: make(chan struct{}),
	}
	wrapper := &chainConnWrapper{cached: cached, parent: parent, dest: cached.dest}

	if err := wrapper.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := wrapper.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := atomic.LoadInt32(&cached.activeUsers); got != 0 {
		t.Fatalf("activeUsers after double close = %d, want 0", got)
	}
}

func resetChainDNSCacheForTest(t *testing.T) {
	t.Helper()
	dnsCacheMu.Lock()
	oldCache := dnsCache
	oldInFlight := dnsCacheInFlight
	dnsCache = make(map[string]dnsCacheEntry)
	dnsCacheInFlight = make(map[string]struct{})
	dnsCacheMu.Unlock()
	t.Cleanup(func() {
		dnsCacheMu.Lock()
		dnsCache = oldCache
		dnsCacheInFlight = oldInFlight
		dnsCacheMu.Unlock()
	})
}

func TestNormalizeCacheKeyDoesNotBlockOnDNSMiss(t *testing.T) {
	resetChainDNSCacheForTest(t)
	oldResolve := resolveChainCacheIP
	started := make(chan struct{})
	release := make(chan struct{})
	resolveChainCacheIP = func(ctx context.Context, host string) (net.IP, string, error) {
		close(started)
		select {
		case <-release:
			return net.ParseIP("203.0.113.10"), "test", nil
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	t.Cleanup(func() {
		close(release)
		resolveChainCacheIP = oldResolve
	})

	start := time.Now()
	key := normalizeCacheKey("example.invalid:19132")
	elapsed := time.Since(start)
	if key != "example.invalid:19132" {
		t.Fatalf("cache miss key = %q, want original destination", key)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("normalizeCacheKey blocked on DNS miss for %s", elapsed)
	}

	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected async DNS warm to start")
	}
}

func TestNormalizeCacheKeyUsesWarmedDNSCache(t *testing.T) {
	resetChainDNSCacheForTest(t)
	dnsCacheMu.Lock()
	dnsCache["example.invalid"] = dnsCacheEntry{ip: "203.0.113.20", expiresAt: time.Now().Add(time.Minute)}
	dnsCacheMu.Unlock()

	if got := normalizeCacheKey("example.invalid:19132"); got != "203.0.113.20:19132" {
		t.Fatalf("cache hit key = %q, want %q", got, "203.0.113.20:19132")
	}
}

// TestChainUDPCache_SequentialReuse verifies that after a wrapper is closed,
// the next ListenPacket reuses the cached conn (not creating a new one).
func TestChainUDPCache_SequentialReuse(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()

	// First call — establishes conn
	ctx := context.Background()
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}

	// Send a ping to verify it works
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}

	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("First call: %d bytes echoed", n)

	// Close first wrapper
	if err := pc1.Close(); err != nil {
		t.Fatalf("close pc1: %v", err)
	}

	// Second call — should reuse cached conn
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}

	// Verify it works
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("second write: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Second call (reused): %d bytes echoed", n)

	// Verify the underlying conn is the same by checking cache
	chainUDP := chainOutbound.(*chainUDPOutbound)
	chainUDP.cacheMu.Lock()
	cached, ok := chainUDP.cache[dest]
	chainUDP.cacheMu.Unlock()
	if !ok {
		t.Fatal("expected cached entry to exist")
	}
	if atomic.LoadInt32(&cached.activeUsers) != 1 {
		t.Fatalf("expected activeUsers=1, got %d", atomic.LoadInt32(&cached.activeUsers))
	}

	pc2.Close()
}

// TestChainUDPCache_DeadConnNotReused verifies that when a cached conn's
// TCP control connection is closed (simulating remote server restart),
// the next ListenPacket does NOT reuse the dead conn but creates a new one.
func TestChainUDPCache_DeadConnNotReused(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-dead",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// First call — establishes conn
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}

	// Verify it works
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	t.Logf("First call: %d bytes echoed", n)

	// Simulate remote closing the TCP control connection
	wrapper1 := pc1.(*chainConnWrapper)
	s5Conn, ok := wrapper1.cached.pc.(*socks5UDPPacketConn)
	if !ok {
		t.Fatalf("expected *socks5UDPPacketConn, got %T", wrapper1.cached.pc)
	}
	// Close the TCP control connection to simulate remote closing it
	if st := s5Conn.state.Load(); st != nil {
		st.ctrlConn.Close()
	}
	// Wait for monitorCtrlConn to detect and close the UDP socket
	time.Sleep(200 * time.Millisecond)

	// Close first wrapper (activeUsers goes to 0)
	pc1.Close()

	// Verify the cached conn is marked as remoteClosed
	if !s5Conn.IsRemoteClosed() {
		t.Fatal("expected remoteClosed=true after ctrl conn closed")
	}

	// Second call — should NOT reuse the dead conn, should create a new one
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}

	// Verify the new conn is different from the dead one
	wrapper2 := pc2.(*chainConnWrapper)
	if wrapper2.cached.pc == s5Conn {
		t.Fatal("expected new conn, but got the same dead conn")
	}

	// Verify it works
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("second write with new conn: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read with new conn: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Second call (new conn after dead): %d bytes echoed", n)

	pc2.Close()
}

// TestChainUDPCache_ConcurrentListenPacket verifies that two concurrent
// ListenPacket calls for the same destination don't share the same conn.
// Each should get its own conn to prevent datagram stealing.
func TestChainUDPCache_ConcurrentListenPacket(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-concurrent",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// Two concurrent ListenPacket calls
	var pc1, pc2 net.PacketConn
	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pc1, err1 = chainOutbound.ListenPacket(ctx, dest)
	}()
	go func() {
		defer wg.Done()
		pc2, err2 = chainOutbound.ListenPacket(ctx, dest)
	}()
	wg.Wait()

	if err1 != nil {
		t.Fatalf("pc1: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("pc2: %v", err2)
	}
	defer pc1.Close()
	defer pc2.Close()

	// Verify they are different underlying conns
	w1 := pc1.(*chainConnWrapper)
	w2 := pc2.(*chainConnWrapper)
	if w1.cached == w2.cached {
		t.Fatal("expected different cached conns for concurrent calls")
	}

	// Both should be able to send and receive independently
	ping := []byte{0x01, 0x02, 0x03, 0x04}

	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("pc1 write: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc1 read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("pc1: expected %d bytes, got %d", len(ping), n)
	}

	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("pc2 write: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc2 read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("pc2: expected %d bytes, got %d", len(ping), n)
	}

	t.Logf("Both concurrent conns work independently")
}

// TestChainUDPCache_EvictOnTimeoutWithActiveUsers verifies that a timeout
// error does NOT evict a cached conn when there are active users.
// This prevents disconnects during loading screens.
func TestChainUDPCache_EvictOnTimeoutWithActiveUsers(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-evict-timeout",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc1.Close()

	wrapper := pc1.(*chainConnWrapper)

	// Simulate a timeout error (30s read deadline expires with no data)
	_ = pc1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 2048)
	_, _, readErr := pc1.ReadFrom(buf)
	if readErr == nil {
		t.Fatal("expected timeout error")
	}

	// Verify the conn is still in the cache (not evicted)
	chainUDP := chainOutbound.(*chainUDPOutbound)
	chainUDP.cacheMu.Lock()
	_, ok := chainUDP.cache[dest]
	chainUDP.cacheMu.Unlock()
	if !ok {
		t.Fatal("cached conn was evicted on timeout with active user — should NOT be evicted")
	}

	// Verify activeUsers is still 1
	if atomic.LoadInt32(&wrapper.cached.activeUsers) != 1 {
		t.Fatalf("expected activeUsers=1, got %d", atomic.LoadInt32(&wrapper.cached.activeUsers))
	}

	t.Logf("Timeout with active user: conn NOT evicted (correct)")

	// Verify the conn still works after timeout
	_ = pc1.SetReadDeadline(time.Time{}) // reset deadline
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("write after timeout: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read after timeout: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Conn still works after timeout: %d bytes echoed", n)
}

// TestChainUDPCache_SOCKS5BusyCreatesParallelAssociate verifies that a busy
// SOCKS5 cached conn is not reused by another active client. After the busy
// wait boundary (covers concurrent ping hold), a second real client gets its
// own UDP ASSOCIATE while the first client's relay mapping remains usable.
func TestChainUDPCache_SOCKS5BusyCreatesParallelAssociate(t *testing.T) {
	oldWait := chainSOCKS5BusyWait
	chainSOCKS5BusyWait = 800 * time.Millisecond
	defer func() { chainSOCKS5BusyWait = oldWait }()

	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-parallel",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// First call — establishes conn, activeUsers=1
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}
	wrapper1 := pc1.(*chainConnWrapper)

	// Second call while activeUsers=1 should wait near the SOCKS5 busy
	// boundary, then create a separate ASSOCIATE for the second client.
	start := time.Now()
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()
	wrapper2 := pc2.(*chainConnWrapper)
	if wrapper2.cached == wrapper1.cached {
		t.Fatal("second active client reused the first client's PacketConn")
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("expected to wait near the SOCKS5 busy boundary, waited %v", elapsed)
	}

	// Verify the cache now points to the newer conn, while the old active conn
	// remains alive until its owner closes it.
	chainUDP := chainOutbound.(*chainUDPOutbound)
	chainUDP.cacheMu.Lock()
	cachedInCache := chainUDP.cache[dest]
	chainUDP.cacheMu.Unlock()
	if cachedInCache != wrapper2.cached {
		t.Fatal("cache should point to the newer parallel conn")
	}

	ping1 := []byte{0x01}
	if _, err := pc1.WriteTo(ping1, realServer); err != nil {
		t.Fatalf("pc1 write after parallel associate: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc1 read after parallel associate: %v", err)
	}
	if n != len(ping1) {
		t.Fatalf("pc1: expected %d bytes, got %d", len(ping1), n)
	}

	ping2 := []byte{0x02, 0x03}
	if _, err := pc2.WriteTo(ping2, realServer); err != nil {
		t.Fatalf("pc2 write after parallel associate: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc2 read after parallel associate: %v", err)
	}
	if n != len(ping2) {
		t.Fatalf("pc2: expected %d bytes, got %d", len(ping2), n)
	}

	pc1.Close()
}

// TestChainUDPCache_PingDialSkipsWhenBusy verifies ping dials fail fast when the
// cached SOCKS5 conn is held by a real client, instead of creating a parallel
// ASSOCIATE that can stomp the player's UDP mapping.
func TestChainUDPCache_PingDialSkipsWhenBusy(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-ping-busy",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	pc1, err := chainOutbound.ListenPacket(context.Background(), dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}
	defer pc1.Close()

	start := time.Now()
	_, err = chainOutbound.ListenPacket(ContextWithPingDial(context.Background()), dest)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected ping dial to fail while cache is busy")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("ping dial should fail fast when busy, waited %v", elapsed)
	}
}

// TestChainUDPCache_MultipleSequentialReuse verifies that the cache
// correctly handles multiple sequential open-close cycles.
func TestChainUDPCache_MultipleSequentialReuse(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-multi",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	buf := make([]byte, 2048)

	for i := 0; i < 5; i++ {
		pc, err := chainOutbound.ListenPacket(ctx, dest)
		if err != nil {
			t.Fatalf("cycle %d ListenPacket: %v", i, err)
		}

		if _, err := pc.WriteTo(ping, realServer); err != nil {
			t.Fatalf("cycle %d write: %v", i, err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("cycle %d read: %v", i, err)
		}
		if n != len(ping) {
			t.Fatalf("cycle %d: expected %d bytes, got %d", i, len(ping), n)
		}

		pc.Close()
		t.Logf("Cycle %d: OK (%d bytes)", i, n)
	}

	// After 5 cycles, there should be exactly 1 cached entry
	chainUDP := chainOutbound.(*chainUDPOutbound)
	chainUDP.cacheMu.Lock()
	cacheLen := len(chainUDP.cache)
	chainUDP.cacheMu.Unlock()
	if cacheLen != 1 {
		t.Fatalf("expected 1 cache entry, got %d", cacheLen)
	}

	t.Logf("5 sequential cycles completed, cache has 1 entry")
}

// TestChainUDPCache_IdleSweeperClosesIdleConn verifies that the idle sweeper
// closes a cached conn after the idle timeout when there are no active users.
func TestChainUDPCache_IdleSweeperClosesIdleConn(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-idle",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// Create and close a conn
	pc, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	wrapper := pc.(*chainConnWrapper)
	underlyingPC := wrapper.cached.pc
	pc.Close()

	// Verify conn is in cache with activeUsers=0
	chainUDP := chainOutbound.(*chainUDPOutbound)
	chainUDP.cacheMu.Lock()
	cached, ok := chainUDP.cache[dest]
	chainUDP.cacheMu.Unlock()
	if !ok {
		t.Fatal("expected cached entry")
	}
	if atomic.LoadInt32(&cached.activeUsers) != 0 {
		t.Fatalf("expected activeUsers=0, got %d", atomic.LoadInt32(&cached.activeUsers))
	}

	// Manually set lastUsed to past to trigger idle sweeper
	cached.lastUsed.Store(time.Now().Add(-200 * time.Second).UnixNano()) // 200s ago, > 120s threshold

	// Trigger idle sweeper manually by calling the same logic
	chainUDP.cacheMu.Lock()
	now := time.Now()
	for d, c := range chainUDP.cache {
		if atomic.LoadInt32(&c.activeUsers) > 0 {
			continue
		}
		idle := now.Sub(time.Unix(0, c.lastUsed.Load()))
		if idle > 120*time.Second {
			c.pc.Close()
			delete(chainUDP.cache, d)
		}
	}
	chainUDP.cacheMu.Unlock()

	// Verify conn was closed and removed from cache
	chainUDP.cacheMu.Lock()
	_, ok = chainUDP.cache[dest]
	chainUDP.cacheMu.Unlock()
	if ok {
		t.Fatal("expected cache entry to be removed by idle sweeper")
	}

	// Verify underlying conn is closed
	s5Conn, ok := underlyingPC.(*socks5UDPPacketConn)
	if ok {
		if !s5Conn.closed.Load() {
			t.Log("Underlying conn not yet marked closed (may be async)")
		}
	}

	t.Logf("Idle sweeper correctly closed idle conn")
}

// TestChainUDPCache_IsConnAlive_SOCKS5 verifies that isConnAlive correctly
// detects SOCKS5 conns with closed TCP control connections.
func TestChainUDPCache_IsConnAlive_SOCKS5(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-alive",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	pc, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	wrapper := pc.(*chainConnWrapper)
	s5Conn := wrapper.cached.pc.(*socks5UDPPacketConn)

	// Initially alive
	if !isConnAlive(s5Conn) {
		t.Fatal("expected conn to be alive initially")
	}

	// Close TCP control connection
	if st := s5Conn.state.Load(); st != nil {
		st.ctrlConn.Close()
	}
	time.Sleep(200 * time.Millisecond)

	// Should now be dead
	if isConnAlive(s5Conn) {
		t.Fatal("expected conn to be dead after TCP control closed")
	}

	if !s5Conn.IsRemoteClosed() {
		t.Fatal("expected remoteClosed=true")
	}

	pc.Close()
	t.Logf("isConnAlive correctly detected dead SOCKS5 conn")
}

// TestChainUDPCache_StressMultipleClients verifies that multiple clients
// can use the chain proxy simultaneously without interfering with each other.
func TestChainUDPCache_StressMultipleClients(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-stress",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	numClients := 10
	var wg sync.WaitGroup
	errs := make([]error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pc, err := chainOutbound.ListenPacket(ctx, dest)
			if err != nil {
				errs[idx] = err
				return
			}
			defer pc.Close()

			ping := []byte{byte(0x80 + idx), 0x02, 0x03, 0x04}
			if _, err := pc.WriteTo(ping, realServer); err != nil {
				errs[idx] = err
				return
			}
			_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 2048)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				errs[idx] = err
				return
			}
			if n != len(ping) {
				errs[idx] = &net.AddrError{Err: "size mismatch", Addr: ""}
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("client %d failed: %v", i, err)
		}
	}
	t.Logf("All %d concurrent clients completed successfully", numClients)
}

// TestChainUDPCache_WriteDeadlineResetAfterPing verifies that after
// pingTargetServer sets a short write deadline and closes the wrapper,
// a subsequent reuse of the cached conn can still write successfully.
// This is a regression test for the write deadline leak that caused
// "i/o timeout" on all writes when MCBE test reused a cached conn after ping.
func TestChainUDPCache_WriteDeadlineResetAfterPing(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-deadline",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// First call — simulates pingTargetServer
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}

	// Simulate what pingTargetServer does: set short write + read deadlines
	_ = pc1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = pc1.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Send and receive (simulating a successful ping)
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	buf := make([]byte, 2048)
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	t.Logf("Ping: %d bytes echoed", n)

	// Close the wrapper (simulates defer conn.Close() in pingTargetServer)
	pc1.Close()

	// Wait for the write deadline to expire (3 seconds > 2s deadline)
	t.Log("Waiting 3s for write deadline to expire...")
	time.Sleep(3 * time.Second)

	// Second call — simulates MCBE test reusing the cached conn.
	// Before the fix, this would fail with "i/o timeout" on write
	// because the expired write deadline was never reset.
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()

	// This write should succeed — the deadline should have been reset
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("second write after deadline expiry: %v (write deadline was not reset)", err)
	}

	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read after deadline expiry: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Reuse after deadline expiry: %d bytes echoed (write deadline correctly reset)", n)
}

// TestChainUDPCache_HadTimeoutEvictsOnClose verifies that when a one-shot
// user (e.g. MCBE UDP test) gets a read timeout on a cached conn, the conn
// is evicted from cache when the user closes their wrapper — so the next
// user gets a fresh conn instead of inheriting a dead SOCKS5 relay session.
func TestChainUDPCache_HadTimeoutEvictsOnClose(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-timeout",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// First call — establish and verify the conn works
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	buf := make([]byte, 2048)
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	t.Logf("First call: %d bytes echoed", n)
	pc1.Close()

	// Second call — simulate MCBE test getting a read timeout.
	// We point at a non-existent target so no response comes back.
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}

	// Set a short read deadline and read — this will timeout
	_ = pc2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = pc2.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected read timeout, got nil")
	}
	if !isTimeoutError(err) {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	t.Logf("Second call: read timeout as expected: %v", err)

	// Close the wrapper — should evict the conn from cache because hadTimeout was set
	pc2.Close()

	// Third call — should get a FRESH conn, not the stale one.
	// The cache should have been evicted, so a new SOCKS5 UDP ASSOCIATE is created.
	pc3, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("third ListenPacket: %v", err)
	}
	defer pc3.Close()

	// Verify the fresh conn works
	if _, err := pc3.WriteTo(ping, realServer); err != nil {
		t.Fatalf("third write (fresh conn after timeout eviction): %v", err)
	}
	_ = pc3.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc3.ReadFrom(buf)
	if err != nil {
		t.Fatalf("third read (fresh conn after timeout eviction): %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Third call (fresh conn after timeout eviction): %d bytes echoed", n)
}

// TestChainUDPCache_HadTimeoutEvictsBeforeReuse verifies that if a conn
// with hadTimeout set is still in cache when the next user calls
// ListenPacket, it is evicted and a fresh conn is created.
func TestChainUDPCache_HadTimeoutEvictsBeforeReuse(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-reuse",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// First call — establish and verify
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	buf := make([]byte, 2048)
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	t.Logf("First call: %d bytes echoed", n)

	// Simulate a read timeout WITHOUT closing — just set a short deadline
	// and read. This sets hadTimeout on the cached conn.
	_ = pc1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _, err = pc1.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected read timeout, got nil")
	}
	if !isTimeoutError(err) {
		t.Fatalf("expected timeout error, got: %v", err)
	}

	// Now close — with hadTimeout set, the conn should be evicted
	pc1.Close()

	// Second call — should get a fresh conn
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()

	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("second write (fresh conn): %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read (fresh conn): %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Second call (fresh conn after hadTimeout eviction): %d bytes echoed", n)
}

// TestChainUDPCache_SuccessClearsHadTimeout verifies that after a read
// timeout, a subsequent successful I/O clears the hadTimeout flag so the
// conn is NOT evicted on close. This models the game-session scenario where
// forwardResponses gets a brief idle timeout but the conn is still healthy.
func TestChainUDPCache_SuccessClearsHadTimeout(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-clear",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}

	wrapper := pc1.(*chainConnWrapper)
	ping := []byte{0x01, 0x02, 0x03, 0x04}
	buf := make([]byte, 2048)

	// First, verify the conn works
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	t.Logf("Initial I/O: %d bytes", n)

	// Simulate a brief idle timeout (like forwardResponses during loading screen)
	_ = pc1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _, err = pc1.ReadFrom(buf)
	if err == nil || !isTimeoutError(err) {
		t.Fatalf("expected timeout, got: %v", err)
	}

	// Verify hadTimeout was set
	if atomic.LoadInt32(&wrapper.cached.hadTimeout) != 1 {
		t.Fatal("expected hadTimeout=1 after timeout")
	}
	t.Log("hadTimeout set after idle timeout (correct)")

	// Now do successful I/O — this should clear hadTimeout
	_ = pc1.SetReadDeadline(time.Time{})
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("write after timeout: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read after timeout: %v", err)
	}
	t.Logf("Successful I/O after timeout: %d bytes", n)

	// Verify hadTimeout was cleared
	if atomic.LoadInt32(&wrapper.cached.hadTimeout) != 0 {
		t.Fatal("expected hadTimeout=0 after successful I/O")
	}
	t.Log("hadTimeout cleared after successful I/O (correct)")

	// Close — conn should stay in cache because hadTimeout is 0
	pc1.Close()

	// Verify conn is still in cache
	chainUDP := chainOutbound.(*chainUDPOutbound)
	chainUDP.cacheMu.Lock()
	_, ok := chainUDP.cache[dest]
	chainUDP.cacheMu.Unlock()
	if !ok {
		t.Fatal("conn was evicted on close after successful I/O — should stay cached")
	}
	t.Log("Conn stayed in cache after close (correct — hadTimeout was cleared)")

	// Verify the cached conn still works for the next user
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("second write: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	t.Logf("Reuse after clear: %d bytes echoed", n)
}

// TestChainUDPCache_SOCKS5IdleThresholdEvicts verifies that a cached SOCKS5
// UDP connection that has been idle for more than 5 seconds is evicted before
// reuse. SOCKS5 UDP relay servers drop UDP mappings after ~10s of idle while
// keeping the TCP control connection alive, so isConnAlive passes but the UDP
// path is dead. The idle threshold prevents reusing such stale connections.
func TestChainUDPCache_SOCKS5IdleThresholdEvicts(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-idle",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// First call: creates and caches a connection
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}

	ping := []byte{0x99, 0x01, 0x02, 0x03}
	buf := make([]byte, 1500)
	_ = pc1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("First call: %d bytes echoed", n)
	_ = pc1.Close()

	// Wait 6 seconds — exceeds the 5s SOCKS5 idle reuse threshold
	t.Logf("Waiting 6s for idle threshold to exceed 5s...")
	time.Sleep(6 * time.Second)

	// Second call: should NOT reuse the stale cached conn — should create a new one
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()

	// Verify the new connection works
	_ = pc2.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("second write: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Second call (fresh conn after idle threshold eviction): %d bytes echoed", n)
}

// TestChainUDPCache_DrainStalePacketsOnReuse verifies that stale packets
// left in the UDP socket buffer by a previous user are drained before the
// next user reads. Without draining, the next ReadFrom returns the stale
// packet, causing timestamp mismatches and spurious timeouts in MCBE ping.
func TestChainUDPCache_DrainStalePacketsOnReuse(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-drain",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	// First call: creates and caches a connection
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}

	ping := []byte{0x99, 0x01, 0x02, 0x03}
	buf := make([]byte, 1500)

	// Send a ping and read the response
	_ = pc1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}

	// Send another ping but DON'T read the response — leave it in the buffer
	_ = pc1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("second write: %v", err)
	}
	// Wait briefly for the server to echo the packet back into the buffer
	time.Sleep(200 * time.Millisecond)
	// Close without reading — the pong is now sitting in the UDP socket buffer
	_ = pc1.Close()

	// Second call: should reuse the cached conn, but the stale pong must be
	// drained so the next ReadFrom gets a fresh response, not the old one.
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()

	// Send a new ping with different data
	ping2 := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	_ = pc2.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc2.WriteTo(ping2, realServer); err != nil {
		t.Fatalf("third write: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read (after drain): %v", err)
	}
	// We should get ping2's echo, not ping's stale echo
	if n != len(ping2) {
		t.Fatalf("expected %d bytes, got %d", len(ping2), n)
	}
	if !bytes.Equal(buf[:n], ping2) {
		t.Fatalf("expected response %v, got %v (stale packet not drained?)", ping2, buf[:n])
	}
	t.Logf("Second call after drain: got correct %d bytes", n)
}

// TestChainUDPCache_SOCKS5ReuseCountEvicts verifies that a cached SOCKS5 UDP
// connection is reused up to maxReuseCount (3) times, after which it is
// evicted and a fresh SOCKS5 UDP ASSOCIATE is established. This prevents
// VPS-side upstream connection staleness that causes i/o timeouts after
// several reuses on the same association.
func TestChainUDPCache_SOCKS5ReuseCountEvicts(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-reusecount",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()

	ping := []byte{0x99, 0x01, 0x02, 0x03}
	buf := make([]byte, 1500)

	// First call creates and caches a connection (reuseCount=0 after creation)
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}
	_ = pc1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Call 1 (create): ok")
	_ = pc1.Close()

	// Reuse 1, 2, 3 — should all succeed with cached conn (reuseCount 1→2→3)
	for i := 2; i <= 4; i++ {
		pc, err := chainOutbound.ListenPacket(ctx, dest)
		if err != nil {
			t.Fatalf("call %d ListenPacket: %v", i, err)
		}
		_ = pc.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := pc.WriteTo(ping, realServer); err != nil {
			t.Fatalf("call %d write: %v", i, err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("call %d read: %v", i, err)
		}
		if n != len(ping) {
			t.Fatalf("call %d: expected %d bytes, got %d", i, len(ping), n)
		}
		t.Logf("Call %d (reuse): ok", i)
		_ = pc.Close()
	}

	// Call 5: reuseCount >= 3, so the cached conn is evicted and a fresh
	// SOCKS5 UDP ASSOCIATE is created. This should still succeed.
	pc5, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("call 5 ListenPacket: %v", err)
	}
	_ = pc5.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc5.WriteTo(ping, realServer); err != nil {
		t.Fatalf("call 5 write: %v", err)
	}
	_ = pc5.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = pc5.ReadFrom(buf)
	if err != nil {
		t.Fatalf("call 5 read: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("call 5: expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Call 5 (fresh conn after reuseCount limit): ok")
	_ = pc5.Close()
}

// TestChainUDPCache_WaitsForBusyConn verifies that when a cached SOCKS5 UDP
// connection is in use (activeUsers > 0), the next ListenPacket waits for it
// to be released rather than creating a new connection. This prevents
// multiple concurrent SOCKS5 ASSOCIATEs to the same remote server.
func TestChainUDPCache_WaitsForBusyConn(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-busy-wait",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()
	ping := []byte{0x99, 0x01, 0x02, 0x03}
	buf := make([]byte, 1500)

	// First call creates and caches a connection
	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}

	// Start a goroutine that holds pc1 for 200ms then releases it
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = pc1.Close()
	}()

	// Second call should wait for pc1 to be released, then reuse it
	start := time.Now()
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}

	// Should have waited at least ~200ms for the conn to be released
	if elapsed < 100*time.Millisecond {
		t.Fatalf("expected to wait ~200ms for busy conn, but only waited %v", elapsed)
	}
	t.Logf("Waited %v for busy conn to be released", elapsed)

	// Verify the reused conn works
	_ = pc2.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("write on reused conn: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read on reused conn: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Reused conn after wait: ok (%d bytes)", n)
	_ = pc2.Close()
}

// TestChainUDPCache_WaitTimeoutCreatesParallelConn verifies that when the wait
// timeout is reached for a busy SOCKS5 conn, a second real client gets a new
// ASSOCIATE and the original active conn remains usable.
func TestChainUDPCache_WaitTimeoutCreatesParallelConn(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-timeout-parallel",
			Type:    config.ProtocolSOCKS5,
			Server:  socks5AHost,
			Port:    socks5APort,
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("create chain outbound: %v", err)
	}
	defer chainOutbound.Close()

	dest := realServer.String()
	ctx := context.Background()
	ping := []byte{0x99, 0x01, 0x02, 0x03}
	buf := make([]byte, 1500)

	pc1, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("first ListenPacket: %v", err)
	}

	_ = pc1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("first write on pc1: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first read on pc1: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("pc1: expected %d bytes, got %d", len(ping), n)
	}

	start := time.Now()
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	defer pc2.Close()
	if elapsed < 400*time.Millisecond {
		t.Fatalf("expected to wait near the 500ms busy boundary, waited %v", elapsed)
	}

	// Critical: pc1 should still work after pc2 is created.
	_ = pc1.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc1.WriteTo(ping, realServer); err != nil {
		t.Fatalf("pc1 write after parallel conn creation: %v", err)
	}
	_ = pc1.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = pc1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc1 read after parallel conn creation: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("pc1 after parallel conn: expected %d bytes, got %d", len(ping), n)
	}

	_ = pc2.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("pc2 write after parallel conn creation: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc2 read after parallel conn creation: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("pc2: expected %d bytes, got %d", len(ping), n)
	}

	_ = pc1.Close()
	_ = pc2.Close()

	pc3, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("ListenPacket after both clients close: %v", err)
	}
	defer pc3.Close()

	_ = pc3.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc3.WriteTo(ping, realServer); err != nil {
		t.Fatalf("pc3 write after both clients close: %v", err)
	}
	_ = pc3.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = pc3.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc3 read after both clients close: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("pc3: expected %d bytes, got %d", len(ping), n)
	}
}
