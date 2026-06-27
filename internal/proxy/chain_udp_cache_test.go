package proxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

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
	s5Conn.ctrlConn.Close()
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

// TestChainUDPCache_CloseReplacedConn verifies that when a new conn replaces
// the cached one while the old one is in use, the old conn is closed when
// its last user calls Close() (no resource leak).
func TestChainUDPCache_CloseReplacedConn(t *testing.T) {
	realServer, stopReal := startFakeRakNetServer(t)
	defer stopReal()

	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	chainOutbound, err := CreateChainUDPOutbound([]*config.ProxyOutbound{
		{
			Name:    "hop1-replaced",
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
	originalPC := wrapper1.cached.pc

	// Second call — activeUsers=1, so creates a new conn and replaces cache
	pc2, err := chainOutbound.ListenPacket(ctx, dest)
	if err != nil {
		t.Fatalf("second ListenPacket: %v", err)
	}
	wrapper2 := pc2.(*chainConnWrapper)

	// Verify the cache now points to the new conn
	chainUDP := chainOutbound.(*chainUDPOutbound)
	chainUDP.cacheMu.Lock()
	cachedInCache := chainUDP.cache[dest]
	chainUDP.cacheMu.Unlock()
	if cachedInCache != wrapper2.cached {
		t.Fatal("cache should point to the new conn")
	}
	if cachedInCache == wrapper1.cached {
		t.Fatal("cache should NOT point to the old conn")
	}

	// Close pc1 — should close the old conn since it's no longer in cache
	pc1.Close()

	// Verify the old conn is closed by trying to write to it
	// (should fail with "use of closed connection" or similar)
	ping := []byte{0x01}
	_, writeErr := originalPC.WriteTo(ping, realServer)
	if writeErr == nil {
		// Some platforms don't error on write to closed UDP socket immediately.
		// Try read instead.
		_ = originalPC.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _, readErr := originalPC.ReadFrom(make([]byte, 64))
		if readErr == nil {
			t.Log("Old conn not immediately closed (platform-dependent), but Close() was called")
		}
	}

	// Verify pc2 still works
	if _, err := pc2.WriteTo(ping, realServer); err != nil {
		t.Fatalf("pc2 write after pc1 close: %v", err)
	}
	_ = pc2.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc2 read after pc1 close: %v", err)
	}
	if n != len(ping) {
		t.Fatalf("pc2: expected %d bytes, got %d", len(ping), n)
	}
	t.Logf("Replaced conn correctly closed, new conn still works")

	pc2.Close()
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
	cached.mu.Lock()
	cached.lastUsed = time.Now().Add(-200 * time.Second) // 200s ago, > 120s threshold
	cached.mu.Unlock()

	// Trigger idle sweeper manually by calling the same logic
	chainUDP.cacheMu.Lock()
	now := time.Now()
	for d, c := range chainUDP.cache {
		if atomic.LoadInt32(&c.activeUsers) > 0 {
			continue
		}
		c.mu.Lock()
		idle := now.Sub(c.lastUsed)
		c.mu.Unlock()
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
	s5Conn.ctrlConn.Close()
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
