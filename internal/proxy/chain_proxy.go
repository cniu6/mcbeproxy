package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/singboxcore"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// chainNxDialer adapts a singboxcore.Dialer (SingboxDialer) to N.Dialer.
// This allows using a SingboxDialer as the underlying dialer for another
// SingboxDialer/SingboxOutbound, enabling proxy chaining.
type chainNxDialer struct {
	tcpDialer   singboxcore.Dialer   // wraps the previous proxy in the chain
	udpOutbound *SingboxOutbound     // previous hop's outbound for UDP relay tunneling
}

func (d *chainNxDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	addr := destination.String()
	conn, err := d.tcpDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("chain dialer: failed to dial %s: %w", addr, err)
	}
	return conn, nil
}

// ListenPacket is required by N.Dialer. For chain dialers, we delegate to
// the previous hop's SingboxOutbound to tunnel UDP datagrams through the chain.
// This is critical for SOCKS5 UDP ASSOCIATE: the relay address returned by the
// SOCKS5 server is only reachable through the chain, not directly.
func (d *chainNxDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d.udpOutbound != nil {
		return d.udpOutbound.ListenPacket(ctx, destination.String())
	}
	return nil, fmt.Errorf("chain dialer does not support ListenPacket; no UDP outbound available")
}

// Close is not part of N.Dialer but is needed for resource cleanup.
func (d *chainNxDialer) Close() error {
	return d.tcpDialer.Close()
}

// chainPrevHop holds both the dialer and outbound of a chain hop so that
// chainNxDialer can tunnel both TCP and UDP through the previous hop.
type chainPrevHop struct {
	dialer   *SingboxDialer
	outbound *SingboxOutbound
}

var _ N.Dialer = (*chainNxDialer)(nil)

// chainSingboxDialer creates a SingboxDialer for the given config, but with
// its underlying dialer replaced by prevDialer (the previous hop in the chain).
// This makes the new dialer connect to its proxy server *through* prevDialer.
func chainSingboxDialer(cfg *config.ProxyOutbound, prevDialer N.Dialer) (*SingboxDialer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("chain: outbound config is nil")
	}
	return &SingboxDialer{
		config: cfg,
		dialer: prevDialer,
	}, nil
}

// chainSingboxOutbound creates a SingboxOutbound for the given config, but with
// its underlying dialer replaced by prevDialer (the previous hop in the chain).
func chainSingboxOutbound(cfg *config.ProxyOutbound, prevDialer N.Dialer) (*SingboxOutbound, error) {
	if cfg == nil {
		return nil, fmt.Errorf("chain: outbound config is nil")
	}
	outbound := &SingboxOutbound{
		config: cfg,
		dialer: prevDialer,
	}

	var err error
	switch cfg.Type {
	case config.ProtocolShadowsocks:
		err = outbound.initShadowsocks(cfg)
	case config.ProtocolVMess:
		err = outbound.initVMess(cfg)
	case config.ProtocolTrojan:
		err = outbound.initTrojan(cfg)
	case config.ProtocolVLESS:
		err = outbound.initVLESS(cfg)
	case config.ProtocolHysteria2:
		err = outbound.initHysteria2(cfg)
	case config.ProtocolAnyTLS:
		err = outbound.initAnyTLS(cfg)
	case config.ProtocolSOCKS5:
		err = outbound.initSOCKS5(cfg)
	case config.ProtocolHTTP:
		err = outbound.initHTTP(cfg)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, cfg.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("chain: failed to init outbound %s (%s): %w", cfg.Name, cfg.Type, err)
	}
	return outbound, nil
}

// chainDialer implements singboxcore.Dialer for a chain of proxy outbounds.
// It dials through each proxy in order, then to the final destination.
type chainDialer struct {
	hops         []*config.ProxyOutbound // ordered list of proxy configs (chain[0]..chain[n-1], then the node itself)
	dialers      []*chainNxDialer        // underlying dialers for each hop (for cleanup)
	final        *SingboxDialer          // the last hop's SingboxDialer (used for DialContext)
	allOutbounds []*SingboxOutbound      // all hop outbounds for resource cleanup (anytls/hy2 goroutines)
	closed       bool
	mu           sync.Mutex
}

// CreateChainDialer creates a TCP dialer that routes through a chain of proxies.
// chainConfigs is ordered: chainConfigs[0] is the first hop, chainConfigs[len-1] is the last.
// The final dialer connects to the actual destination through all hops.
func CreateChainDialer(chainConfigs []*config.ProxyOutbound) (singboxcore.Dialer, error) {
	if len(chainConfigs) == 0 {
		return nil, fmt.Errorf("chain: at least one proxy config is required")
	}

	// Build the chain: each hop's dialer uses the previous hop's dialer as its underlying
	var prevDialer N.Dialer = &directDialer{timeout: 30 * time.Second}
	nxDialers := make([]*chainNxDialer, 0, len(chainConfigs))
	allOutbounds := make([]*SingboxOutbound, 0, len(chainConfigs))
	var finalSingboxDialer *SingboxDialer

	for i, cfg := range chainConfigs {
		if cfg == nil {
			return nil, fmt.Errorf("chain: hop %d config is nil", i)
		}

		sd, err := chainSingboxDialer(cfg, prevDialer)
		if err != nil {
			return nil, fmt.Errorf("chain: failed to create dialer for hop %d (%s): %w", i, cfg.Name, err)
		}

		// Create outbound for this hop (needed for UDP tunneling via ListenPacket)
		outbound, err := chainSingboxOutbound(cfg, prevDialer)
		if err != nil {
			return nil, fmt.Errorf("chain: failed to create outbound for hop %d (%s): %w", i, cfg.Name, err)
		}
		allOutbounds = append(allOutbounds, outbound)

		// Wrap the SingboxDialer as an N.Dialer for the next hop
		nxD := &chainNxDialer{tcpDialer: sd, udpOutbound: outbound}
		nxDialers = append(nxDialers, nxD)
		prevDialer = nxD

		if i == len(chainConfigs)-1 {
			finalSingboxDialer = sd
		}
	}

	if finalSingboxDialer == nil {
		return nil, fmt.Errorf("chain: failed to create final dialer")
	}

	return &chainDialer{
		hops:         chainConfigs,
		dialers:      nxDialers,
		final:        finalSingboxDialer,
		allOutbounds: allOutbounds,
	}, nil
}

func (d *chainDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	logger.Debug("ChainDialer: dialing %s via %d-hop chain", address, len(d.hops))
	conn, err := d.final.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("chain dial failed: %w", err)
	}
	logger.Debug("ChainDialer: connection established to %s via chain", address)
	return conn, nil
}

func (d *chainDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	var lastErr error
	for _, nxD := range d.dialers {
		if err := nxD.Close(); err != nil {
			lastErr = err
		}
	}
	// Close all hop outbounds to release anytls/hy2 background goroutines.
	// SingboxOutbound.Close() is safe to call multiple times (sets clients to nil).
	for _, ob := range d.allOutbounds {
		ob.Close()
	}
	return lastErr
}

var _ singboxcore.Dialer = (*chainDialer)(nil)

// chainUDPOutbound implements singboxcore.UDPOutbound for a chain of proxies.
// It establishes the UDP connection through the last hop, which itself dials
// through all previous hops.
//
// To avoid re-establishing the full chain (TCP handshake through every hop +
// SOCKS5/protocol handshake + UDP ASSOCIATE) on every ListenPacket call,
// completed PacketConns are cached by destination and reused. A background
// goroutine closes idle entries after 2 minutes.
type chainUDPOutbound struct {
	hops         []*config.ProxyOutbound
	outbound     *SingboxOutbound   // the last hop's outbound (with chained dialer)
	allOutbounds []*SingboxOutbound // all hop outbounds for resource cleanup (anytls/hy2 goroutines)
	closed       bool
	mu           sync.Mutex

	// UDP connection cache
	cacheMu    sync.Mutex
	cache      map[string]*cachedChainConn // destination -> cached conn
	cacheStop  chan struct{}
	cacheOnce  sync.Once
}

// cachedChainConn wraps a PacketConn for reuse. Close() does NOT close the
// underlying connection — it just marks lastUsed so the idle sweeper can
// clean it up later.
type cachedChainConn struct {
	pc          net.PacketConn
	dest        string
	lastUsed    atomic.Int64 // unix nano — updated lock-free in hot path
	createdAt   time.Time // for max lifetime enforcement
	maxLifetime time.Duration // with jitter applied per-conn
	mu          sync.Mutex
	activeUsers int32 // atomic: number of chainConnWrappers currently using this conn
	hadTimeout  int32 // atomic: set when a read/write timeout occurred — conn may be stale
	reuseCount  int32 // atomic: number of times this cached conn has been reused via ListenPacket
	releaseCh   chan struct{} // closed when activeUsers drops to 0 — wakes waiters instantly
}

// maxLifetimeForProto returns the max lifetime for a cached UDP conn based on
// the last hop protocol. SOCKS5 UDP relay sessions can silently degrade after
// several minutes (server-side mapping rotation, NAT changes, etc.), so we
// force a refresh after ~5 minutes. Other protocols (Hysteria2, AnyTLS, etc.)
// maintain healthier long-lived sessions, so we allow ~10 minutes.
// A ±10% jitter is applied per-conn to prevent thundering-herd reconnections
// when multiple dests are accessed simultaneously.
func maxLifetimeForProto(isSocks5 bool) time.Duration {
	base := 10 * time.Minute
	if isSocks5 {
		base = 5 * time.Minute
	}
	// ±10% jitter: 90%-110% of base
	jitterRange := int64(float64(base) * 0.1)
	jitter := time.Duration(rand.Int63n(2*jitterRange) - jitterRange)
	return base + jitter
}

// chainConnWrapper is returned to callers of ListenPacket. It forwards
// reads/writes to the cached underlying conn but Close() is a no-op —
// the actual cleanup is done by the idle sweeper.
type chainConnWrapper struct {
	cached *cachedChainConn
	parent *chainUDPOutbound
	dest   string
}

// evictOnFatalError removes the cached entry and closes the underlying conn
// when a non-timeout error occurs (the conn is dead). Timeout errors never
// evict if there are any active users — the player's forwardResponses will
// handle timeouts via its own clientInactiveTimeout check, and the idle
// sweeper will clean up the conn when all users have closed their wrappers.
// This prevents disconnects during loading screens or other brief idle
// periods where the server sends no data for 60+ seconds.
func (w *chainConnWrapper) evictOnFatalError(err error) {
	if err == nil {
		return
	}
	if isTimeoutError(err) {
		// Mark the conn as suspect so it's evicted before next reuse.
		// This is critical for one-shot tests (MCBE UDP test) where a
		// read timeout means the SOCKS5 relay stopped forwarding —
		// without this flag, the dead conn stays in cache and poisons
		// all subsequent users (including periodic pings).
		atomic.StoreInt32(&w.cached.hadTimeout, 1)

		// Never evict on timeout if anyone is actively using this conn.
		// The idle sweeper will clean up when activeUsers == 0.
		if atomic.LoadInt32(&w.cached.activeUsers) > 0 {
			return
		}
		// No active users — check if the conn has been idle long enough
		// to be considered dead (TCP control link silently dropped).
		idle := time.Since(time.Unix(0, w.cached.lastUsed.Load()))
		if idle < 60*time.Second {
			return
		}
		logger.Debug("ChainUDPOutbound: evicting stale cached conn for %s (idle %s, timeout)", w.dest, idle)
	} else {
		// Non-timeout error — the conn is dead. Don't evict if other users
		// are actively using this conn; they'll get the same error and
		// close on their own.
		if atomic.LoadInt32(&w.cached.activeUsers) > 1 {
			logger.Debug("ChainUDPOutbound: skipping eviction for %s (other active users), err=%v", w.dest, err)
			return
		}
		logger.Debug("ChainUDPOutbound: evicting dead cached conn for %s: %v", w.dest, err)
	}
	w.parent.cacheMu.Lock()
	if cached, ok := w.parent.cache[w.dest]; ok && cached == w.cached {
		cached.pc.Close()
		delete(w.parent.cache, w.dest)
	}
	w.parent.cacheMu.Unlock()
}

func (w *chainConnWrapper) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := w.cached.pc.ReadFrom(p)
	if err != nil {
		w.evictOnFatalError(err)
	} else {
		atomic.StoreInt32(&w.cached.hadTimeout, 0)
		atomic.StoreInt32(&w.cached.reuseCount, 0)
		w.cached.lastUsed.Store(time.Now().UnixNano())
	}
	return n, addr, err
}

func (w *chainConnWrapper) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := w.cached.pc.WriteTo(p, addr)
	if err != nil {
		w.evictOnFatalError(err)
	} else {
		atomic.StoreInt32(&w.cached.hadTimeout, 0)
		w.cached.lastUsed.Store(time.Now().UnixNano())
	}
	return n, err
}

func (w *chainConnWrapper) LocalAddr() net.Addr { return w.cached.pc.LocalAddr() }

func (w *chainConnWrapper) SetDeadline(t time.Time) error      { return w.cached.pc.SetDeadline(t) }
func (w *chainConnWrapper) SetReadDeadline(t time.Time) error  { return w.cached.pc.SetReadDeadline(t) }
func (w *chainConnWrapper) SetWriteDeadline(t time.Time) error { return w.cached.pc.SetWriteDeadline(t) }

func (w *chainConnWrapper) Close() error {
	// Decrement active user count first
	remaining := atomic.AddInt32(&w.cached.activeUsers, -1)
	if remaining <= 0 {
		// No more active users. Signal any goroutine waiting in ListenPacket
		// that this conn is now available for reuse.
		w.cached.mu.Lock()
		if w.cached.releaseCh != nil {
			close(w.cached.releaseCh)
			w.cached.releaseCh = nil
		}
		w.cached.mu.Unlock()

		// Check if this conn is still the cached one.
		w.parent.cacheMu.Lock()
		if cached, ok := w.parent.cache[w.dest]; !ok || cached != w.cached {
			// This conn is no longer in the cache (was replaced by a newer
			// one while it was in use). Close it now to prevent a resource
			// leak — the idle sweeper can't reach it since it's not cached.
			w.cached.pc.Close()
		} else if atomic.LoadInt32(&w.cached.hadTimeout) != 0 {
			// Previous user had a read/write timeout — the SOCKS5 relay
			// may have stopped forwarding. Evict the conn so the next
			// user gets a fresh connection instead of inheriting a dead
			// relay session.
			w.cached.pc.Close()
			delete(w.parent.cache, w.dest)
			logger.Debug("ChainUDPOutbound: evicted cached conn for %s on close (had timeout)", w.dest)
		} else {
			// Still in cache — set a short read deadline to unblock
			// any pending ReadFrom calls (e.g. forwardResponses in
			// RawUDPProxy.Stop()). 1s is long enough for the next user
			// to start reading before the deadline fires, but short
			// enough to not block Stop() for too long.
			w.cached.pc.SetReadDeadline(time.Now().Add(1 * time.Second))
			w.cached.pc.SetWriteDeadline(time.Time{})
		}
		w.parent.cacheMu.Unlock()
	}
	return nil
}

var _ net.PacketConn = (*chainConnWrapper)(nil)

// CreateChainUDPOutbound creates a UDP outbound that routes through a chain of proxies.
// chainConfigs is ordered: chainConfigs[0] is the first hop, chainConfigs[len-1] is the last.
func CreateChainUDPOutbound(chainConfigs []*config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
	if len(chainConfigs) == 0 {
		return nil, fmt.Errorf("chain: at least one proxy config is required")
	}

	// Build the chain: each hop's dialer uses the previous hop's dialer
	var prevDialer N.Dialer = &directDialer{timeout: 30 * time.Second}
	var finalOutbound *SingboxOutbound
	allOutbounds := make([]*SingboxOutbound, 0, len(chainConfigs))

	for i, cfg := range chainConfigs {
		if cfg == nil {
			return nil, fmt.Errorf("chain: hop %d config is nil", i)
		}

		outbound, err := chainSingboxOutbound(cfg, prevDialer)
		if err != nil {
			return nil, fmt.Errorf("chain: failed to create outbound for hop %d (%s): %w", i, cfg.Name, err)
		}
		allOutbounds = append(allOutbounds, outbound)

		// Create a SingboxDialer for this hop to use as the next hop's underlying dialer
		sd, err := chainSingboxDialer(cfg, prevDialer)
		if err != nil {
			return nil, fmt.Errorf("chain: failed to create dialer for hop %d (%s): %w", i, cfg.Name, err)
		}
		nxD := &chainNxDialer{tcpDialer: sd, udpOutbound: outbound}
		prevDialer = nxD

		if i == len(chainConfigs)-1 {
			finalOutbound = outbound
		}
	}

	if finalOutbound == nil {
		return nil, fmt.Errorf("chain: failed to create final outbound")
	}

	return &chainUDPOutbound{
		hops:         chainConfigs,
		outbound:     finalOutbound,
		allOutbounds: allOutbounds,
		cache:        make(map[string]*cachedChainConn),
		cacheStop:    make(chan struct{}),
	}, nil
}

// drainUDPBuffer discards any pending packets in the UDP socket buffer by
// performing non-blocking reads until the buffer is empty. This prevents
// stale packets (e.g. a late pong from a previous MCBE ping) from being
// returned to the next user of a cached connection, which would cause
// timestamp mismatches and spurious read timeouts.
func drainUDPBuffer(pc net.PacketConn) {
	_ = pc.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	buf := make([]byte, 1500)
	for {
		_, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
	}
	_ = pc.SetReadDeadline(time.Time{})
}

// isConnAlive checks whether a cached PacketConn is still usable before reuse.
// It checks for protocol-specific liveness flags (e.g. SOCKS5 remoteClosed)
// and falls back to a non-blocking read probe for unknown types.
func isConnAlive(pc net.PacketConn) bool {
	// Check SOCKS5-specific liveness flag
	if s5, ok := pc.(*socks5UDPPacketConn); ok {
		if s5.IsRemoteClosed() {
			return false
		}
		// Reconnecting means the conn is being rebuilt — still alive.
		return true
	}
	// For other protocols, try a zero-length read with immediate deadline.
	// A timeout means the conn is alive; a non-timeout error means it's dead.
	// Use a 1ms deadline to avoid blocking.
	_ = pc.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	buf := make([]byte, 1)
	_, _, err := pc.ReadFrom(buf)
	if err == nil {
		// Got data — conn is alive (but we consumed a byte; this is a
		// last-resort path that shouldn't happen for well-behaved protocols)
		return true
	}
	if isTimeoutError(err) {
		return true
	}
	return false
}

func (c *chainUDPOutbound) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	// Normalize cache key: resolve domain to IP so that "mco.cubecraft.net:19132"
	// and "176.116.126.224:19132" share the same cache entry.
	cacheKey := normalizeCacheKey(destination)
	if cacheKey != destination {
		logger.Debug("ChainUDPOutbound: normalized cache key dest=%s -> key=%s", destination, cacheKey)
	}

	// Try cache first — but ONLY if no one else is actively using it AND it's
	// still alive. Multiple concurrent readers on the same SOCKS5 UDP socket
	// would steal each other's datagrams (UDP ReadFrom returns complete
	// datagrams to whichever reader wakes up first). They would also
	// overwrite each other's read deadlines on the shared socket. So we only
	// allow sequential reuse: when the previous user has closed their wrapper
	// (activeUsers == 0) and the conn is still alive, the next user can take
	// over. Dead cached conns are evicted immediately.
	// maxIdleReuse limits how long an idle cached connection can be reused.
	// SOCKS5 UDP relay servers typically drop UDP mappings after 30-60s of
	// idle while keeping the TCP control connection alive, making isConnAlive
	// pass but the UDP path dead. With UDP keepalive now active (25s interval),
	// the server-side mapping stays alive longer, so we can safely reuse for
	// 30s. For other protocols (Hysteria2, AnyTLS, etc.) the session stays
	// alive longer, so use 60s to allow ping reuse within the 60s ping interval.
	maxIdleReuse := 60 * time.Second
	isSocks5LastHop := len(c.hops) > 0 && c.hops[len(c.hops)-1].Type == config.ProtocolSOCKS5
	if isSocks5LastHop {
		maxIdleReuse = 30 * time.Second
	}
	c.cacheMu.Lock()

	// Wait for the cached conn to become available if it's currently in use.
	// This prevents creating multiple concurrent SOCKS5 ASSOCIATEs to the same
	// remote server, which can cause the server to drop packets for the older
	// association. We wait up to 3s for SOCKS5 (enough for a quick ping to
	// finish) before falling back to creating a new connection.
	waitTimeout := 5 * time.Second
	if isSocks5LastHop {
		waitTimeout = 2 * time.Second
	}
	waitDeadline := time.Now().Add(waitTimeout)

	// maxReuseCount is now unlimited (0). We rely on three mechanisms to
	// detect and evict dead SOCKS5 UDP relay connections:
	//  1. IsRemoteClosed() — checks if the TCP control connection was closed
	//     by the remote server (called before reuse in the cache lookup below).
	//  2. hadTimeout flag — set when a ReadFrom/WriteTo times out, causing
	//     immediate eviction on Close() and before next reuse.
	//  3. UDP keepalive (every 15s) — keeps the server-side UDP mapping alive
	//     on healthy connections, preventing idle-timeout drops.
	// Additionally, testMCBEServer has a retry-on-timeout fallback that creates
	// a fresh ASSOCIATE if the cached one turns out to be dead.
	// Previously maxReuseCount=3 forced a new ASSOCIATE every 4th request,
	// causing 400-800ms latency spikes and ~5% broken-ASSOCIATE failures.
	maxReuseCount := int32(0) // 0 = unlimited

	for {
		cached, ok := c.cache[cacheKey]
		if !ok {
			break // no cached conn — create new one
		}
		if atomic.LoadInt32(&cached.activeUsers) > 0 {
			// Conn is busy — wait for it to be released via channel signal.
			// UDP sockets are not shareable: concurrent ReadFrom callers
			// would steal each other's datagrams. So we wait for the
			// active user to finish (e.g. a quick ping test) before reusing.
			if time.Now().After(waitDeadline) {
				// Wait timed out — the active user is likely a long-lived
				// game client, not a stuck ping. Create a new ASSOCIATE;
				// the old conn stays alive for the active user.
				logger.Debug("ChainUDPOutbound: cached conn for %s still busy after %s wait, creating new conn (old conn preserved for active user)", cacheKey, waitTimeout)
				break
			}
			// Channel-based wait: releaseCh is closed when activeUsers
			// drops to 0, waking us instantly. This replaces the old
			// 10ms busy-wait polling and reduces wake latency from
			// ~5ms avg to ~0.01ms.
			cached.mu.Lock()
			ch := cached.releaseCh
			if ch == nil {
				ch = make(chan struct{})
				cached.releaseCh = ch
			}
			cached.mu.Unlock()
			remaining := time.Until(waitDeadline)
			if remaining <= 0 {
				break
			}
			c.cacheMu.Unlock()
			select {
			case <-ch:
				// Conn was released — re-acquire lock and re-check.
				c.cacheMu.Lock()
				continue
			case <-time.After(remaining):
				// Wait timed out.
				c.cacheMu.Lock()
				continue
			}
		}

		// Conn is available — check if it's still usable
		idle := time.Since(time.Unix(0, cached.lastUsed.Load()))
		age := time.Since(cached.createdAt)
		if !isConnAlive(cached.pc) {
			cached.pc.Close()
			delete(c.cache, cacheKey)
			logger.Debug("ChainUDPOutbound: evicted dead cached conn for %s before reuse", cacheKey)
			break // create new conn
		} else if idle > maxIdleReuse {
			cached.pc.Close()
			delete(c.cache, cacheKey)
			logger.Debug("ChainUDPOutbound: evicted stale cached conn for %s (idle %s > %s) before reuse", cacheKey, idle, maxIdleReuse)
			break // create new conn
		} else if cached.maxLifetime > 0 && age > cached.maxLifetime {
			cached.pc.Close()
			delete(c.cache, cacheKey)
			logger.Debug("ChainUDPOutbound: evicted expired cached conn for %s (age %s > maxLifetime %s) before reuse", cacheKey, age, cached.maxLifetime)
			break // create new conn
		} else if atomic.LoadInt32(&cached.hadTimeout) != 0 {
			cached.pc.Close()
			delete(c.cache, cacheKey)
			logger.Debug("ChainUDPOutbound: evicted cached conn for %s before reuse (had timeout)", cacheKey)
			break // create new conn
		} else if maxReuseCount > 0 && atomic.LoadInt32(&cached.reuseCount) >= maxReuseCount {
			cached.pc.Close()
			delete(c.cache, cacheKey)
			logger.Debug("ChainUDPOutbound: evicted cached conn for %s before reuse (reuseCount %d >= %d)", cacheKey, atomic.LoadInt32(&cached.reuseCount), maxReuseCount)
			break // create new conn
		} else {
			atomic.AddInt32(&cached.activeUsers, 1)
			atomic.AddInt32(&cached.reuseCount, 1)
			reuseCount := atomic.LoadInt32(&cached.reuseCount)
			// Create a fresh releaseCh for the next potential waiter.
			cached.mu.Lock()
			cached.releaseCh = make(chan struct{})
			cached.mu.Unlock()
			c.cacheMu.Unlock()
			_ = cached.pc.SetDeadline(time.Time{})
			// Only drain stale packets if the conn has been idle long
			// enough for a previous user's unread response to be sitting
			// in the socket buffer. 200ms is enough for a round-trip pong
			// to arrive after the previous user closed without reading.
			// The 1ms drain cost is negligible compared to the 100ms+
			// ping round-trip, so we always drain if idle > 200ms.
			if idle > 200*time.Millisecond {
				drainUDPBuffer(cached.pc)
			}
			idleDur := time.Since(time.Unix(0, cached.lastUsed.Load()))
			logger.Debug("ChainUDPOutbound: reusing cached UDP conn for %s (key=%s) via %d-hop chain reuseCount=%d idleMs=%d ageMs=%d", destination, cacheKey, len(c.hops), reuseCount, idleDur.Milliseconds(), age.Milliseconds())
			return &chainConnWrapper{cached: cached, parent: c, dest: cacheKey}, nil
		}
	}

	c.cacheMu.Unlock()

	establishStart := time.Now()
	logger.Debug("ChainUDPOutbound: establishing UDP to %s via %d-hop chain", destination, len(c.hops))
	conn, err := c.outbound.ListenPacket(ctx, destination)
	establishMs := time.Since(establishStart).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("chain UDP outbound failed: %w", err)
	}
	logger.Debug("ChainUDPOutbound: UDP connection established to %s via chain establishMs=%d", destination, establishMs)

	cached := &cachedChainConn{
		pc:          conn,
		dest:        cacheKey,
		createdAt:   time.Now(),
		maxLifetime: maxLifetimeForProto(isSocks5LastHop),
		releaseCh:   make(chan struct{}),
	}
	cached.lastUsed.Store(time.Now().UnixNano())

	// Cache this new conn. If the old cached conn is still in use by someone
	// else, it will be closed when its last user calls Close() (since it's
	// no longer in the cache at that point).
	c.cacheMu.Lock()
	c.cache[cacheKey] = cached
	c.cacheMu.Unlock()

	// Start idle sweeper once
	c.cacheOnce.Do(func() {
		go c.idleSweeper()
	})

	atomic.AddInt32(&cached.activeUsers, 1)
	return &chainConnWrapper{cached: cached, parent: c, dest: cacheKey}, nil
}

// normalizeCacheKey resolves the host part of a host:port address to an IP
// address so that the same server accessed by domain or IP shares a single
// cache entry. If resolution fails, the original string is used as-is.
// DNS results are cached for 5 minutes to avoid repeated lookups.
var dnsCacheMu sync.Mutex
var dnsCache = make(map[string]dnsCacheEntry)

type dnsCacheEntry struct {
	ip        string
	expiresAt time.Time
}

func normalizeCacheKey(destination string) string {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return destination
	}
	if net.ParseIP(host) != nil {
		return destination // already an IP
	}

	// Check DNS cache first
	dnsCacheMu.Lock()
	if entry, ok := dnsCache[host]; ok && time.Now().Before(entry.expiresAt) {
		dnsCacheMu.Unlock()
		return net.JoinHostPort(entry.ip, port)
	}
	dnsCacheMu.Unlock()

	// Use the filtered resolver (resolveOutboundServerIP) instead of
	// net.DefaultResolver. When a TUN proxy (Clash/Mihomo) is running, the
	// system resolver returns fake IPs (198.18.0.0/15, 100.64/10, ...) which
	// would produce a different cache key than the real IP used by
	// pingTargetServer (which gets resolved IP from config). This mismatch
	// prevents the MCBE UDP test from reusing the ping's cached SOCKS5 UDP
	// connection, forcing it to create a new UDP ASSOCIATE that may get a
	// firewalled relay port — causing the persistent read i/o timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, _, err := resolveOutboundServerIP(ctx, host)
	if err != nil || ip == nil {
		return destination
	}
	ipStr := ip.String()

	// Cache the result
	dnsCacheMu.Lock()
	dnsCache[host] = dnsCacheEntry{ip: ipStr, expiresAt: time.Now().Add(5 * time.Minute)}
	// Clean expired entries occasionally
	if len(dnsCache) > 100 {
		now := time.Now()
		for h, e := range dnsCache {
			if !now.Before(e.expiresAt) {
				delete(dnsCache, h)
			}
		}
	}
	dnsCacheMu.Unlock()

	return net.JoinHostPort(ipStr, port)
}

// idleSweeper is a proactive background health checker that runs every 15
// seconds. It performs three critical functions:
//  1. Evicts idle conns past their max idle reuse time (120s) — these are
//     likely dead since the SOCKS5 relay has dropped the UDP mapping.
//  2. Health-checks idle conns via isConnAlive — detects silently dropped
//     TCP control connections before a user tries to reuse them.
//  3. Enforces max lifetime — prevents using degraded relay sessions that
//     pass isConnAlive but have stale server-side state.
//
// Conns with active users (real players) are never forcibly closed — the
// player's RakNet keepalive and our UDP keepalive (15s) keep the session
// alive, and evictOnFatalError handles dead conns.
func (c *chainUDPOutbound) idleSweeper() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.cacheStop:
			return
		case <-ticker.C:
			c.cacheMu.Lock()
			now := time.Now()
			for dest, cached := range c.cache {
				if atomic.LoadInt32(&cached.activeUsers) > 0 {
					// Active user — don't evict. But check if the SOCKS5
					// TCP control connection was silently dropped by the
					// remote server. If so, mark hadTimeout so the conn
					// is evicted when the user closes it.
					if s5, ok := cached.pc.(*socks5UDPPacketConn); ok && s5.IsRemoteClosed() {
						atomic.StoreInt32(&cached.hadTimeout, 1)
						logger.Debug("ChainUDPOutbound: marked active cached conn for %s as dead (SOCKS5 remote closed)", dest)
					}
					continue
				}
				idle := now.Sub(time.Unix(0, cached.lastUsed.Load()))
				age := now.Sub(cached.createdAt)
				// 1. Idle timeout
				if idle > 120*time.Second {
					cached.pc.Close()
					delete(c.cache, dest)
					logger.Debug("ChainUDPOutbound: closed idle cached UDP conn for %s (idle %s)", dest, idle)
					continue
				}
				// 2. Health check — detect dead conns proactively
				if !isConnAlive(cached.pc) {
					cached.pc.Close()
					delete(c.cache, dest)
					logger.Debug("ChainUDPOutbound: health-checked and evicted dead cached conn for %s (idle %s)", dest, idle)
					continue
				}
				// 3. Max lifetime — force refresh of old conns
				if cached.maxLifetime > 0 && age > cached.maxLifetime {
					cached.pc.Close()
					delete(c.cache, dest)
					logger.Debug("ChainUDPOutbound: evicted expired cached conn for %s (age %s > maxLifetime %s)", dest, age, cached.maxLifetime)
					continue
				}
			}
			c.cacheMu.Unlock()
		}
	}
}

func (c *chainUDPOutbound) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true

	// Stop idle sweeper and close all cached connections
	close(c.cacheStop)
	c.cacheMu.Lock()
	for dest, cached := range c.cache {
		cached.pc.Close()
		delete(c.cache, dest)
	}
	c.cacheMu.Unlock()

	// Close all hop outbounds to release anytls/hy2 background goroutines.
	// SingboxOutbound.Close() is safe to call multiple times (sets clients to nil).
	for _, ob := range c.allOutbounds {
		ob.Close()
	}
	return nil
}

var _ singboxcore.UDPOutbound = (*chainUDPOutbound)(nil)

// ChainFactory wraps a singboxcore.Factory and intercepts creation for chain proxy outbounds.
type ChainFactory struct {
	inner       singboxcore.Factory
	outboundMgr OutboundManager
}

// NewChainFactory creates a ChainFactory that wraps the given factory.
// outboundMgr is used to resolve chain hop names to ProxyOutbound configs.
func NewChainFactory(inner singboxcore.Factory, outboundMgr OutboundManager) *ChainFactory {
	return &ChainFactory{
		inner:       inner,
		outboundMgr: outboundMgr,
	}
}

func (f *ChainFactory) CreateUDPOutbound(ctx context.Context, cfg *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
	if cfg.IsChainProxy() {
		return f.createChainUDPOutbound(ctx, cfg)
	}
	return f.inner.CreateUDPOutbound(ctx, cfg)
}

func (f *ChainFactory) CreateDialer(ctx context.Context, cfg *config.ProxyOutbound) (singboxcore.Dialer, error) {
	if cfg.IsChainProxy() {
		return f.createChainDialer(ctx, cfg)
	}
	return f.inner.CreateDialer(ctx, cfg)
}

func (f *ChainFactory) createChainUDPOutbound(ctx context.Context, cfg *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
	chainConfigs, err := f.resolveChain(cfg)
	if err != nil {
		return nil, err
	}
	return CreateChainUDPOutbound(chainConfigs)
}

func (f *ChainFactory) createChainDialer(ctx context.Context, cfg *config.ProxyOutbound) (singboxcore.Dialer, error) {
	chainConfigs, err := f.resolveChain(cfg)
	if err != nil {
		return nil, err
	}
	return CreateChainDialer(chainConfigs)
}

// resolveChain resolves the chain hop names to ProxyOutbound configs.
// Returns an ordered list: chain[0], chain[1], ..., chain[n-1], then cfg itself.
// Nested chains are supported: if a hop is itself a chain proxy, its hops are
// recursively expanded and inserted in order. Cycle detection prevents infinite loops.
func (f *ChainFactory) resolveChain(cfg *config.ProxyOutbound) ([]*config.ProxyOutbound, error) {
	chainNames := cfg.GetChain()
	if len(chainNames) == 0 {
		return nil, fmt.Errorf("chain: no chain hops configured for %s", cfg.Name)
	}
	if f.outboundMgr == nil {
		return nil, fmt.Errorf("chain: outbound manager not available to resolve chain hops")
	}

	visited := make(map[string]bool)
	visited[cfg.Name] = true

	chainConfigs := make([]*config.ProxyOutbound, 0, len(chainNames))
	for _, name := range chainNames {
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("chain: hop name is empty in %s", cfg.Name)
		}
		expanded, err := f.resolveHop(name, visited)
		if err != nil {
			return nil, err
		}
		chainConfigs = append(chainConfigs, expanded...)
	}
	if len(chainConfigs) == 0 {
		return nil, fmt.Errorf("chain: no valid hops configured for %s", cfg.Name)
	}
	return chainConfigs, nil
}

// resolveHop resolves a single hop name into one or more ProxyOutbound configs.
// If the hop is a chain proxy, its sub-hops are recursively expanded.
// visited tracks names already in the current expansion path to detect cycles.
func (f *ChainFactory) resolveHop(name string, visited map[string]bool) ([]*config.ProxyOutbound, error) {
	if visited[name] {
		return nil, fmt.Errorf("chain: cycle detected at %s (circular chain reference)", name)
	}
	hop, ok := f.outboundMgr.GetOutbound(name)
	if !ok {
		return nil, fmt.Errorf("chain: hop %s not found", name)
	}

	if !hop.IsChainProxy() {
		visited[name] = true
		return []*config.ProxyOutbound{hop.Clone()}, nil
	}

	// Nested chain: recursively expand its hops
	subNames := hop.GetChain()
	if len(subNames) == 0 {
		// Edge case: IsChainProxy returned true but GetChain is empty
		visited[name] = true
		return []*config.ProxyOutbound{hop.Clone()}, nil
	}

	visited[name] = true
	result := make([]*config.ProxyOutbound, 0, len(subNames))
	for _, subName := range subNames {
		subName = strings.TrimSpace(subName)
		if subName == "" {
			return nil, fmt.Errorf("chain: hop name is empty in %s", name)
		}
		expanded, err := f.resolveHop(subName, visited)
		if err != nil {
			return nil, err
		}
		result = append(result, expanded...)
	}
	return result, nil
}

var _ singboxcore.Factory = (*ChainFactory)(nil)
