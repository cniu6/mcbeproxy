package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
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
	tcpDialer singboxcore.Dialer // wraps the previous proxy in the chain
}

func (d *chainNxDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	addr := destination.String()
	conn, err := d.tcpDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("chain dialer: failed to dial %s: %w", addr, err)
	}
	return conn, nil
}

// ListenPacket is required by N.Dialer but chain dialers only support TCP
// (the UDP path is handled separately via chainUDPOutbound).
func (d *chainNxDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("chain dialer does not support ListenPacket; use chainUDPOutbound instead")
}

// Close is not part of N.Dialer but is needed for resource cleanup.
func (d *chainNxDialer) Close() error {
	return d.tcpDialer.Close()
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
	hops     []*config.ProxyOutbound // ordered list of proxy configs (chain[0]..chain[n-1], then the node itself)
	dialers  []*chainNxDialer        // underlying dialers for each hop (for cleanup)
	final    *SingboxDialer          // the last hop's SingboxDialer (used for DialContext)
	closed   bool
	mu       sync.Mutex
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
	var finalSingboxDialer *SingboxDialer

	for i, cfg := range chainConfigs {
		if cfg == nil {
			return nil, fmt.Errorf("chain: hop %d config is nil", i)
		}

		sd, err := chainSingboxDialer(cfg, prevDialer)
		if err != nil {
			return nil, fmt.Errorf("chain: failed to create dialer for hop %d (%s): %w", i, cfg.Name, err)
		}

		// Wrap the SingboxDialer as an N.Dialer for the next hop
		nxD := &chainNxDialer{tcpDialer: sd}
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
		hops:    chainConfigs,
		dialers: nxDialers,
		final:   finalSingboxDialer,
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
	hops     []*config.ProxyOutbound
	outbound *SingboxOutbound // the last hop's outbound (with chained dialer)
	closed   bool
	mu       sync.Mutex

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
	pc       net.PacketConn
	dest     string
	lastUsed time.Time
	mu       sync.Mutex
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
// when an error occurs. Non-timeout errors always evict. Timeout errors only
// evict if the connection has been idle for more than 30 seconds (likely a
// dead connection whose TCP control link was silently dropped).
func (w *chainConnWrapper) evictOnFatalError(err error) {
	if err == nil {
		return
	}
	if isTimeoutError(err) {
		w.cached.mu.Lock()
		idle := time.Since(w.cached.lastUsed)
		w.cached.mu.Unlock()
		if idle < 30*time.Second {
			return
		}
		logger.Debug("ChainUDPOutbound: evicting stale cached conn for %s (idle %s, timeout)", w.dest, idle)
	} else {
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
		w.cached.mu.Lock()
		w.cached.lastUsed = time.Now()
		w.cached.mu.Unlock()
	}
	return n, addr, err
}

func (w *chainConnWrapper) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := w.cached.pc.WriteTo(p, addr)
	if err != nil {
		w.evictOnFatalError(err)
	} else {
		w.cached.mu.Lock()
		w.cached.lastUsed = time.Now()
		w.cached.mu.Unlock()
	}
	return n, err
}

func (w *chainConnWrapper) LocalAddr() net.Addr { return w.cached.pc.LocalAddr() }

func (w *chainConnWrapper) SetDeadline(t time.Time) error      { return w.cached.pc.SetDeadline(t) }
func (w *chainConnWrapper) SetReadDeadline(t time.Time) error  { return w.cached.pc.SetReadDeadline(t) }
func (w *chainConnWrapper) SetWriteDeadline(t time.Time) error { return w.cached.pc.SetWriteDeadline(t) }

func (w *chainConnWrapper) Close() error {
	// Reset deadlines so the cached conn is clean for the next user.
	// Without this, a expired read deadline from the previous user causes
	// all subsequent reads to immediately time out.
	w.cached.pc.SetDeadline(time.Time{})

	// Drain any stale datagrams left in the socket buffer so the next user
	// doesn't receive a response to the previous user's request.
	go func() {
		buf := make([]byte, 2048)
		w.cached.pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		for {
			if _, _, err := w.cached.pc.ReadFrom(buf); err != nil {
				break
			}
		}
		w.cached.pc.SetReadDeadline(time.Time{})
	}()

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

	for i, cfg := range chainConfigs {
		if cfg == nil {
			return nil, fmt.Errorf("chain: hop %d config is nil", i)
		}

		outbound, err := chainSingboxOutbound(cfg, prevDialer)
		if err != nil {
			return nil, fmt.Errorf("chain: failed to create outbound for hop %d (%s): %w", i, cfg.Name, err)
		}

		// Create a SingboxDialer for this hop to use as the next hop's underlying dialer
		sd, err := chainSingboxDialer(cfg, prevDialer)
		if err != nil {
			return nil, fmt.Errorf("chain: failed to create dialer for hop %d (%s): %w", i, cfg.Name, err)
		}
		nxD := &chainNxDialer{tcpDialer: sd}
		prevDialer = nxD

		if i == len(chainConfigs)-1 {
			finalOutbound = outbound
		}
	}

	if finalOutbound == nil {
		return nil, fmt.Errorf("chain: failed to create final outbound")
	}

	return &chainUDPOutbound{
		hops:      chainConfigs,
		outbound:  finalOutbound,
		cache:     make(map[string]*cachedChainConn),
		cacheStop: make(chan struct{}),
	}, nil
}

func (c *chainUDPOutbound) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	// Normalize cache key: resolve domain to IP so that "mco.cubecraft.net:19132"
	// and "176.116.126.224:19132" share the same cache entry.
	cacheKey := normalizeCacheKey(destination)

	// Try cache first
	c.cacheMu.Lock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.cacheMu.Unlock()
		logger.Debug("ChainUDPOutbound: reusing cached UDP conn for %s (key=%s) via %d-hop chain", destination, cacheKey, len(c.hops))
		return &chainConnWrapper{cached: cached, parent: c, dest: cacheKey}, nil
	}
	c.cacheMu.Unlock()

	logger.Debug("ChainUDPOutbound: establishing UDP to %s via %d-hop chain", destination, len(c.hops))
	conn, err := c.outbound.ListenPacket(ctx, destination)
	if err != nil {
		return nil, fmt.Errorf("chain UDP outbound failed: %w", err)
	}
	logger.Debug("ChainUDPOutbound: UDP connection established to %s via chain", destination)

	cached := &cachedChainConn{
		pc:       conn,
		dest:     cacheKey,
		lastUsed: time.Now(),
	}

	c.cacheMu.Lock()
	c.cache[cacheKey] = cached
	c.cacheMu.Unlock()

	// Start idle sweeper once
	c.cacheOnce.Do(func() {
		go c.idleSweeper()
	})

	return &chainConnWrapper{cached: cached, parent: c, dest: cacheKey}, nil
}

// normalizeCacheKey resolves the host part of a host:port address to an IP
// address so that the same server accessed by domain or IP shares a single
// cache entry. If resolution fails, the original string is used as-is.
func normalizeCacheKey(destination string) string {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return destination
	}
	if net.ParseIP(host) != nil {
		return destination // already an IP
	}
	// Try quick DNS resolution
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return destination
	}
	return net.JoinHostPort(ips[0].IP.String(), port)
}

// idleSweeper periodically closes cached UDP connections that have been idle
// for more than 45 seconds. The aggressive timeout is intentional: SOCKS5 UDP
// ASSOCIATE relies on a TCP control connection that can be silently dropped by
// the server or NAT, and a stale cached connection is worse than creating a
// fresh one.
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
				cached.mu.Lock()
				idle := now.Sub(cached.lastUsed)
				cached.mu.Unlock()
				if idle > 45*time.Second {
					cached.pc.Close()
					delete(c.cache, dest)
					logger.Debug("ChainUDPOutbound: closed idle cached UDP conn for %s (idle %s)", dest, idle)
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

	return c.outbound.Close()
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
