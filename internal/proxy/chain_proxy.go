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
type chainUDPOutbound struct {
	hops     []*config.ProxyOutbound
	outbound *SingboxOutbound // the last hop's outbound (with chained dialer)
	closed   bool
	mu       sync.Mutex
}

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
		hops:     chainConfigs,
		outbound: finalOutbound,
	}, nil
}

func (c *chainUDPOutbound) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	logger.Debug("ChainUDPOutbound: establishing UDP to %s via %d-hop chain", destination, len(c.hops))
	conn, err := c.outbound.ListenPacket(ctx, destination)
	if err != nil {
		return nil, fmt.Errorf("chain UDP outbound failed: %w", err)
	}
	logger.Debug("ChainUDPOutbound: UDP connection established to %s via chain", destination)
	return conn, nil
}

func (c *chainUDPOutbound) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
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
