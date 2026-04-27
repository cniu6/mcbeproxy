// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

type outboundPacketConnNoRetryDialer interface {
	DialPacketConnNoRetry(ctx context.Context, outboundName string, destination string) (net.PacketConn, error)
}

type proxySelectionConfig interface {
	IsGroupSelection() bool
	IsMultiNodeSelection() bool
	GetNodeList() []string
	GetGroupName() string
}

func dialPacketConnForFailover(ctx context.Context, outboundMgr OutboundManager, outboundName string, destination string) (net.PacketConn, error) {
	if noRetryDialer, ok := outboundMgr.(outboundPacketConnNoRetryDialer); ok {
		return noRetryDialer.DialPacketConnNoRetry(ctx, outboundName, destination)
	}
	return outboundMgr.DialPacketConn(ctx, outboundName, destination)
}

// ProxyDialer implements a custom dialer that routes connections through OutboundManager.
// It implements the interface needed by go-raknet's Dialer.UpstreamDialer.
// Supports load balancing and failover for group selections.
// Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2
type ProxyDialer struct {
	outboundMgr   OutboundManager
	serverConfig  *config.ServerConfig
	timeout       time.Duration
	excludedNodes []string // Nodes to exclude during failover (already tried and failed)
	selectedNode  string   // Currently selected node name (for logging)
	mu            sync.Mutex
}

// NewProxyDialer creates a new ProxyDialer.
// If outboundMgr is nil or serverConfig.ProxyOutbound is empty/"direct", it will use direct connections.
func NewProxyDialer(outboundMgr OutboundManager, serverConfig *config.ServerConfig, timeout time.Duration) *ProxyDialer {
	return &ProxyDialer{
		outboundMgr:   outboundMgr,
		serverConfig:  serverConfig,
		timeout:       timeout,
		excludedNodes: nil,
		selectedNode:  "",
	}
}

// GetSelectedNode returns the name of the currently selected node.
// This is useful for logging which node was actually used for the connection.
func (d *ProxyDialer) GetSelectedNode() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.selectedNode
}

// ResetFailover clears the excluded nodes list, allowing all nodes to be tried again.
// This should be called when starting a new connection attempt.
func (d *ProxyDialer) ResetFailover() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.excludedNodes = nil
	d.selectedNode = ""
}

func (d *ProxyDialer) setSelectedNode(nodeName string) {
	d.mu.Lock()
	d.selectedNode = nodeName
	d.mu.Unlock()
}

// Dial creates a connection to the specified address.
// If a proxy outbound is configured, it routes through the proxy.
// Otherwise, it uses a direct connection.
// Requirements: 2.1, 2.2, 2.4
func (d *ProxyDialer) Dial(network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

// DialContext creates a connection to the specified address with context.
// If a proxy outbound is configured, it routes through the proxy.
// Otherwise, it uses a direct connection.
// Supports load balancing for group selections (@groupName) and automatic failover.
// This method is required by raknet.UpstreamDialer interface.
// Requirements: 2.1, 2.2, 2.4, 3.1, 3.2
func (d *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.setSelectedNode("")
	if d.serverConfig == nil {
		return nil, errors.New("proxy dial failed: missing server config")
	}

	// Check if we should use direct connection
	// Requirements: 2.2
	if d.shouldUseDirect() {
		logger.Debug("ProxyDialer: Using direct connection for %s", address)
		dialer := &net.Dialer{Timeout: d.timeout}
		return dialer.DialContext(ctx, network, address)
	}
	if d.outboundMgr == nil {
		return nil, errors.New("proxy dial failed: outbound manager unavailable")
	}

	proxyOutbound := d.serverConfig.GetProxyOutbound()

	// Check if this is a group selection (load balancing mode)
	if d.serverConfig.IsGroupSelection() {
		return d.dialWithLoadBalancing(ctx, network, address, proxyOutbound)
	}

	// Check if this is a multi-node selection (load balancing mode)
	if d.serverConfig.IsMultiNodeSelection() {
		return d.dialWithLoadBalancing(ctx, network, address, proxyOutbound)
	}

	// Single node mode - use direct outbound name
	logger.Debug("ProxyDialer: Dialing %s via proxy outbound %s (network=%s)", address, proxyOutbound, network)

	// Get PacketConn through the outbound manager
	packetConn, packetConnCancel, err := d.dialDetachedPacketConn(ctx, proxyOutbound, address)
	if err != nil {
		d.setSelectedNode("")
		logger.Warn("ProxyDialer: Failed to dial through proxy %s: %v", proxyOutbound, err)
		return nil, fmt.Errorf("proxy dial failed via outbound %q: %w", proxyOutbound, err)
	}

	// Track the selected node
	d.setSelectedNode(proxyOutbound)

	logger.Debug("ProxyDialer: PacketConn created successfully for %s via %s", address, proxyOutbound)

	// Wrap PacketConn as a Conn for go-raknet compatibility
	remoteAddr := parseUDPAddr(address)
	logger.Debug("ProxyDialer: Wrapping PacketConn, remoteAddr=%v", remoteAddr)
	return &packetConnWrapper{
		PacketConn: packetConn,
		nodeName:   proxyOutbound,
		remoteAddr: remoteAddr,
		cancel:     packetConnCancel,
	}, nil
}

func proxySelectionAttemptLimit(cfg proxySelectionConfig, outboundMgr OutboundManager) int {
	if cfg == nil || outboundMgr == nil {
		return 1
	}
	if cfg.IsMultiNodeSelection() {
		nodes := cfg.GetNodeList()
		if len(nodes) > 0 {
			return len(nodes)
		}
	}
	if cfg.IsGroupSelection() {
		groupName := cfg.GetGroupName()
		if groupName != "" {
			nodes := outboundMgr.GetOutboundsByGroup(groupName)
			if len(nodes) > 0 {
				return len(nodes)
			}
		}
	}
	return 1
}

// dialWithLoadBalancing handles connection with load balancing and failover support.
// It selects a node from the group based on the configured strategy and automatically
// fails over to the next healthy node if connection fails.
// Requirements: 3.1, 3.2
func (d *ProxyDialer) dialWithLoadBalancing(ctx context.Context, network, address, groupSelector string) (net.Conn, error) {
	strategy := d.serverConfig.GetLoadBalance()
	sortBy := d.serverConfig.GetLoadBalanceSort()

	d.mu.Lock()
	d.excludedNodes = nil
	excludedNodes := make([]string, 0, 4)
	d.mu.Unlock()

	// Determine selector type for logging
	selectorType := "group"
	selectorDisplay := groupSelector
	if strings.Contains(groupSelector, ",") {
		selectorType = "node-list"
		nodeCount := len(strings.Split(groupSelector, ","))
		selectorDisplay = fmt.Sprintf("%d nodes", nodeCount)
	}

	// Log: selecting ONE node from the pool
	if len(excludedNodes) == 0 {
		logger.Debug("ProxyDialer: Selecting one node from %s %s for %s (strategy=%s, sortBy=%s)",
			selectorType, selectorDisplay, address, strategy, sortBy)
	} else {
		logger.Debug("ProxyDialer: Failover - selecting next node from %s %s for %s (excluded=%v, strategy=%s, sortBy=%s)",
			selectorType, selectorDisplay, address, excludedNodes, strategy, sortBy)
	}

	// Try to select and connect to a node, with failover on failure
	for {
		// Select a healthy node from the group
		selectedOutbound, err := d.outboundMgr.SelectOutboundWithFailoverForServer(d.serverConfig.ID, groupSelector, strategy, sortBy, excludedNodes)
		if err != nil {
			// No more healthy nodes available
			// Requirements: 3.2 - Log failover event
			if len(excludedNodes) > 0 {
				logger.Warn("ProxyDialer: All failover attempts exhausted for %s %s (tried: %v): %v",
					selectorType, selectorDisplay, excludedNodes, err)
			} else {
				logger.Warn("ProxyDialer: No healthy nodes available in %s %s: %v", selectorType, selectorDisplay, err)
			}

			d.setSelectedNode("")
			return nil, fmt.Errorf("proxy dial failed for selector %q after tried=%v: %w", groupSelector, excludedNodes, err)
		}

		nodeName := selectedOutbound.Name
		logger.Debug("ProxyDialer: Selected node '%s' (from %s %s) for %s", nodeName, selectorType, selectorDisplay, address)

		// "direct" virtual node selected from a multi-node list: use a plain
		// net.Dialer connection. Failover still applies if the direct dial
		// itself fails (e.g. target is unreachable from this host).
		if IsDirectSelection(selectedOutbound) {
			directDialer := &net.Dialer{Timeout: d.timeout}
			directConn, directErr := directDialer.DialContext(ctx, network, address)
			if directErr == nil {
				d.setSelectedNode(DirectNodeName)
				return directConn, nil
			}
			excludedNodes = append(excludedNodes, DirectNodeName)
			d.mu.Lock()
			d.excludedNodes = excludedNodes
			d.mu.Unlock()
			logger.Warn("ProxyDialer: Failover - virtual 'direct' failed: %v, trying next node", directErr)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				continue
			}
		}

		// Try to connect through the selected node
		packetConn, packetConnCancel, err := d.dialDetachedPacketConn(ctx, nodeName, address)
		if err != nil {
			// Connection failed - add to excluded list and try next node
			// Requirements: 3.1, 3.2 - Automatic failover and logging
			excludedNodes = append(excludedNodes, nodeName)

			d.mu.Lock()
			d.excludedNodes = excludedNodes
			d.mu.Unlock()

			logger.Warn("ProxyDialer: Failover - node '%s' failed: %v, trying next node", nodeName, err)

			// Check context cancellation before retrying
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				continue // Try next node
			}
		}

		// Connection successful
		d.mu.Lock()
		previousNode := d.selectedNode
		d.selectedNode = nodeName
		d.mu.Unlock()

		// Log failover success if we had to try multiple nodes
		// Requirements: 3.2 - Log failover event with original and new node names
		if len(excludedNodes) > 0 {
			logger.Info("ProxyDialer: Failover successful - connected via '%s' after %d failed attempts (failed: %v)",
				nodeName, len(excludedNodes), excludedNodes)
		} else if previousNode != "" && previousNode != nodeName {
			logger.Debug("ProxyDialer: Node selection changed from '%s' to '%s'", previousNode, nodeName)
		}

		logger.Debug("ProxyDialer: PacketConn created for %s via '%s'", address, nodeName)

		// Wrap PacketConn as a Conn for go-raknet compatibility
		remoteAddr := parseUDPAddr(address)
		return &packetConnWrapper{
			PacketConn: packetConn,
			nodeName:   nodeName,
			remoteAddr: remoteAddr,
			cancel:     packetConnCancel,
		}, nil
	}
}

func (d *ProxyDialer) dialDetachedPacketConn(ctx context.Context, outboundName string, address string) (net.PacketConn, context.CancelFunc, error) {
	type dialResult struct {
		conn net.PacketConn
		err  error
	}

	packetCtx, packetCancel := context.WithCancel(context.Background())
	resultCh := make(chan dialResult, 1)

	go func() {
		conn, err := dialPacketConnForFailover(packetCtx, d.outboundMgr, outboundName, address)
		resultCh <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		packetCancel()
		go func() {
			result := <-resultCh
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		return nil, nil, ctx.Err()
	case result := <-resultCh:
		if result.err != nil {
			packetCancel()
			if result.conn != nil {
				_ = result.conn.Close()
			}
			return nil, nil, result.err
		}
		return result.conn, packetCancel, nil
	}
}

// shouldUseDirect returns true if direct connection should be used.
// Requirements: 2.2
func (d *ProxyDialer) shouldUseDirect() bool {
	return d.serverConfig != nil && d.serverConfig.IsDirectConnection()
}

// parseUDPAddr parses an address string into a UDP address.
func parseUDPAddr(address string) *net.UDPAddr {
	addr, err := resolveUDPAddr(address)
	if err != nil {
		return nil
	}
	return addr
}

// packetConnWrapper wraps a PacketConn to implement net.Conn interface.
// This is needed because go-raknet expects a net.Conn but we have a PacketConn.
type packetConnWrapper struct {
	net.PacketConn
	nodeName      string
	remoteAddr    *net.UDPAddr
	cancel        context.CancelFunc
	readMu        sync.Mutex
	writeMu       sync.Mutex
	closed        bool
	closedMu      sync.Mutex
	errorLoggedMu sync.Mutex
	errorLogged   bool // Prevent repeated error logging after close
}

// Read reads data from the connection.
func (c *packetConnWrapper) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Check if already closed
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return 0, net.ErrClosed
	}
	c.closedMu.Unlock()

	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			// Normalize close-related errors to net.ErrClosed so go-raknet's Dialer.clientListen
			// can exit cleanly instead of spinning/logging forever.
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				return 0, net.ErrClosed
			}

			// Only log the first error after close to avoid spam
			c.errorLoggedMu.Lock()
			if !c.errorLogged {
				logger.Debug("packetConnWrapper.Read error: %v", err)
				// Mark as logged if it's a close-related error
				errStr := err.Error()
				if strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
					c.errorLogged = true
				}
			}
			c.errorLoggedMu.Unlock()
			return n, err
		}

		if c.remoteAddr == nil || addr == nil || samePacketSource(addr, c.remoteAddr) {
			return n, nil
		}

		if logger.IsLevelEnabled(logger.LevelDebug) {
			logger.Debug("packetConnWrapper.Read dropped packet from unexpected source: expected=%v got=%v bytes=%d", c.remoteAddr, addr, n)
		}
	}
}

func samePacketSource(addr net.Addr, expected *net.UDPAddr) bool {
	if expected == nil || addr == nil {
		return false
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return addr.String() == expected.String()
	}

	if udpAddr.Port != expected.Port {
		return false
	}

	if udpAddr.IP == nil || expected.IP == nil {
		return addr.String() == expected.String()
	}

	return udpAddr.IP.Equal(expected.IP)
}

// Write writes data to the connection.
func (c *packetConnWrapper) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.remoteAddr == nil {
		return 0, fmt.Errorf("remote address not set")
	}
	n, err = c.PacketConn.WriteTo(b, c.remoteAddr)
	if err != nil {
		logger.Debug("packetConnWrapper.Write error: %v", err)
	}
	return n, err
}

// RemoteAddr returns the remote network address.
func (c *packetConnWrapper) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (c *packetConnWrapper) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *packetConnWrapper) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *packetConnWrapper) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}

// Close closes the connection.
func (c *packetConnWrapper) Close() error {
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return nil
	}
	c.closed = true
	c.closedMu.Unlock()
	if logger.IsLevelEnabled(logger.LevelDebug) {
		// 关闭 sing-box UDP 上游连接属于正常生命周期事件，不再输出完整调用栈，避免在 ACL 踢出等场景下制造“错误”假象。
		logger.Debug("packetConnWrapper.Close: node=%s local=%v remote=%v", c.nodeName, c.PacketConn.LocalAddr(), c.remoteAddr)
	}
	if c.cancel != nil {
		c.cancel()
	}
	return c.PacketConn.Close()
}

// Ensure packetConnWrapper implements net.Conn
var _ net.Conn = (*packetConnWrapper)(nil)
