// Package proxy provides the core UDP proxy functionality.
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
)

// ProxyDialer implements a custom dialer that routes connections through OutboundManager.
// It implements the interface needed by go-raknet's Dialer.UpstreamDialer.
// Requirements: 2.1, 2.2, 2.3, 2.4
type ProxyDialer struct {
	outboundMgr  OutboundManager
	serverConfig *config.ServerConfig
	timeout      time.Duration
}

// NewProxyDialer creates a new ProxyDialer.
// If outboundMgr is nil or serverConfig.ProxyOutbound is empty/"direct", it will use direct connections.
func NewProxyDialer(outboundMgr OutboundManager, serverConfig *config.ServerConfig, timeout time.Duration) *ProxyDialer {
	return &ProxyDialer{
		outboundMgr:  outboundMgr,
		serverConfig: serverConfig,
		timeout:      timeout,
	}
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
// This method is required by raknet.UpstreamDialer interface.
// Requirements: 2.1, 2.2, 2.4
func (d *ProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Check if we should use direct connection
	// Requirements: 2.2
	if d.shouldUseDirect() {
		logger.Debug("ProxyDialer: Using direct connection for %s", address)
		dialer := &net.Dialer{Timeout: d.timeout}
		return dialer.DialContext(ctx, network, address)
	}

	proxyOutbound := d.serverConfig.GetProxyOutbound()
	logger.Debug("ProxyDialer: Dialing %s via proxy outbound %s (network=%s)", address, proxyOutbound, network)

	// Get PacketConn through the outbound manager
	packetConn, err := d.outboundMgr.DialPacketConn(ctx, proxyOutbound, address)
	if err != nil {
		// Requirements: 2.4 - Fallback to direct connection on error
		logger.Warn("ProxyDialer: Failed to dial through proxy %s: %v, falling back to direct", proxyOutbound, err)
		dialer := &net.Dialer{Timeout: d.timeout}
		return dialer.DialContext(ctx, network, address)
	}

	logger.Debug("ProxyDialer: PacketConn created successfully for %s via %s", address, proxyOutbound)

	// Wrap PacketConn as a Conn for go-raknet compatibility
	remoteAddr := parseUDPAddr(address)
	logger.Debug("ProxyDialer: Wrapping PacketConn, remoteAddr=%v", remoteAddr)
	return &packetConnWrapper{
		PacketConn: packetConn,
		remoteAddr: remoteAddr,
	}, nil
}

// shouldUseDirect returns true if direct connection should be used.
// Requirements: 2.2
func (d *ProxyDialer) shouldUseDirect() bool {
	// No outbound manager configured
	if d.outboundMgr == nil {
		return true
	}

	// No server config
	if d.serverConfig == nil {
		return true
	}

	// Check if proxy outbound is empty or "direct"
	return d.serverConfig.IsDirectConnection()
}

// parseUDPAddr parses an address string into a UDP address.
func parseUDPAddr(address string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil
	}
	return addr
}

// packetConnWrapper wraps a PacketConn to implement net.Conn interface.
// This is needed because go-raknet expects a net.Conn but we have a PacketConn.
type packetConnWrapper struct {
	net.PacketConn
	remoteAddr    *net.UDPAddr
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
		return 0, fmt.Errorf("connection closed")
	}
	c.closedMu.Unlock()

	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
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
	} else {
		logger.Debug("packetConnWrapper.Read: received %d bytes from %v", n, addr)
	}
	return n, err
}

// Write writes data to the connection.
func (c *packetConnWrapper) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.remoteAddr == nil {
		return 0, fmt.Errorf("remote address not set")
	}
	logger.Debug("packetConnWrapper.Write: sending %d bytes to %v", len(b), c.remoteAddr)
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
	c.closed = true
	c.closedMu.Unlock()
	return c.PacketConn.Close()
}

// Ensure packetConnWrapper implements net.Conn
var _ net.Conn = (*packetConnWrapper)(nil)
