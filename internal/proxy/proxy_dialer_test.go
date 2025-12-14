// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"mcpeserverproxy/internal/config"
)

// **Feature: singbox-outbound-proxy, Property 5: Direct routing for empty/direct proxy_outbound**
// **Validates: Requirements 2.2**
// For any ServerConfig with proxy_outbound set to empty string or "direct",
// the routing logic should return a direct connection (no proxy).
func TestProperty5_DirectRoutingForEmptyOrDirectProxyOutbound(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for server configs with empty or "direct" proxy_outbound
	directProxyOutboundGen := gen.OneConstOf("", "direct")

	properties.Property("empty proxy_outbound uses direct connection", prop.ForAll(
		func(proxyOutbound string) bool {
			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          19132,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound,
			}

			// Verify IsDirectConnection returns true for empty or "direct"
			if !cfg.IsDirectConnection() {
				t.Logf("IsDirectConnection should return true for proxy_outbound=%q", proxyOutbound)
				return false
			}

			// Create a ProxyDialer with an OutboundManager
			outboundMgr := NewOutboundManager(nil)
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			// Verify shouldUseDirect returns true
			if !dialer.shouldUseDirect() {
				t.Logf("shouldUseDirect should return true for proxy_outbound=%q", proxyOutbound)
				return false
			}

			return true
		},
		directProxyOutboundGen,
	))

	properties.Property("nil outbound manager uses direct connection", prop.ForAll(
		func(proxyOutbound string) bool {
			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          19132,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound,
			}

			// Create a ProxyDialer with nil OutboundManager
			dialer := NewProxyDialer(nil, cfg, 5*time.Second)

			// Verify shouldUseDirect returns true when outboundMgr is nil
			if !dialer.shouldUseDirect() {
				t.Logf("shouldUseDirect should return true when outboundMgr is nil")
				return false
			}

			return true
		},
		gen.AnyString(),
	))

	properties.Property("nil server config uses direct connection", prop.ForAll(
		func(_ bool) bool {
			// Create a ProxyDialer with nil ServerConfig
			outboundMgr := NewOutboundManager(nil)
			dialer := NewProxyDialer(outboundMgr, nil, 5*time.Second)

			// Verify shouldUseDirect returns true when serverConfig is nil
			if !dialer.shouldUseDirect() {
				t.Logf("shouldUseDirect should return true when serverConfig is nil")
				return false
			}

			return true
		},
		gen.Bool(),
	))

	properties.Property("direct connection actually works", prop.ForAll(
		func(proxyOutbound string) bool {
			// Create a local UDP server to test direct connection
			serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Logf("Failed to resolve server address: %v", err)
				return false
			}

			serverConn, err := net.ListenUDP("udp", serverAddr)
			if err != nil {
				t.Logf("Failed to create server connection: %v", err)
				return false
			}
			defer serverConn.Close()

			actualServerAddr := serverConn.LocalAddr().String()

			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          serverConn.LocalAddr().(*net.UDPAddr).Port,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound, // empty or "direct"
			}

			// Create a ProxyDialer
			outboundMgr := NewOutboundManager(nil)
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			// Dial should succeed with direct connection
			conn, err := dialer.Dial("udp", actualServerAddr)
			if err != nil {
				t.Logf("Failed to dial: %v", err)
				return false
			}
			defer conn.Close()

			// Verify connection is established
			if conn == nil {
				t.Logf("Connection should not be nil")
				return false
			}

			return true
		},
		directProxyOutboundGen,
	))

	properties.TestingRun(t)
}

// **Feature: singbox-outbound-proxy, Property 6: Fallback to direct for non-existent outbound**
// **Validates: Requirements 2.4**
// For any ServerConfig referencing a non-existent proxy outbound name,
// the routing logic should return a direct connection.
func TestProperty6_FallbackToDirectForNonExistentOutbound(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for non-existent outbound names
	nonExistentOutboundGen := gen.Identifier().Map(func(s string) string {
		return "nonexistent_" + s
	})

	properties.Property("non-existent outbound falls back to direct connection", prop.ForAll(
		func(proxyOutbound string) bool {
			// Create a local UDP server to test fallback
			serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Logf("Failed to resolve server address: %v", err)
				return false
			}

			serverConn, err := net.ListenUDP("udp", serverAddr)
			if err != nil {
				t.Logf("Failed to create server connection: %v", err)
				return false
			}
			defer serverConn.Close()

			actualServerAddr := serverConn.LocalAddr().String()

			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          serverConn.LocalAddr().(*net.UDPAddr).Port,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound, // non-existent outbound
			}

			// Create an OutboundManager without the referenced outbound
			outboundMgr := NewOutboundManager(nil)

			// Create a ProxyDialer
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			// Verify shouldUseDirect returns false (because proxy_outbound is set)
			if dialer.shouldUseDirect() {
				t.Logf("shouldUseDirect should return false for proxy_outbound=%q", proxyOutbound)
				return false
			}

			// Dial should succeed by falling back to direct connection
			// because the outbound doesn't exist
			conn, err := dialer.Dial("udp", actualServerAddr)
			if err != nil {
				t.Logf("Failed to dial (should have fallen back to direct): %v", err)
				return false
			}
			defer conn.Close()

			// Verify connection is established
			if conn == nil {
				t.Logf("Connection should not be nil")
				return false
			}

			return true
		},
		nonExistentOutboundGen,
	))

	properties.Property("DialContext also falls back for non-existent outbound", prop.ForAll(
		func(proxyOutbound string) bool {
			// Create a local UDP server to test fallback
			serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Logf("Failed to resolve server address: %v", err)
				return false
			}

			serverConn, err := net.ListenUDP("udp", serverAddr)
			if err != nil {
				t.Logf("Failed to create server connection: %v", err)
				return false
			}
			defer serverConn.Close()

			actualServerAddr := serverConn.LocalAddr().String()

			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          serverConn.LocalAddr().(*net.UDPAddr).Port,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound, // non-existent outbound
			}

			// Create an OutboundManager without the referenced outbound
			outboundMgr := NewOutboundManager(nil)

			// Create a ProxyDialer
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			// DialContext should succeed by falling back to direct connection
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := dialer.DialContext(ctx, "udp", actualServerAddr)
			if err != nil {
				t.Logf("DialContext failed (should have fallen back to direct): %v", err)
				return false
			}
			defer conn.Close()

			// Verify connection is established
			if conn == nil {
				t.Logf("Connection should not be nil")
				return false
			}

			return true
		},
		nonExistentOutboundGen,
	))

	properties.TestingRun(t)
}
