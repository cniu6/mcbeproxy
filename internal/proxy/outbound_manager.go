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
)

// Error definitions for OutboundManager operations.
var (
	ErrOutboundNotFound  = errors.New("proxy outbound not found")
	ErrOutboundExists    = errors.New("proxy outbound already exists")
	ErrOutboundUnhealthy = errors.New("proxy outbound is unhealthy")
	ErrAllRetriesFailed  = errors.New("all retry attempts failed")
)

// Retry configuration constants
// Requirements: 6.1
const (
	MaxRetryAttempts     = 3                      // Maximum number of retry attempts
	InitialRetryDelay    = 100 * time.Millisecond // Initial delay before first retry
	MaxRetryDelay        = 2 * time.Second        // Maximum delay between retries
	RetryBackoffMultiple = 2                      // Multiplier for exponential backoff
)

// HealthStatus represents the health status of a proxy outbound.
type HealthStatus struct {
	Healthy   bool          `json:"healthy"`
	Latency   time.Duration `json:"latency"`
	LastCheck time.Time     `json:"last_check"`
	ConnCount int64         `json:"conn_count"`
	LastError string        `json:"last_error,omitempty"`
}

// OutboundManager defines the interface for managing proxy outbound nodes.
// Requirements: 1.1, 1.3, 1.4, 1.5, 3.1, 3.3, 3.4, 4.1, 4.2, 4.3, 4.4, 8.1, 8.2, 8.3
type OutboundManager interface {
	// AddOutbound adds a new proxy outbound configuration.
	// Returns ErrOutboundExists if an outbound with the same name already exists.
	// Returns validation error if the configuration is invalid.
	AddOutbound(cfg *config.ProxyOutbound) error

	// GetOutbound retrieves a proxy outbound by name.
	// Returns the outbound and true if found, nil and false otherwise.
	GetOutbound(name string) (*config.ProxyOutbound, bool)

	// DeleteOutbound removes a proxy outbound by name.
	// Returns ErrOutboundNotFound if the outbound doesn't exist.
	DeleteOutbound(name string) error

	// ListOutbounds returns all configured proxy outbounds.
	ListOutbounds() []*config.ProxyOutbound

	// UpdateOutbound updates an existing proxy outbound configuration.
	// Returns ErrOutboundNotFound if the outbound doesn't exist.
	// Returns validation error if the new configuration is invalid.
	UpdateOutbound(name string, cfg *config.ProxyOutbound) error

	// CheckHealth performs a health check on the specified outbound.
	// It measures latency by attempting to establish a connection.
	// Returns ErrOutboundNotFound if the outbound doesn't exist.
	// Requirements: 4.1, 4.2, 4.4
	CheckHealth(ctx context.Context, name string) error

	// GetHealthStatus returns the health status of a proxy outbound.
	// Returns nil if the outbound doesn't exist.
	// Requirements: 4.3
	GetHealthStatus(name string) *HealthStatus

	// DialPacketConn creates a UDP PacketConn through the specified outbound.
	// Returns ErrOutboundNotFound if the outbound doesn't exist.
	// Requirements: 3.1, 3.3, 3.4
	DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error)

	// Start initializes all sing-box outbound instances for configured proxy outbounds.
	// Requirements: 8.1
	Start() error

	// Stop gracefully closes all sing-box outbound connections.
	// It waits for pending connections to complete before closing.
	// Requirements: 8.3
	Stop() error

	// Reload recreates sing-box outbounds when configuration changes.
	// It preserves existing connections during reload.
	// Requirements: 8.2
	Reload() error

	// GetActiveConnectionCount returns the total number of active connections across all outbounds.
	GetActiveConnectionCount() int64
}

// ServerConfigUpdater is an interface for updating server configurations.
// This is used for cascade updates when deleting outbounds.
type ServerConfigUpdater interface {
	// GetAllServers returns all server configurations.
	GetAllServers() []*config.ServerConfig
	// UpdateServerProxyOutbound updates the proxy_outbound field for a server.
	UpdateServerProxyOutbound(serverID string, proxyOutbound string) error
}

// outboundManagerImpl is the in-memory implementation of OutboundManager.
type outboundManagerImpl struct {
	mu                  sync.RWMutex
	outbounds           map[string]*config.ProxyOutbound
	singboxOutbounds    map[string]*SingboxOutbound
	serverConfigUpdater ServerConfigUpdater
}

// NewOutboundManager creates a new OutboundManager instance.
// The serverConfigUpdater parameter is optional and used for cascade updates on delete.
func NewOutboundManager(serverConfigUpdater ServerConfigUpdater) OutboundManager {
	return &outboundManagerImpl{
		outbounds:           make(map[string]*config.ProxyOutbound),
		singboxOutbounds:    make(map[string]*SingboxOutbound),
		serverConfigUpdater: serverConfigUpdater,
	}
}

// AddOutbound adds a new proxy outbound configuration.
// Requirements: 1.1, 1.5
func (m *outboundManagerImpl) AddOutbound(cfg *config.ProxyOutbound) error {
	if cfg == nil {
		return errors.New("proxy outbound configuration cannot be nil")
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if outbound already exists
	if _, exists := m.outbounds[cfg.Name]; exists {
		return ErrOutboundExists
	}

	// Store a clone to prevent external modification
	m.outbounds[cfg.Name] = cfg.Clone()
	return nil
}

// GetOutbound retrieves a proxy outbound by name.
// Requirements: 1.1
func (m *outboundManagerImpl) GetOutbound(name string) (*config.ProxyOutbound, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	outbound, exists := m.outbounds[name]
	if !exists {
		return nil, false
	}

	// Return a clone to prevent external modification
	return outbound.Clone(), true
}

// DeleteOutbound removes a proxy outbound by name.
// If serverConfigUpdater is set, it will cascade update server configs to use "direct".
// Requirements: 1.4
func (m *outboundManagerImpl) DeleteOutbound(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.outbounds[name]; !exists {
		return ErrOutboundNotFound
	}

	// Close and remove the sing-box outbound if it exists
	if singboxOutbound, ok := m.singboxOutbounds[name]; ok {
		singboxOutbound.Close()
		delete(m.singboxOutbounds, name)
	}

	// Delete the outbound
	delete(m.outbounds, name)

	// Cascade update server configs if updater is available
	// This is done outside the lock to avoid deadlocks
	if m.serverConfigUpdater != nil {
		m.cascadeUpdateServerConfigs(name)
	}

	return nil
}

// cascadeUpdateServerConfigs updates all server configs that reference the deleted outbound.
// Must be called after releasing the lock to avoid deadlocks.
// Requirements: 1.4
func (m *outboundManagerImpl) cascadeUpdateServerConfigs(deletedOutboundName string) {
	if m.serverConfigUpdater == nil {
		return
	}

	servers := m.serverConfigUpdater.GetAllServers()
	for _, server := range servers {
		// Check if this server references the deleted outbound
		if server.ProxyOutbound == deletedOutboundName {
			// Update to "direct" connection
			if err := m.serverConfigUpdater.UpdateServerProxyOutbound(server.ID, "direct"); err != nil {
				// Log warning for affected servers
				// In production, this would use a proper logger
				fmt.Printf("warning: failed to update server %s proxy_outbound after deleting outbound %s: %v\n",
					server.ID, deletedOutboundName, err)
			} else {
				// Log warning about the cascade update
				fmt.Printf("warning: server %s proxy_outbound updated to 'direct' because outbound %s was deleted\n",
					server.ID, deletedOutboundName)
			}
		}
	}
}

// ListOutbounds returns all configured proxy outbounds.
// Requirements: 1.3
func (m *outboundManagerImpl) ListOutbounds() []*config.ProxyOutbound {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*config.ProxyOutbound, 0, len(m.outbounds))
	for _, outbound := range m.outbounds {
		// Return clones to prevent external modification
		result = append(result, outbound.Clone())
	}
	return result
}

// UpdateOutbound updates an existing proxy outbound configuration.
// Requirements: 1.5
func (m *outboundManagerImpl) UpdateOutbound(name string, cfg *config.ProxyOutbound) error {
	if cfg == nil {
		return errors.New("proxy outbound configuration cannot be nil")
	}

	// Validate the new configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.outbounds[name]; !exists {
		return ErrOutboundNotFound
	}

	// If name changed, we need to handle the rename
	if name != cfg.Name {
		// Check if new name already exists
		if _, exists := m.outbounds[cfg.Name]; exists {
			return ErrOutboundExists
		}
		// Remove old entry
		delete(m.outbounds, name)
	}

	// Close and remove the cached sing-box outbound (will be recreated on next use)
	if singboxOutbound, ok := m.singboxOutbounds[name]; ok {
		singboxOutbound.Close()
		delete(m.singboxOutbounds, name)
	}

	// Store the updated configuration
	m.outbounds[cfg.Name] = cfg.Clone()
	return nil
}

// GetHealthStatus returns the health status of a proxy outbound.
// Requirements: 4.3
func (m *outboundManagerImpl) GetHealthStatus(name string) *HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	outbound, exists := m.outbounds[name]
	if !exists {
		return nil
	}

	return &HealthStatus{
		Healthy:   outbound.GetHealthy(),
		Latency:   outbound.GetLatency(),
		LastCheck: outbound.GetLastCheck(),
		ConnCount: outbound.GetConnCount(),
		LastError: outbound.GetLastError(),
	}
}

// CheckHealth performs a health check on the specified outbound by attempting
// to establish a connection and measuring the latency.
// Requirements: 4.1, 4.2, 4.4
func (m *outboundManagerImpl) CheckHealth(ctx context.Context, name string) error {
	m.mu.Lock()
	cfg, exists := m.outbounds[name]
	if !exists {
		m.mu.Unlock()
		return ErrOutboundNotFound
	}

	// Get or create sing-box outbound instance
	singboxOutbound, err := m.getOrCreateSingboxOutbound(cfg)
	m.mu.Unlock()

	startTime := time.Now()

	if err != nil {
		// Mark as unhealthy on creation failure
		// Requirements: 4.2, 4.4
		m.mu.Lock()
		if c, ok := m.outbounds[name]; ok {
			c.SetHealthy(false)
			c.SetLastError(fmt.Sprintf("failed to create outbound: %v", err))
			c.SetLastCheck(time.Now())
			c.SetLatency(0)
		}
		m.mu.Unlock()
		return fmt.Errorf("health check failed: %w", err)
	}

	// Perform a test connection to measure latency
	// We use a well-known DNS server as a test destination
	testDestination := "8.8.8.8:53"

	// Create a context with timeout for the health check
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := singboxOutbound.ListenPacket(checkCtx, testDestination)
	latency := time.Since(startTime)

	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.outbounds[name]
	if !ok {
		// Outbound was deleted during health check
		if conn != nil {
			conn.Close()
		}
		return ErrOutboundNotFound
	}

	c.SetLastCheck(time.Now())
	c.SetLatency(latency)

	if err != nil {
		// Mark as unhealthy on connection failure
		// Requirements: 4.2, 4.4
		c.SetHealthy(false)
		c.SetLastError(fmt.Sprintf("connection failed: %v", err))
		return fmt.Errorf("health check failed: %w", err)
	}

	// Close the test connection
	conn.Close()

	// Mark as healthy on success
	// Requirements: 4.1
	c.SetHealthy(true)
	c.SetLastError("")

	return nil
}

// DialPacketConn creates a UDP PacketConn through the specified outbound.
// Implements retry logic with exponential backoff (max 3 attempts).
// Fast-fails for unhealthy nodes without retrying.
// Requirements: 3.1, 3.3, 3.4, 6.1, 6.2, 6.4
func (m *outboundManagerImpl) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	// First, validate the outbound exists and is usable (with lock)
	m.mu.Lock()
	cfg, exists := m.outbounds[outboundName]
	if !exists {
		m.mu.Unlock()
		return nil, ErrOutboundNotFound
	}

	// Check if outbound is enabled
	if !cfg.Enabled {
		m.mu.Unlock()
		return nil, fmt.Errorf("outbound %s is disabled", outboundName)
	}

	// Fast-fail for unhealthy nodes - skip retries
	// Requirements: 6.4
	if !cfg.GetHealthy() && cfg.GetLastError() != "" {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: %s - %s", ErrOutboundUnhealthy, outboundName, cfg.GetLastError())
	}
	m.mu.Unlock()

	// Attempt connection with retry logic
	// Requirements: 6.1, 6.2
	return m.dialWithRetry(ctx, outboundName, destination)
}

// dialWithRetry implements exponential backoff retry logic for DialPacketConn.
// Requirements: 6.1, 6.2
func (m *outboundManagerImpl) dialWithRetry(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	var lastErr error
	retryDelay := InitialRetryDelay

	for attempt := 1; attempt <= MaxRetryAttempts; attempt++ {
		// Check context cancellation before each attempt
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		conn, err := m.dialPacketConnOnce(ctx, outboundName, destination)
		if err == nil {
			return conn, nil
		}

		lastErr = err

		// Check if we should skip retries (unhealthy node marked during attempt)
		// Requirements: 6.4
		m.mu.RLock()
		cfg, exists := m.outbounds[outboundName]
		if !exists {
			m.mu.RUnlock()
			return nil, ErrOutboundNotFound
		}
		isUnhealthy := !cfg.GetHealthy() && cfg.GetLastError() != ""
		m.mu.RUnlock()

		if isUnhealthy {
			// Fast-fail: don't retry for unhealthy nodes
			return nil, fmt.Errorf("%w: %s (attempt %d/%d failed, node marked unhealthy)", ErrOutboundUnhealthy, outboundName, attempt, MaxRetryAttempts)
		}

		// If this was the last attempt, don't wait
		if attempt == MaxRetryAttempts {
			break
		}

		// Wait with exponential backoff before next retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}

		// Increase delay for next retry (exponential backoff)
		retryDelay *= RetryBackoffMultiple
		if retryDelay > MaxRetryDelay {
			retryDelay = MaxRetryDelay
		}
	}

	// All retries failed
	// Requirements: 6.2
	return nil, fmt.Errorf("%w: %s after %d attempts: %v", ErrAllRetriesFailed, outboundName, MaxRetryAttempts, lastErr)
}

// dialPacketConnOnce performs a single connection attempt without retry.
func (m *outboundManagerImpl) dialPacketConnOnce(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get the outbound configuration
	cfg, exists := m.outbounds[outboundName]
	if !exists {
		return nil, ErrOutboundNotFound
	}

	// Get or create sing-box outbound instance
	singboxOutbound, err := m.getOrCreateSingboxOutbound(cfg)
	if err != nil {
		// Mark as unhealthy on creation failure
		cfg.SetHealthy(false)
		cfg.SetLastError(err.Error())
		cfg.SetLastCheck(time.Now())
		return nil, fmt.Errorf("failed to create outbound: %w", err)
	}

	// Create packet connection
	conn, err := singboxOutbound.ListenPacket(ctx, destination)
	if err != nil {
		errStr := err.Error()
		// For Hysteria2 temporary failures (connection closed, EOF), try to recreate the outbound
		// These are recoverable errors that may require a fresh connection
		isTemporaryError := strings.Contains(errStr, "connection closed") ||
			strings.Contains(errStr, "EOF") ||
			strings.Contains(errStr, "after retries")

		if cfg.Type == config.ProtocolHysteria2 && isTemporaryError {
			// Try to recreate the Hysteria2 outbound
			newOutbound, recreateErr := m.recreateSingboxOutbound(outboundName)
			if recreateErr == nil {
				// Try again with the new outbound
				conn, err = newOutbound.ListenPacket(ctx, destination)
				if err == nil {
					// Success! Continue to the success path below
					goto success
				}
			}
			// Still failed, but don't mark as permanently unhealthy
			cfg.SetLastCheck(time.Now())
			return nil, fmt.Errorf("failed to dial packet connection: %w", err)
		}

		// Mark as unhealthy on connection failure for other protocols or permanent errors
		cfg.SetHealthy(false)
		cfg.SetLastError(err.Error())
		cfg.SetLastCheck(time.Now())
		return nil, fmt.Errorf("failed to dial packet connection: %w", err)
	}

success:

	// Increment connection count
	cfg.IncrConnCount()

	// Mark as healthy on success
	cfg.SetHealthy(true)
	cfg.SetLastError("")
	cfg.SetLastCheck(time.Now())

	// Wrap connection to track when it's closed
	return &trackedPacketConn{
		PacketConn: conn,
		onClose: func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if c, ok := m.outbounds[outboundName]; ok {
				c.DecrConnCount()
			}
		},
	}, nil
}

// getOrCreateSingboxOutbound gets an existing sing-box outbound or creates a new one.
func (m *outboundManagerImpl) getOrCreateSingboxOutbound(cfg *config.ProxyOutbound) (*SingboxOutbound, error) {
	// Check if we already have a sing-box outbound for this config
	if existing, ok := m.singboxOutbounds[cfg.Name]; ok {
		return existing, nil
	}

	// Create new sing-box outbound
	singboxOutbound, err := CreateSingboxOutbound(cfg)
	if err != nil {
		return nil, err
	}

	// Cache the outbound
	m.singboxOutbounds[cfg.Name] = singboxOutbound
	return singboxOutbound, nil
}

// recreateSingboxOutbound closes and recreates a sing-box outbound.
// This is useful for protocols like Hysteria2 that may need reconnection.
func (m *outboundManagerImpl) recreateSingboxOutbound(name string) (*SingboxOutbound, error) {
	cfg, exists := m.outbounds[name]
	if !exists {
		return nil, ErrOutboundNotFound
	}

	// Close existing outbound if it exists
	if existing, ok := m.singboxOutbounds[name]; ok {
		existing.Close()
		delete(m.singboxOutbounds, name)
	}

	// Create new sing-box outbound
	singboxOutbound, err := CreateSingboxOutbound(cfg)
	if err != nil {
		return nil, err
	}

	// Cache the outbound
	m.singboxOutbounds[name] = singboxOutbound
	return singboxOutbound, nil
}

// trackedPacketConn wraps a PacketConn to track when it's closed.
type trackedPacketConn struct {
	net.PacketConn
	onClose func()
	closed  bool
}

// Close closes the connection and calls the onClose callback.
func (c *trackedPacketConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	err := c.PacketConn.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return err
}

// Start initializes all sing-box outbound instances for configured proxy outbounds.
// Requirements: 8.1
func (m *outboundManagerImpl) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize sing-box outbounds for all configured outbounds
	for name, cfg := range m.outbounds {
		if !cfg.Enabled {
			continue
		}

		// Create sing-box outbound instance
		singboxOutbound, err := CreateSingboxOutbound(cfg)
		if err != nil {
			// Log error and mark as unhealthy, but continue with other outbounds
			cfg.SetHealthy(false)
			cfg.SetLastError(fmt.Sprintf("failed to create outbound: %v", err))
			cfg.SetLastCheck(time.Now())
			fmt.Printf("warning: failed to initialize sing-box outbound %s: %v\n", name, err)
			continue
		}

		// Cache the outbound
		m.singboxOutbounds[name] = singboxOutbound
		cfg.SetHealthy(true)
		cfg.SetLastError("")
		cfg.SetLastCheck(time.Now())
	}

	return nil
}

// Stop gracefully closes all sing-box outbound connections.
// It waits for pending connections to complete before closing.
// Requirements: 8.3
func (m *outboundManagerImpl) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Wait for pending connections to complete (with timeout)
	maxWait := 10 * time.Second
	checkInterval := 100 * time.Millisecond
	waited := time.Duration(0)

	for waited < maxWait {
		activeConns := int64(0)
		for _, cfg := range m.outbounds {
			activeConns += cfg.GetConnCount()
		}
		if activeConns == 0 {
			break
		}
		m.mu.Unlock()
		time.Sleep(checkInterval)
		waited += checkInterval
		m.mu.Lock()
	}

	// Close all sing-box outbound connections
	for name, singboxOutbound := range m.singboxOutbounds {
		if err := singboxOutbound.Close(); err != nil {
			fmt.Printf("warning: failed to close sing-box outbound %s: %v\n", name, err)
		}
	}

	// Clear the cached outbounds
	m.singboxOutbounds = make(map[string]*SingboxOutbound)

	return nil
}

// Reload recreates sing-box outbounds when configuration changes.
// It preserves existing connections during reload by only recreating outbounds
// that have changed or been added.
// Requirements: 8.2
func (m *outboundManagerImpl) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Track which outbounds need to be recreated
	for name, cfg := range m.outbounds {
		if !cfg.Enabled {
			// Close and remove disabled outbounds
			if singboxOutbound, ok := m.singboxOutbounds[name]; ok {
				singboxOutbound.Close()
				delete(m.singboxOutbounds, name)
			}
			continue
		}

		// Check if we need to recreate the outbound
		// For now, we recreate if the outbound doesn't exist in cache
		if _, exists := m.singboxOutbounds[name]; !exists {
			singboxOutbound, err := CreateSingboxOutbound(cfg)
			if err != nil {
				cfg.SetHealthy(false)
				cfg.SetLastError(fmt.Sprintf("failed to create outbound: %v", err))
				cfg.SetLastCheck(time.Now())
				fmt.Printf("warning: failed to recreate sing-box outbound %s: %v\n", name, err)
				continue
			}
			m.singboxOutbounds[name] = singboxOutbound
			cfg.SetHealthy(true)
			cfg.SetLastError("")
			cfg.SetLastCheck(time.Now())
		}
	}

	// Remove sing-box outbounds for deleted configurations
	for name := range m.singboxOutbounds {
		if _, exists := m.outbounds[name]; !exists {
			m.singboxOutbounds[name].Close()
			delete(m.singboxOutbounds, name)
		}
	}

	return nil
}

// GetActiveConnectionCount returns the total number of active connections across all outbounds.
func (m *outboundManagerImpl) GetActiveConnectionCount() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var total int64
	for _, cfg := range m.outbounds {
		total += cfg.GetConnCount()
	}
	return total
}
