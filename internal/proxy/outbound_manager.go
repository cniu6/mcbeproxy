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

// Error definitions for OutboundManager operations.
var (
	ErrOutboundNotFound   = errors.New("proxy outbound not found")
	ErrOutboundExists     = errors.New("proxy outbound already exists")
	ErrOutboundUnhealthy  = errors.New("proxy outbound is unhealthy")
	ErrAllRetriesFailed   = errors.New("all retry attempts failed")
	ErrGroupNotFound      = errors.New("proxy group not found")
	ErrNoHealthyNodes     = errors.New("no healthy nodes available")
	ErrAllFailoversFailed = errors.New("all failover attempts failed")
)

// Retry configuration constants
// Requirements: 6.1
const (
	MaxRetryAttempts     = 2                     // Maximum number of retry attempts (reduced from 3 to save CPU)
	InitialRetryDelay    = 50 * time.Millisecond // Initial delay before first retry (reduced from 100ms)
	MaxRetryDelay        = 1 * time.Second       // Maximum delay between retries (reduced from 2s)
	RetryBackoffMultiple = 2                     // Multiplier for exponential backoff

	// OutboundIdleTimeout is the time after which an unused singbox outbound is closed
	// to release TLS connections and other resources
	OutboundIdleTimeout = 5 * time.Minute

	serverNodeLatencyCacheTTL = 30 * time.Minute
)

// HealthStatus represents the health status of a proxy outbound.
type HealthStatus struct {
	Healthy   bool          `json:"healthy"`
	Latency   time.Duration `json:"latency"`
	LastCheck time.Time     `json:"last_check"`
	ConnCount int64         `json:"conn_count"`
	LastError string        `json:"last_error,omitempty"`
}

// GroupStats represents statistics for a proxy outbound group.
// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 8.4
type GroupStats struct {
	Name           string `json:"name"`                // Group name (empty string for ungrouped nodes)
	TotalCount     int    `json:"total_count"`         // Total node count
	HealthyCount   int    `json:"healthy_count"`       // Healthy node count
	UDPAvailable   int    `json:"udp_available"`       // UDP available node count
	AvgTCPLatency  int64  `json:"avg_tcp_latency_ms"`  // Average TCP latency in milliseconds
	AvgUDPLatency  int64  `json:"avg_udp_latency_ms"`  // Average UDP latency in milliseconds
	AvgHTTPLatency int64  `json:"avg_http_latency_ms"` // Average HTTP latency in milliseconds
	MinTCPLatency  int64  `json:"min_tcp_latency_ms"`  // Minimum TCP latency in milliseconds
	MinUDPLatency  int64  `json:"min_udp_latency_ms"`  // Minimum UDP latency in milliseconds
	MinHTTPLatency int64  `json:"min_http_latency_ms"` // Minimum HTTP latency in milliseconds
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

	// GetGroupStats returns statistics for a specific group.
	// Returns nil if the group has no nodes.
	// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
	GetGroupStats(groupName string) *GroupStats

	// ListGroups returns statistics for all groups including ungrouped nodes.
	// Ungrouped nodes are returned with an empty group name.
	// Requirements: 8.4
	ListGroups() []*GroupStats

	// GetOutboundsByGroup returns all outbounds in a specific group.
	// Returns empty slice if the group has no nodes.
	GetOutboundsByGroup(groupName string) []*config.ProxyOutbound

	// SelectOutbound selects a healthy proxy outbound based on the specified strategy.
	// groupOrName: node name or "@groupName" for group selection
	// strategy: load balance strategy (least-latency, round-robin, random, least-connections)
	// sortBy: latency sort type (udp, tcp, http)
	// Returns the selected outbound or error if no healthy nodes available.
	// Requirements: 3.1, 3.3, 3.4
	SelectOutbound(groupOrName, strategy, sortBy string) (*config.ProxyOutbound, error)

	// SelectOutboundWithFailover selects a healthy proxy outbound with failover support.
	// excludeNodes: list of node names to exclude (for failover after connection failure)
	// Returns the selected outbound or error if all nodes exhausted.
	// Requirements: 3.1, 3.4
	SelectOutboundWithFailover(groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error)

	// SetServerNodeLatency caches latency for a specific server and node.
	// sortBy: udp/tcp/http (same values as ServerConfig.LoadBalanceSort)
	SetServerNodeLatency(serverID, nodeName, sortBy string, latencyMs int64)

	// GetServerNodeLatency returns cached latency for a specific server and node.
	// Returns (0,false) if missing or expired.
	GetServerNodeLatency(serverID, nodeName, sortBy string) (int64, bool)

	// SelectOutboundWithFailoverForServer selects a healthy proxy outbound with per-server latency preference.
	// If serverID is empty, it behaves like SelectOutboundWithFailover.
	SelectOutboundWithFailoverForServer(serverID, groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error)
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
	singboxLastUsed     map[string]time.Time // Track last usage time for idle cleanup
	serverConfigUpdater ServerConfigUpdater
	cleanupCtx          context.Context
	cleanupCancel       context.CancelFunc
	serverNodeLatencyMu sync.RWMutex
	serverNodeLatency   map[serverNodeLatencyKey]serverNodeLatencyValue
}

type serverNodeLatencyKey struct {
	serverID string
	nodeName string
	sortBy   string
}

type serverNodeLatencyValue struct {
	latencyMs  int64
	updatedAt  time.Time
	updatedAtN int64
}

// NewOutboundManager creates a new OutboundManager instance.
// The serverConfigUpdater parameter is optional and used for cascade updates on delete.
func NewOutboundManager(serverConfigUpdater ServerConfigUpdater) OutboundManager {
	return &outboundManagerImpl{
		outbounds:           make(map[string]*config.ProxyOutbound),
		singboxOutbounds:    make(map[string]*SingboxOutbound),
		singboxLastUsed:     make(map[string]time.Time),
		serverConfigUpdater: serverConfigUpdater,
		serverNodeLatency:   make(map[serverNodeLatencyKey]serverNodeLatencyValue),
	}
}

func normalizeSortBy(sortBy string) string {
	sortBy = strings.ToLower(strings.TrimSpace(sortBy))
	switch sortBy {
	case config.LoadBalanceSortTCP:
		return config.LoadBalanceSortTCP
	case config.LoadBalanceSortHTTP:
		return config.LoadBalanceSortHTTP
	case config.LoadBalanceSortUDP:
		fallthrough
	default:
		return config.LoadBalanceSortUDP
	}
}

func (m *outboundManagerImpl) SetServerNodeLatency(serverID, nodeName, sortBy string, latencyMs int64) {
	serverID = strings.TrimSpace(serverID)
	nodeName = strings.TrimSpace(nodeName)
	if serverID == "" || nodeName == "" {
		return
	}
	sortBy = normalizeSortBy(sortBy)

	key := serverNodeLatencyKey{serverID: serverID, nodeName: nodeName, sortBy: sortBy}
	now := time.Now()

	m.serverNodeLatencyMu.Lock()
	m.serverNodeLatency[key] = serverNodeLatencyValue{latencyMs: latencyMs, updatedAt: now, updatedAtN: now.UnixNano()}
	m.serverNodeLatencyMu.Unlock()
}

func (m *outboundManagerImpl) GetServerNodeLatency(serverID, nodeName, sortBy string) (int64, bool) {
	serverID = strings.TrimSpace(serverID)
	nodeName = strings.TrimSpace(nodeName)
	if serverID == "" || nodeName == "" {
		return 0, false
	}
	sortBy = normalizeSortBy(sortBy)

	key := serverNodeLatencyKey{serverID: serverID, nodeName: nodeName, sortBy: sortBy}

	m.serverNodeLatencyMu.RLock()
	v, ok := m.serverNodeLatency[key]
	m.serverNodeLatencyMu.RUnlock()
	if !ok {
		return 0, false
	}
	if !v.updatedAt.IsZero() && time.Since(v.updatedAt) > serverNodeLatencyCacheTTL {
		return 0, false
	}
	if v.latencyMs <= 0 {
		return 0, false
	}
	return v.latencyMs, true
}

func (m *outboundManagerImpl) selectLeastLatencyForServer(serverID string, nodes []*config.ProxyOutbound, sortBy string) *config.ProxyOutbound {
	// Prefer per-server cache. If none are available, fall back to the old global latency selection.
	var selected *config.ProxyOutbound
	var minLatency int64 = -1
	var hasCached bool

	for _, node := range nodes {
		latency, ok := m.GetServerNodeLatency(serverID, node.Name, sortBy)
		if !ok {
			continue
		}
		hasCached = true
		if minLatency < 0 || latency < minLatency {
			minLatency = latency
			selected = node
		}
	}

	if hasCached {
		if selected == nil && len(nodes) > 0 {
			return nodes[0]
		}
		return selected
	}

	return loadBalancer.Select(nodes, config.LoadBalanceLeastLatency, sortBy, "")
}

func (m *outboundManagerImpl) SelectOutboundWithFailoverForServer(serverID, groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	serverID = strings.TrimSpace(serverID)
	strategy = strings.TrimSpace(strategy)
	sortBy = normalizeSortBy(sortBy)

	// Empty serverID => preserve old behavior.
	if serverID == "" {
		return m.SelectOutboundWithFailover(groupOrName, strategy, sortBy, excludeNodes)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if it's a group selection (starts with "@")
	if strings.HasPrefix(groupOrName, "@") {
		groupName := strings.TrimPrefix(groupOrName, "@")
		return m.selectFromGroupForServer(serverID, groupName, strategy, sortBy, excludeNodes)
	}

	// Check if it's a multi-node selection (comma-separated)
	if strings.Contains(groupOrName, ",") {
		return m.selectFromNodeListForServer(serverID, groupOrName, strategy, sortBy, excludeNodes)
	}

	// Single node selection
	return m.selectSingleNode(groupOrName, excludeNodes)
}

// selectFromNodeListForServer selects a healthy node from a comma-separated list with per-server latency preference.
// Must be called with read lock held.
func (m *outboundManagerImpl) selectFromNodeListForServer(serverID, nodeListStr, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	// Parse the comma-separated node list
	nodeNames := strings.Split(nodeListStr, ",")

	// Build exclusion set for O(1) lookup
	excludeSet := make(map[string]bool)
	for _, name := range excludeNodes {
		excludeSet[name] = true
	}

	// Collect healthy nodes from the specified list
	var healthyNodes []*config.ProxyOutbound
	var notFoundNodes []string

	for _, nodeName := range nodeNames {
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			continue
		}

		// Skip excluded nodes (for failover)
		if excludeSet[nodeName] {
			continue
		}

		outbound, exists := m.outbounds[nodeName]
		if !exists {
			notFoundNodes = append(notFoundNodes, nodeName)
			continue
		}

		// Skip disabled nodes
		if !outbound.Enabled {
			continue
		}

		// Skip unhealthy nodes only if they have been tested and failed recently
		// Allow retry after 30 seconds to recover from transient issues
		lastCheck := outbound.GetLastCheck()
		isNeverTested := lastCheck.IsZero()
		hasError := outbound.GetLastError() != ""
		isHealthy := outbound.GetHealthy()
		timeSinceLastCheck := time.Since(lastCheck)

		if !isHealthy && !isNeverTested && hasError && timeSinceLastCheck < 30*time.Second {
			continue
		}

		healthyNodes = append(healthyNodes, outbound)
	}

	if len(healthyNodes) == 0 {
		if len(notFoundNodes) > 0 {
			return nil, fmt.Errorf("%w: nodes not found: %v", ErrOutboundNotFound, notFoundNodes)
		}
		if len(excludeNodes) > 0 {
			return nil, fmt.Errorf("%w: all specified nodes have been tried", ErrAllFailoversFailed)
		}
		return nil, fmt.Errorf("%w: in specified node list", ErrNoHealthyNodes)
	}

	if strategy == config.LoadBalanceLeastLatency {
		selected := m.selectLeastLatencyForServer(serverID, healthyNodes, sortBy)
		if selected == nil {
			return nil, fmt.Errorf("%w: in specified node list", ErrNoHealthyNodes)
		}
		return selected.Clone(), nil
	}

	virtualGroupName := "nodelist:" + nodeListStr
	selected := loadBalancer.Select(healthyNodes, strategy, sortBy, virtualGroupName)
	if selected == nil {
		return nil, fmt.Errorf("%w: in specified node list", ErrNoHealthyNodes)
	}
	return selected.Clone(), nil
}

// selectFromGroupForServer selects a healthy node from a group with per-server latency preference.
// Must be called with read lock held.
func (m *outboundManagerImpl) selectFromGroupForServer(serverID, groupName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	// Build exclusion set for O(1) lookup
	excludeSet := make(map[string]bool)
	for _, name := range excludeNodes {
		excludeSet[name] = true
	}

	// Collect healthy nodes from the group, excluding specified nodes
	var healthyNodes []*config.ProxyOutbound
	var groupExists bool

	for _, outbound := range m.outbounds {
		if outbound.Group == groupName {
			groupExists = true

			if excludeSet[outbound.Name] {
				continue
			}
			if !outbound.Enabled {
				continue
			}

			lastCheck := outbound.GetLastCheck()
			hasError := outbound.GetLastError() != ""
			isHealthy := outbound.GetHealthy()
			timeSinceLastCheck := time.Since(lastCheck)

			if !isHealthy && hasError && !lastCheck.IsZero() && timeSinceLastCheck < 30*time.Second {
				continue
			}

			healthyNodes = append(healthyNodes, outbound)
		}
	}

	if !groupExists {
		return nil, fmt.Errorf("%w: '@%s'", ErrGroupNotFound, groupName)
	}
	if len(healthyNodes) == 0 {
		if len(excludeNodes) > 0 {
			return nil, fmt.Errorf("%w: all nodes in group '@%s' have been tried", ErrAllFailoversFailed, groupName)
		}
		return nil, fmt.Errorf("%w: in group '@%s'", ErrNoHealthyNodes, groupName)
	}

	if strategy == config.LoadBalanceLeastLatency {
		selected := m.selectLeastLatencyForServer(serverID, healthyNodes, sortBy)
		if selected == nil {
			return nil, fmt.Errorf("%w: in group '@%s'", ErrNoHealthyNodes, groupName)
		}
		return selected.Clone(), nil
	}

	selected := loadBalancer.Select(healthyNodes, strategy, sortBy, groupName)
	if selected == nil {
		return nil, fmt.Errorf("%w: in group '@%s'", ErrNoHealthyNodes, groupName)
	}
	return selected.Clone(), nil
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
	deletedCfg, exists := m.outbounds[name]
	if !exists {
		m.mu.Unlock()
		return ErrOutboundNotFound
	}
	deletedGroup := deletedCfg.Group

	// Close and remove the sing-box outbound if it exists
	if singboxOutbound, ok := m.singboxOutbounds[name]; ok {
		singboxOutbound.Close()
		delete(m.singboxOutbounds, name)
		delete(m.singboxLastUsed, name)
	}

	// Delete the outbound
	delete(m.outbounds, name)
	m.mu.Unlock()

	// Cascade update server configs after releasing the lock to avoid deadlocks
	if m.serverConfigUpdater != nil {
		m.cascadeUpdateServerConfigs(name, deletedGroup)
	}
	return nil
}

// cascadeUpdateServerConfigs updates all server configs that reference the deleted outbound.
// Must be called after releasing the lock to avoid deadlocks.
// Requirements: 1.4
func (m *outboundManagerImpl) cascadeUpdateServerConfigs(deletedOutboundName string, deletedOutboundGroup string) {
	if m.serverConfigUpdater == nil {
		return
	}

	m.mu.RLock()
	remainingNames := make(map[string]struct{}, len(m.outbounds))
	groupCounts := make(map[string]int)
	for name, cfg := range m.outbounds {
		remainingNames[name] = struct{}{}
		groupCounts[cfg.Group]++
	}
	m.mu.RUnlock()

	servers := m.serverConfigUpdater.GetAllServers()
	for _, server := range servers {
		current := strings.TrimSpace(server.ProxyOutbound)
		if current == "" || current == "direct" {
			continue
		}

		next := current
		if current == deletedOutboundName {
			next = "direct"
		} else if strings.HasPrefix(current, "@") {
			group := strings.TrimPrefix(current, "@")
			if group == deletedOutboundGroup && groupCounts[group] == 0 {
				next = "direct"
			}
		} else if strings.Contains(current, ",") {
			nodes := strings.Split(current, ",")
			kept := make([]string, 0, len(nodes))
			removed := false
			for _, n := range nodes {
				n = strings.TrimSpace(n)
				if n == "" {
					continue
				}
				if n == deletedOutboundName {
					removed = true
					continue
				}
				kept = append(kept, n)
			}
			if removed {
				if len(kept) == 0 {
					next = "direct"
				} else if len(kept) == 1 {
					next = kept[0]
				} else {
					next = strings.Join(kept, ",")
				}
			}
		}

		if next == current {
			continue
		}

		if err := m.serverConfigUpdater.UpdateServerProxyOutbound(server.ID, next); err != nil {
			fmt.Printf("warning: failed to update server %s proxy_outbound after deleting outbound %s: %v\n",
				server.ID, deletedOutboundName, err)
		} else {
			fmt.Printf("warning: server %s proxy_outbound updated to '%s' because outbound %s was deleted\n",
				server.ID, next, deletedOutboundName)
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
		delete(m.singboxLastUsed, name)
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

	// If the node is unhealthy, recreate the singbox outbound to get a fresh connection
	// This helps recover from transient DNS/connection issues
	var singboxOutbound *SingboxOutbound
	var err error
	if !cfg.GetHealthy() && cfg.GetLastError() != "" {
		singboxOutbound, err = m.recreateSingboxOutbound(name)
	} else {
		singboxOutbound, err = m.getOrCreateSingboxOutbound(cfg)
	}
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
	// But allow retry after 30 seconds to recover from transient issues
	// Requirements: 6.4
	if !cfg.GetHealthy() && cfg.GetLastError() != "" {
		lastCheck := cfg.GetLastCheck()
		// Allow retry after 30 seconds of being unhealthy
		if time.Since(lastCheck) < 30*time.Second {
			m.mu.Unlock()
			return nil, fmt.Errorf("%w: %s - %s", ErrOutboundUnhealthy, outboundName, cfg.GetLastError())
		}
		// Time to retry - recreate the singbox outbound
		if _, err := m.recreateSingboxOutbound(outboundName); err != nil {
			m.mu.Unlock()
			return nil, fmt.Errorf("%w: %s - failed to recreate: %v", ErrOutboundUnhealthy, outboundName, err)
		}
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
	// Get the outbound configuration
	cfg, exists := m.outbounds[outboundName]
	if !exists {
		m.mu.Unlock()
		return nil, ErrOutboundNotFound
	}

	// Get or create sing-box outbound instance
	singboxOutbound, err := m.getOrCreateSingboxOutbound(cfg)
	m.mu.Unlock()
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
			m.mu.Lock()
			newOutbound, recreateErr := m.recreateSingboxOutbound(outboundName)
			m.mu.Unlock()
			if recreateErr == nil {
				conn, err = newOutbound.ListenPacket(ctx, destination)
				if err == nil {
					goto success
				}
			}
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

	m.mu.Lock()
	if cfg, ok := m.outbounds[outboundName]; ok {
		// Increment connection count
		cfg.IncrConnCount()
		// Mark as healthy on success
		cfg.SetHealthy(true)
		cfg.SetLastError("")
		cfg.SetLastCheck(time.Now())
		m.mu.Unlock()
	} else {
		m.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		return nil, ErrOutboundNotFound
	}

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
		// Update last used time
		m.singboxLastUsed[cfg.Name] = time.Now()
		return existing, nil
	}

	// Create new sing-box outbound
	singboxOutbound, err := CreateSingboxOutbound(cfg)
	if err != nil {
		return nil, err
	}

	// Cache the outbound and record creation time
	m.singboxOutbounds[cfg.Name] = singboxOutbound
	m.singboxLastUsed[cfg.Name] = time.Now()
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
		delete(m.singboxLastUsed, name)
	}

	// Create new sing-box outbound
	singboxOutbound, err := CreateSingboxOutbound(cfg)
	if err != nil {
		return nil, err
	}

	// Cache the outbound and record creation time
	m.singboxOutbounds[name] = singboxOutbound
	m.singboxLastUsed[name] = time.Now()
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

	// NOTE: We use lazy initialization for sing-box outbounds to save memory.
	// Each Hysteria2 client can consume 16MB+ of memory for QUIC buffers.
	// With 200+ proxy nodes, eager initialization would consume 3GB+ of memory.
	// Instead, outbounds are created on-demand when first used via getOrCreateSingboxOutbound().

	// Just mark all enabled outbounds as ready (healthy status will be set on first use)
	for name, cfg := range m.outbounds {
		if !cfg.Enabled {
			continue
		}

		// Don't create the outbound yet - it will be created lazily on first use
		// Just log that it's configured
		logger.Info("Outbound configured (lazy init): %s (%s)", name, cfg.Type)
	}

	// Start idle outbound cleanup goroutine
	m.cleanupCtx, m.cleanupCancel = context.WithCancel(context.Background())
	go m.cleanupIdleOutbounds()

	return nil
}

// cleanupIdleOutbounds periodically closes singbox outbounds that haven't been used recently.
// This helps release TLS connections and other resources for unused proxy nodes.
func (m *outboundManagerImpl) cleanupIdleOutbounds() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.cleanupCtx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			now := time.Now()
			for name, lastUsed := range m.singboxLastUsed {
				// Skip if outbound has active connections
				if cfg, ok := m.outbounds[name]; ok && cfg.GetConnCount() > 0 {
					continue
				}
				// Close if idle for too long
				if now.Sub(lastUsed) > OutboundIdleTimeout {
					if outbound, ok := m.singboxOutbounds[name]; ok {
						logger.Debug("Closing idle outbound: %s (idle for %v)", name, now.Sub(lastUsed))
						outbound.Close()
						delete(m.singboxOutbounds, name)
						delete(m.singboxLastUsed, name)
					}
				}
			}
			m.mu.Unlock()
		}
	}
}

// Stop gracefully closes all sing-box outbound connections.
// It waits for pending connections to complete before closing.
// Requirements: 8.3
func (m *outboundManagerImpl) Stop() error {
	// Cancel cleanup goroutine first
	if m.cleanupCancel != nil {
		m.cleanupCancel()
	}

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
	m.singboxLastUsed = make(map[string]time.Time)

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
				delete(m.singboxLastUsed, name)
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
			m.singboxLastUsed[name] = time.Now()
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
			delete(m.singboxLastUsed, name)
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

// GetOutboundsByGroup returns all outbounds in a specific group.
// Returns empty slice if the group has no nodes.
func (m *outboundManagerImpl) GetOutboundsByGroup(groupName string) []*config.ProxyOutbound {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*config.ProxyOutbound
	for _, outbound := range m.outbounds {
		if outbound.Group == groupName {
			result = append(result, outbound.Clone())
		}
	}
	return result
}

// GetGroupStats returns statistics for a specific group.
// Returns nil if the group has no nodes.
// Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
func (m *outboundManagerImpl) GetGroupStats(groupName string) *GroupStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.calculateGroupStats(groupName)
}

// ListGroups returns statistics for all groups including ungrouped nodes.
// Ungrouped nodes are returned with an empty group name.
// Requirements: 8.4
func (m *outboundManagerImpl) ListGroups() []*GroupStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect all unique group names
	groupNames := make(map[string]bool)
	for _, outbound := range m.outbounds {
		groupNames[outbound.Group] = true
	}

	// Calculate stats for each group
	var result []*GroupStats
	for groupName := range groupNames {
		stats := m.calculateGroupStats(groupName)
		if stats != nil {
			result = append(result, stats)
		}
	}

	return result
}

// calculateGroupStats calculates statistics for a specific group.
// Must be called with read lock held.
func (m *outboundManagerImpl) calculateGroupStats(groupName string) *GroupStats {
	var nodes []*config.ProxyOutbound
	for _, outbound := range m.outbounds {
		if outbound.Group == groupName {
			nodes = append(nodes, outbound)
		}
	}

	if len(nodes) == 0 {
		return nil
	}

	stats := &GroupStats{
		Name:           groupName,
		TotalCount:     len(nodes),
		MinTCPLatency:  -1, // Use -1 to indicate no value yet
		MinUDPLatency:  -1,
		MinHTTPLatency: -1,
	}

	var totalTCPLatency, totalUDPLatency, totalHTTPLatency int64
	var tcpCount, udpCount, httpCount int

	for _, node := range nodes {
		// Count healthy nodes
		if node.GetHealthy() {
			stats.HealthyCount++
		}

		// Count UDP available nodes
		if node.UDPAvailable != nil && *node.UDPAvailable {
			stats.UDPAvailable++
		}

		// Calculate TCP latency stats
		if node.TCPLatencyMs > 0 {
			totalTCPLatency += node.TCPLatencyMs
			tcpCount++
			if stats.MinTCPLatency < 0 || node.TCPLatencyMs < stats.MinTCPLatency {
				stats.MinTCPLatency = node.TCPLatencyMs
			}
		}

		// Calculate UDP latency stats
		if node.UDPLatencyMs > 0 {
			totalUDPLatency += node.UDPLatencyMs
			udpCount++
			if stats.MinUDPLatency < 0 || node.UDPLatencyMs < stats.MinUDPLatency {
				stats.MinUDPLatency = node.UDPLatencyMs
			}
		}

		// Calculate HTTP latency stats
		if node.HTTPLatencyMs > 0 {
			totalHTTPLatency += node.HTTPLatencyMs
			httpCount++
			if stats.MinHTTPLatency < 0 || node.HTTPLatencyMs < stats.MinHTTPLatency {
				stats.MinHTTPLatency = node.HTTPLatencyMs
			}
		}
	}

	// Calculate averages
	if tcpCount > 0 {
		stats.AvgTCPLatency = totalTCPLatency / int64(tcpCount)
	}
	if udpCount > 0 {
		stats.AvgUDPLatency = totalUDPLatency / int64(udpCount)
	}
	if httpCount > 0 {
		stats.AvgHTTPLatency = totalHTTPLatency / int64(httpCount)
	}

	// Reset -1 values to 0 for JSON output
	if stats.MinTCPLatency < 0 {
		stats.MinTCPLatency = 0
	}
	if stats.MinUDPLatency < 0 {
		stats.MinUDPLatency = 0
	}
	if stats.MinHTTPLatency < 0 {
		stats.MinHTTPLatency = 0
	}

	return stats
}

// loadBalancer is a shared LoadBalancer instance for the OutboundManager.
var loadBalancer = NewLoadBalancer()

// SelectOutbound selects a healthy proxy outbound based on the specified strategy.
// groupOrName: node name or "@groupName" for group selection
// strategy: load balance strategy (least-latency, round-robin, random, least-connections)
// sortBy: latency sort type (udp, tcp, http)
// Returns the selected outbound or error if no healthy nodes available.
// Requirements: 3.1, 3.3, 3.4
func (m *outboundManagerImpl) SelectOutbound(groupOrName, strategy, sortBy string) (*config.ProxyOutbound, error) {
	return m.SelectOutboundWithFailover(groupOrName, strategy, sortBy, nil)
}

// SelectOutboundWithFailover selects a healthy proxy outbound with failover support.
// excludeNodes: list of node names to exclude (for failover after connection failure)
// Returns the selected outbound or error if all nodes exhausted.
// Requirements: 3.1, 3.4
func (m *outboundManagerImpl) SelectOutboundWithFailover(groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if it's a group selection (starts with "@")
	if strings.HasPrefix(groupOrName, "@") {
		groupName := strings.TrimPrefix(groupOrName, "@")
		return m.selectFromGroup(groupName, strategy, sortBy, excludeNodes)
	}

	// Check if it's a multi-node selection (comma-separated)
	if strings.Contains(groupOrName, ",") {
		return m.selectFromNodeList(groupOrName, strategy, sortBy, excludeNodes)
	}

	// Single node selection
	return m.selectSingleNode(groupOrName, excludeNodes)
}

// selectFromNodeList selects a healthy node from a comma-separated list of node names.
// Must be called with read lock held.
func (m *outboundManagerImpl) selectFromNodeList(nodeListStr, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	// Parse the comma-separated node list
	nodeNames := strings.Split(nodeListStr, ",")

	// Build exclusion set for O(1) lookup
	excludeSet := make(map[string]bool)
	for _, name := range excludeNodes {
		excludeSet[name] = true
	}

	// Collect healthy nodes from the specified list
	var healthyNodes []*config.ProxyOutbound
	var notFoundNodes []string

	for _, nodeName := range nodeNames {
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			continue
		}

		// Skip excluded nodes (for failover)
		if excludeSet[nodeName] {
			continue
		}

		outbound, exists := m.outbounds[nodeName]
		if !exists {
			notFoundNodes = append(notFoundNodes, nodeName)
			continue
		}

		// Skip disabled nodes
		if !outbound.Enabled {
			continue
		}

		// Skip unhealthy nodes only if they have been tested and failed recently
		// Allow retry after 30 seconds to recover from transient issues
		lastCheck := outbound.GetLastCheck()
		isNeverTested := lastCheck.IsZero()
		hasError := outbound.GetLastError() != ""
		isHealthy := outbound.GetHealthy()
		timeSinceLastCheck := time.Since(lastCheck)

		// Allow node if:
		// - healthy
		// - never tested
		// - no error recorded
		// - unhealthy but last check was more than 30 seconds ago (allow retry)
		if !isHealthy && !isNeverTested && hasError && timeSinceLastCheck < 30*time.Second {
			continue
		}

		healthyNodes = append(healthyNodes, outbound)
	}

	// Check if there are any healthy nodes
	if len(healthyNodes) == 0 {
		if len(notFoundNodes) > 0 {
			return nil, fmt.Errorf("%w: nodes not found: %v", ErrOutboundNotFound, notFoundNodes)
		}
		if len(excludeNodes) > 0 {
			return nil, fmt.Errorf("%w: all specified nodes have been tried", ErrAllFailoversFailed)
		}
		return nil, fmt.Errorf("%w: in specified node list", ErrNoHealthyNodes)
	}

	// Use load balancer to select a node
	// Use a virtual group name based on the node list for round-robin state tracking
	virtualGroupName := "nodelist:" + nodeListStr
	selected := loadBalancer.Select(healthyNodes, strategy, sortBy, virtualGroupName)
	if selected == nil {
		return nil, fmt.Errorf("%w: in specified node list", ErrNoHealthyNodes)
	}

	return selected.Clone(), nil
}

// selectFromGroup selects a healthy node from a group.
// Must be called with read lock held.
func (m *outboundManagerImpl) selectFromGroup(groupName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	// Build exclusion set for O(1) lookup
	excludeSet := make(map[string]bool)
	for _, name := range excludeNodes {
		excludeSet[name] = true
	}

	// Collect healthy nodes from the group, excluding specified nodes
	var healthyNodes []*config.ProxyOutbound
	var groupExists bool

	for _, outbound := range m.outbounds {
		if outbound.Group == groupName {
			groupExists = true

			// Skip excluded nodes (for failover)
			if excludeSet[outbound.Name] {
				continue
			}

			// Skip disabled nodes
			if !outbound.Enabled {
				continue
			}

			// Skip unhealthy nodes only if they failed recently
			// Allow retry after 30 seconds to recover from transient issues
			// Requirements: 3.4 - exclude unhealthy nodes from selection
			lastCheck := outbound.GetLastCheck()
			hasError := outbound.GetLastError() != ""
			isHealthy := outbound.GetHealthy()
			timeSinceLastCheck := time.Since(lastCheck)

			if !isHealthy && hasError && !lastCheck.IsZero() && timeSinceLastCheck < 30*time.Second {
				continue
			}

			healthyNodes = append(healthyNodes, outbound)
		}
	}

	// Check if group exists
	if !groupExists {
		return nil, fmt.Errorf("%w: '@%s'", ErrGroupNotFound, groupName)
	}

	// Check if there are any healthy nodes
	// Requirements: 3.3 - return error when all nodes are unhealthy
	if len(healthyNodes) == 0 {
		if len(excludeNodes) > 0 {
			return nil, fmt.Errorf("%w: all nodes in group '@%s' have been tried", ErrAllFailoversFailed, groupName)
		}
		return nil, fmt.Errorf("%w: in group '@%s'", ErrNoHealthyNodes, groupName)
	}

	// Use load balancer to select a node
	selected := loadBalancer.Select(healthyNodes, strategy, sortBy, groupName)
	if selected == nil {
		return nil, fmt.Errorf("%w: in group '@%s'", ErrNoHealthyNodes, groupName)
	}

	return selected.Clone(), nil
}

// selectSingleNode selects a specific node by name.
// Must be called with read lock held.
func (m *outboundManagerImpl) selectSingleNode(nodeName string, excludeNodes []string) (*config.ProxyOutbound, error) {
	// Check if node is in exclusion list (for failover scenarios)
	for _, excluded := range excludeNodes {
		if excluded == nodeName {
			return nil, fmt.Errorf("%w: '%s' has already been tried", ErrAllFailoversFailed, nodeName)
		}
	}

	// Find the node
	outbound, exists := m.outbounds[nodeName]
	if !exists {
		return nil, fmt.Errorf("%w: '%s'", ErrOutboundNotFound, nodeName)
	}

	// Check if node is enabled
	if !outbound.Enabled {
		return nil, fmt.Errorf("outbound '%s' is disabled", nodeName)
	}

	// Check if node is healthy
	// Requirements: 3.4 - exclude unhealthy nodes from selection
	if !outbound.GetHealthy() && outbound.GetLastError() != "" {
		return nil, fmt.Errorf("%w: '%s' - %s", ErrOutboundUnhealthy, nodeName, outbound.GetLastError())
	}

	return outbound.Clone(), nil
}
