// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/singboxcore"
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
	metadataLikeOutboundNamePattern = regexp.MustCompile(`(?i)^(剩余流量|套餐到期|到期时间|过期时间|流量重置|订阅信息|订阅更新时间|更新时间|使用说明|官网|公告|客服|telegram|tg|email|邮箱)\s*[：:]`)
)

// DirectNodeName is the reserved token meaning "connect directly, no proxy".
//
// It has two supported positions:
//  1. As the single / only value of proxy_outbound (e.g. "" or "direct") —
//     handled by ServerConfig.IsDirectConnection() / ProxyPortConfig.IsDirectConnection().
//  2. As one of several comma-separated tokens in a multi-node selector
//     (e.g. "direct,HK-01,HK-02") — handled by selectFromNodeList below, which
//     synthesizes a virtual healthy outbound so load balancing / failover
//     can include "try direct" as a candidate alongside real proxy outbounds.
//
// Downstream dial paths MUST check selectedOutbound.Name == DirectNodeName
// after selection and translate that into a plain net.Dialer / net.DialUDP
// call instead of routing through the outbound manager (there is no
// singbox outbound named "direct" — the sentinel only exists to drive
// selection).
const DirectNodeName = "direct"

// IsDirectSelection reports whether the selection result from one of the
// Select* methods means "use a plain direct dial". Callers should gate their
// dial path on this so mixed lists like "direct,HK-01" work.
func IsDirectSelection(outbound *config.ProxyOutbound) bool {
	return outbound != nil && outbound.Name == DirectNodeName
}

func isMetadataLikeOutboundName(name string) bool {
	return metadataLikeOutboundNamePattern.MatchString(strings.TrimSpace(name))
}

// newDirectVirtualOutbound returns the sentinel outbound used to represent
// the "direct" token inside a multi-node list during selection.
func newDirectVirtualOutbound() *config.ProxyOutbound {
	cfg := &config.ProxyOutbound{
		Name:    DirectNodeName,
		Type:    "direct",
		Enabled: true,
	}
	cfg.SetHealthy(true)
	return cfg
}

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

	serverNodeLatencyCacheTTL         = 30 * time.Minute
	serverNodeLatencyHistoryRetention = 5 * 24 * time.Hour
	serverNodeLatencyHistoryLimit     = 1000
	serverNodeLatencyHistoryMinGap    = 10 * time.Minute
)

// HealthStatus represents the health status of a proxy outbound.
type HealthStatus struct {
	Healthy        bool          `json:"healthy"`
	Latency        time.Duration `json:"latency"`
	LastCheck      time.Time     `json:"last_check"`
	ConnCount      int64         `json:"conn_count"`
	LastError      string        `json:"last_error,omitempty"`
	BytesUp        int64         `json:"bytes_up"`
	BytesDown      int64         `json:"bytes_down"`
	LastActive     time.Time     `json:"last_active,omitempty"`
	ActiveDuration time.Duration `json:"active_duration"`
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
	SetOutboundLatency(name, sortBy string, latencyMs int64)
	GetOutboundLatencyHistory(name, sortBy string) []OutboundLatencySample

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

	// GetServerNodeLatencyHistory returns cached latency history for a specific server and node.
	// Returns nil if missing or expired.
	GetServerNodeLatencyHistory(serverID, nodeName, sortBy string) []ServerNodeLatencySample

	// SelectOutboundWithFailoverForServer selects a healthy proxy outbound with per-server latency preference.
	// If serverID is empty, it behaves like SelectOutboundWithFailover.
	SelectOutboundWithFailoverForServer(serverID, groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error)

	// GetServerSelectedNode returns the currently pinned/selected node for a server.
	// Returns ("", false) if no node is pinned.
	GetServerSelectedNode(serverID string) (string, bool)

	// SetServerSelectedNode pins a specific node as the active node for a server.
	// Set nodeName="" to clear.
	SetServerSelectedNode(serverID, nodeName string)

	// GetBestNodeForServer determines the best node for a server based on cached latency.
	// Returns the best node name and its latency, or ("", 0) if no data.
	GetBestNodeForServer(serverID, groupOrName, sortBy string) (string, int64)
}

// ServerConfigUpdater is an interface for updating server configurations.
// This is used for cascade updates when deleting outbounds.
type ServerConfigUpdater interface {
	// GetAllServers returns all server configurations.
	GetAllServers() []*config.ServerConfig
	// UpdateServerProxyOutbound updates the proxy_outbound field for a server.
	UpdateServerProxyOutbound(serverID string, proxyOutbound string) error
}

type serverConfigGetter interface {
	GetServer(serverID string) (*config.ServerConfig, bool)
}

// outboundManagerImpl is the in-memory implementation of OutboundManager.
type outboundManagerImpl struct {
	mu                  sync.RWMutex
	globalConfig        *config.GlobalConfig
	outbounds           map[string]*config.ProxyOutbound
	singboxOutbounds    map[string]singboxcore.UDPOutbound
	singboxLastUsed     map[string]time.Time // Track last usage time for idle cleanup
	singboxInitGroup    singleflight.Group
	singboxFactory      singboxcore.Factory
	serverConfigUpdater ServerConfigUpdater
	cleanupCtx          context.Context
	cleanupCancel       context.CancelFunc
	serverNodeLatencyMu sync.RWMutex
	serverNodeLatency   map[serverNodeLatencyKey]serverNodeLatencyValue
	serverNodeHistory   map[serverNodeLatencyKey]*serverNodeLatencyHistory
	outboundLatencyMu   sync.RWMutex
	outboundHistory     map[outboundLatencyKey]*outboundLatencyHistory
	serverSelectedMu    sync.RWMutex
	serverSelectedNode  map[string]string // serverID -> pinned node name
}

type ServerNodeLatencySample struct {
	Timestamp int64 `json:"timestamp"`
	LatencyMs int64 `json:"latency_ms"`
	OK        bool  `json:"ok"`
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

type serverNodeLatencyHistory struct {
	samples []ServerNodeLatencySample
}

func (h *serverNodeLatencyHistory) append(sample ServerNodeLatencySample, retention time.Duration, minIntervalMs int64, storageLimit int) {
	if h == nil {
		return
	}
	cutoff := time.UnixMilli(sample.Timestamp).Add(-retention).UnixMilli()
	filtered := h.filtered(cutoff)
	if len(filtered) > 0 && minIntervalMs > 0 {
		lastIndex := len(filtered) - 1
		if sample.Timestamp-filtered[lastIndex].Timestamp < minIntervalMs {
			filtered[lastIndex] = sample
			h.samples = filtered
			return
		}
	}
	filtered = append(filtered, sample)
	if storageLimit > 0 && len(filtered) > storageLimit {
		filtered = filtered[len(filtered)-storageLimit:]
	}
	h.samples = filtered
}

func (h *serverNodeLatencyHistory) filtered(cutoff int64) []ServerNodeLatencySample {
	if h == nil || len(h.samples) == 0 {
		return nil
	}
	result := make([]ServerNodeLatencySample, 0, len(h.samples))
	for _, sample := range h.samples {
		if sample.Timestamp < cutoff {
			continue
		}
		result = append(result, sample)
	}
	return result
}

func (h *serverNodeLatencyHistory) compact(cutoff int64) bool {
	if h == nil || len(h.samples) == 0 {
		return true
	}
	filtered := h.filtered(cutoff)
	if len(filtered) == 0 {
		h.samples = nil
		return true
	}
	h.samples = filtered
	return false
}

// NewOutboundManager creates a new OutboundManager instance.
// The serverConfigUpdater parameter is optional and used for cascade updates on delete.
func NewOutboundManager(serverConfigUpdater ServerConfigUpdater) OutboundManager {
	return NewOutboundManagerWithConfig(serverConfigUpdater, nil)
}

func NewOutboundManagerWithConfig(serverConfigUpdater ServerConfigUpdater, globalConfig *config.GlobalConfig) OutboundManager {
	return NewOutboundManagerWithSingboxFactoryAndConfig(serverConfigUpdater, globalConfig, nil)
}

// NewOutboundManagerWithSingboxFactory creates an OutboundManager with an injectable sing-box factory.
func NewOutboundManagerWithSingboxFactory(serverConfigUpdater ServerConfigUpdater, factory singboxcore.Factory) OutboundManager {
	return NewOutboundManagerWithSingboxFactoryAndConfig(serverConfigUpdater, nil, factory)
}

func NewOutboundManagerWithSingboxFactoryAndConfig(serverConfigUpdater ServerConfigUpdater, globalConfig *config.GlobalConfig, factory singboxcore.Factory) OutboundManager {
	if factory == nil {
		factory = NewSingboxCoreFactory()
	}
	return &outboundManagerImpl{
		globalConfig:        globalConfig,
		outbounds:           make(map[string]*config.ProxyOutbound),
		singboxOutbounds:    make(map[string]singboxcore.UDPOutbound),
		singboxLastUsed:     make(map[string]time.Time),
		singboxFactory:      factory,
		serverConfigUpdater: serverConfigUpdater,
		serverNodeLatency:   make(map[serverNodeLatencyKey]serverNodeLatencyValue),
		serverNodeHistory:   make(map[serverNodeLatencyKey]*serverNodeLatencyHistory),
		outboundHistory:     make(map[outboundLatencyKey]*outboundLatencyHistory),
		serverSelectedNode:  make(map[string]string),
	}
}

func (m *outboundManagerImpl) latencyHistoryRetention() time.Duration {
	if m == nil || m.globalConfig == nil {
		return serverNodeLatencyHistoryRetention
	}
	return time.Duration(m.globalConfig.GetLatencyHistoryRetentionDays()) * 24 * time.Hour
}

func (m *outboundManagerImpl) latencyHistoryStorageLimit() int {
	if m == nil || m.globalConfig == nil {
		return serverNodeLatencyHistoryLimit
	}
	return m.globalConfig.GetLatencyHistoryStorageLimit()
}

func (m *outboundManagerImpl) latencyHistoryMinIntervalMs() int64 {
	if m == nil || m.globalConfig == nil {
		return 0
	}
	return int64(time.Duration(m.globalConfig.GetLatencyHistoryMinIntervalMinutes()) * time.Minute / time.Millisecond)
}

func coalesceLatencyHistoryMinIntervalMs(defaultMinGapMs, overrideMs int64) int64 {
	if overrideMs <= 0 {
		return defaultMinGapMs
	}
	if defaultMinGapMs <= 0 || overrideMs < defaultMinGapMs {
		return overrideMs
	}
	return defaultMinGapMs
}

func (m *outboundManagerImpl) serverLatencyHistoryMinIntervalMs(serverID string) int64 {
	baseMinIntervalMs := m.latencyHistoryMinIntervalMs()
	if m == nil || m.serverConfigUpdater == nil {
		return baseMinIntervalMs
	}
	serverID = strings.TrimSpace(serverID)
	if serverID == "" || strings.HasPrefix(serverID, "proxy-port:") {
		return baseMinIntervalMs
	}
	getter, ok := m.serverConfigUpdater.(serverConfigGetter)
	if !ok {
		return baseMinIntervalMs
	}
	serverCfg, exists := getter.GetServer(serverID)
	if !exists || serverCfg == nil || !serverCfg.IsAutoPingEnabled() {
		return baseMinIntervalMs
	}
	intervalMinutes := serverCfg.AutoPingIntervalMinutes
	if intervalMinutes <= 0 && m.globalConfig != nil {
		intervalMinutes = m.globalConfig.GetServerAutoPingIntervalMinutesDefault()
	}
	if intervalMinutes <= 0 {
		return baseMinIntervalMs
	}
	overrideMs := int64(time.Duration(intervalMinutes) * time.Minute / time.Millisecond)
	return coalesceLatencyHistoryMinIntervalMs(baseMinIntervalMs, overrideMs)
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

func outboundSupportsUDP(outbound *config.ProxyOutbound) bool {
	if outbound == nil {
		return false
	}
	switch outbound.Type {
	case config.ProtocolHTTP:
		return false
	default:
		return true
	}
}

func outboundSupportsSort(outbound *config.ProxyOutbound, sortBy string) bool {
	if outbound == nil {
		return false
	}
	if normalizeSortBy(sortBy) == config.LoadBalanceSortUDP {
		return outboundSupportsUDP(outbound)
	}
	return true
}

func (m *outboundManagerImpl) SetServerNodeLatency(serverID, nodeName, sortBy string, latencyMs int64) {
	m.setServerNodeLatencyAt(serverID, nodeName, sortBy, latencyMs, time.Now())
}

func (m *outboundManagerImpl) setServerNodeLatencyAt(serverID, nodeName, sortBy string, latencyMs int64, recordedAt time.Time) {
	serverID = strings.TrimSpace(serverID)
	nodeName = strings.TrimSpace(nodeName)
	if serverID == "" || nodeName == "" {
		return
	}
	sortBy = normalizeSortBy(sortBy)
	if recordedAt.IsZero() {
		recordedAt = time.Now()
	}

	key := serverNodeLatencyKey{serverID: serverID, nodeName: nodeName, sortBy: sortBy}
	retention := m.latencyHistoryRetention()
	minIntervalMs := m.serverLatencyHistoryMinIntervalMs(serverID)
	storageLimit := m.latencyHistoryStorageLimit()

	m.serverNodeLatencyMu.Lock()
	m.serverNodeLatency[key] = serverNodeLatencyValue{latencyMs: latencyMs, updatedAt: recordedAt, updatedAtN: recordedAt.UnixNano()}
	history := m.serverNodeHistory[key]
	if history == nil {
		history = &serverNodeLatencyHistory{}
		m.serverNodeHistory[key] = history
	}
	history.append(ServerNodeLatencySample{Timestamp: recordedAt.UnixMilli(), LatencyMs: latencyMs, OK: latencyMs > 0}, retention, minIntervalMs, storageLimit)
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

func (m *outboundManagerImpl) GetServerNodeLatencyHistory(serverID, nodeName, sortBy string) []ServerNodeLatencySample {
	serverID = strings.TrimSpace(serverID)
	nodeName = strings.TrimSpace(nodeName)
	if serverID == "" || nodeName == "" {
		return nil
	}
	sortBy = normalizeSortBy(sortBy)

	key := serverNodeLatencyKey{serverID: serverID, nodeName: nodeName, sortBy: sortBy}
	cutoff := time.Now().Add(-m.latencyHistoryRetention()).UnixMilli()

	m.serverNodeLatencyMu.Lock()
	defer m.serverNodeLatencyMu.Unlock()

	history := m.serverNodeHistory[key]
	if history == nil {
		return nil
	}
	samples := history.filtered(cutoff)
	if len(samples) == 0 {
		delete(m.serverNodeHistory, key)
		return nil
	}
	if history.compact(cutoff) {
		delete(m.serverNodeHistory, key)
	}
	return samples
}

func (m *outboundManagerImpl) cleanupExpiredServerNodeLatencyHistory(now time.Time) {
	cutoff := now.Add(-m.latencyHistoryRetention()).UnixMilli()
	m.serverNodeLatencyMu.Lock()
	defer m.serverNodeLatencyMu.Unlock()
	for key, history := range m.serverNodeHistory {
		if history == nil || history.compact(cutoff) {
			delete(m.serverNodeHistory, key)
		}
	}
}

func (m *outboundManagerImpl) GetServerSelectedNode(serverID string) (string, bool) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return "", false
	}
	m.serverSelectedMu.RLock()
	node, ok := m.serverSelectedNode[serverID]
	m.serverSelectedMu.RUnlock()
	if !ok || node == "" {
		return "", false
	}
	return node, true
}

func (m *outboundManagerImpl) SetServerSelectedNode(serverID, nodeName string) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return
	}
	m.serverSelectedMu.Lock()
	if nodeName == "" {
		delete(m.serverSelectedNode, serverID)
	} else {
		m.serverSelectedNode[serverID] = nodeName
	}
	m.serverSelectedMu.Unlock()
}

func (m *outboundManagerImpl) isSelectableOutboundLocked(outbound *config.ProxyOutbound) bool {
	if outbound == nil || isMetadataLikeOutboundName(outbound.Name) || !outbound.Enabled || outbound.IsAutoSelectBlocked() {
		return false
	}
	lastCheck := outbound.GetLastCheck()
	hasError := outbound.GetLastError() != ""
	isHealthy := outbound.GetHealthy()
	if !isHealthy && hasError && !lastCheck.IsZero() && time.Since(lastCheck) < 30*time.Second {
		return false
	}
	return true
}

func (m *outboundManagerImpl) GetBestNodeForServer(serverID, groupOrName, sortBy string) (string, int64) {
	serverID = strings.TrimSpace(serverID)
	sortBy = normalizeSortBy(sortBy)
	if serverID == "" || groupOrName == "" {
		return "", 0
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var nodeNames []string
	if strings.HasPrefix(groupOrName, "@") {
		groupName := strings.TrimPrefix(groupOrName, "@")
		for _, o := range m.outbounds {
			if m.isSelectableOutboundLocked(o) && outboundSupportsSort(o, sortBy) && (o.Group == groupName) {
				nodeNames = append(nodeNames, o.Name)
			}
		}
	} else if strings.Contains(groupOrName, ",") {
		for _, n := range strings.Split(groupOrName, ",") {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			if n == DirectNodeName {
				nodeNames = append(nodeNames, n)
				continue
			}
			if outbound, exists := m.outbounds[n]; exists && m.isSelectableOutboundLocked(outbound) && outboundSupportsSort(outbound, sortBy) {
				nodeNames = append(nodeNames, n)
			}
		}
	} else {
		if groupOrName == DirectNodeName {
			if latency, ok := m.GetServerNodeLatency(serverID, DirectNodeName, sortBy); ok {
				return DirectNodeName, latency
			}
			return "", 0
		}
		if outbound, exists := m.outbounds[groupOrName]; exists && m.isSelectableOutboundLocked(outbound) && outboundSupportsSort(outbound, sortBy) {
			return groupOrName, 0
		}
		return "", 0
	}

	var bestName string
	var bestLatency int64 = -1
	for _, name := range nodeNames {
		lat, ok := m.GetServerNodeLatency(serverID, name, sortBy)
		if !ok || lat <= 0 {
			continue
		}
		if bestLatency < 0 || lat < bestLatency {
			bestLatency = lat
			bestName = name
		}
	}
	if bestName == "" {
		return "", 0
	}
	return bestName, bestLatency
}

func (m *outboundManagerImpl) selectLeastLatencyForServer(serverID string, nodes []*config.ProxyOutbound, sortBy string) *config.ProxyOutbound {
	// Prefer per-server cache. If none are available, fall back to the old global latency selection.
	var selected *config.ProxyOutbound
	var minLatency int64 = -1
	var hasCached bool

	for _, node := range nodes {
		latency, ok := m.GetServerNodeLatency(serverID, node.Name, sortBy)
		if !ok || latency <= 0 {
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

func selectorIncludesSelection(groupOrName, nodeName, groupName string) bool {
	groupOrName = strings.TrimSpace(groupOrName)
	nodeName = strings.TrimSpace(nodeName)
	groupName = strings.TrimSpace(groupName)
	if groupOrName == "" || nodeName == "" {
		return false
	}
	if strings.HasPrefix(groupOrName, "@") {
		return groupName == strings.TrimPrefix(groupOrName, "@")
	}
	if strings.Contains(groupOrName, ",") {
		for _, entry := range strings.Split(groupOrName, ",") {
			if strings.TrimSpace(entry) == nodeName {
				return true
			}
		}
		return false
	}
	return groupOrName == nodeName
}

func selectorIncludesOutbound(groupOrName string, outbound *config.ProxyOutbound) bool {
	if outbound == nil {
		return false
	}
	return selectorIncludesSelection(groupOrName, outbound.Name, outbound.Group)
}

func shouldPreferBestNodeOverPinned(pinnedLatency, bestLatency int64) bool {
	if bestLatency <= 0 {
		return false
	}
	if pinnedLatency <= 0 {
		return true
	}
	improvement := pinnedLatency - bestLatency
	if improvement <= 0 {
		return false
	}
	absoluteGainOK := improvement >= autoSwitchMinLatencyGainMs
	relativeGainOK := float64(improvement) >= float64(pinnedLatency)*autoSwitchMinRelativeGain
	return absoluteGainOK || relativeGainOK
}

func (m *outboundManagerImpl) SelectOutboundWithFailoverForServer(serverID, groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	serverID = strings.TrimSpace(serverID)
	strategy = strings.TrimSpace(strategy)
	sortBy = normalizeSortBy(sortBy)

	// Empty serverID => preserve old behavior.
	if serverID == "" {
		return m.SelectOutboundWithFailover(groupOrName, strategy, sortBy, excludeNodes)
	}
	bestName, bestLatency := "", int64(0)
	if strategy == config.LoadBalanceLeastLatency {
		bestName, bestLatency = m.GetBestNodeForServer(serverID, groupOrName, sortBy)
	}

	// If a pinned node is set and not excluded, prefer it.
	if pinnedName, ok := m.GetServerSelectedNode(serverID); ok {
		excluded := false
		for _, ex := range excludeNodes {
			if ex == pinnedName {
				excluded = true
				break
			}
		}
		if !excluded {
			if pinnedName == DirectNodeName && selectorIncludesSelection(groupOrName, DirectNodeName, "") {
				usePinned := true
				if strategy == config.LoadBalanceLeastLatency && bestName != "" && bestName != pinnedName {
					pinnedLatency, ok := m.GetServerNodeLatency(serverID, pinnedName, sortBy)
					if !ok || shouldPreferBestNodeOverPinned(pinnedLatency, bestLatency) {
						usePinned = false
					}
				}
				if usePinned {
					return newDirectVirtualOutbound(), nil
				}
			}
			m.mu.RLock()
			if o, exists := m.outbounds[pinnedName]; exists && o != nil && o.Enabled && !o.IsAutoSelectBlocked() && outboundSupportsSort(o, sortBy) && selectorIncludesOutbound(groupOrName, o) {
				lastCheck := o.GetLastCheck()
				hasError := o.GetLastError() != ""
				isHealthy := o.GetHealthy()
				if isHealthy || lastCheck.IsZero() || !hasError || time.Since(lastCheck) >= 30*time.Second {
					usePinned := true
					if strategy == config.LoadBalanceLeastLatency && bestName != "" && bestName != pinnedName {
						pinnedLatency, ok := m.GetServerNodeLatency(serverID, pinnedName, sortBy)
						if !ok || shouldPreferBestNodeOverPinned(pinnedLatency, bestLatency) {
							usePinned = false
						}
					}
					if usePinned {
						selected := o.Clone()
						m.mu.RUnlock()
						return selected, nil
					}
				}
			}
			m.mu.RUnlock()
		}
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

		// Reserved token "direct" means "connect without any proxy". We inject
		// a synthetic virtual outbound into the candidate pool so load balancing
		// and failover treat it as a first-class option alongside real nodes.
		// Downstream dial paths check IsDirectSelection() to do a plain dial.
		if nodeName == DirectNodeName {
			healthyNodes = append(healthyNodes, newDirectVirtualOutbound())
			continue
		}

		outbound, exists := m.outbounds[nodeName]
		if !exists {
			notFoundNodes = append(notFoundNodes, nodeName)
			continue
		}
		if !outboundSupportsSort(outbound, sortBy) {
			continue
		}
		if !m.isSelectableOutboundLocked(outbound) {
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
			if !outboundSupportsSort(outbound, sortBy) {
				continue
			}
			if !m.isSelectableOutboundLocked(outbound) {
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

func (m *outboundManagerImpl) DeleteOutboundNoCascade(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.outbounds[name]; !exists {
		return ErrOutboundNotFound
	}

	if singboxOutbound, ok := m.singboxOutbounds[name]; ok {
		singboxOutbound.Close()
		delete(m.singboxOutbounds, name)
		delete(m.singboxLastUsed, name)
	}

	delete(m.outbounds, name)
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
		Healthy:        outbound.GetHealthy(),
		Latency:        outbound.GetLatency(),
		LastCheck:      outbound.GetLastCheck(),
		ConnCount:      outbound.GetConnCount(),
		LastError:      outbound.GetLastError(),
		BytesUp:        outbound.GetBytesUp(),
		BytesDown:      outbound.GetBytesDown(),
		LastActive:     outbound.GetLastActive(),
		ActiveDuration: outbound.GetActiveDuration(),
	}
}

// CheckHealth performs a health check on the specified outbound by attempting
// to establish a connection and measuring the latency.
// Requirements: 4.1, 4.2, 4.4
func (m *outboundManagerImpl) CheckHealth(ctx context.Context, name string) error {
	m.mu.RLock()
	cfg, exists := m.outbounds[name]
	if !exists {
		m.mu.RUnlock()
		return ErrOutboundNotFound
	}
	m.mu.RUnlock()
	if cfg == nil || isMetadataLikeOutboundName(cfg.Name) {
		return ErrOutboundNotFound
	}

	startTime := time.Now()
	testDestination := "1.1.1.1:443"
	checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	dialer, err := m.singboxFactory.CreateDialer(checkCtx, cfg)
	if err == nil {
		defer dialer.Close()
	}

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

	conn, err := dialer.DialContext(checkCtx, "tcp", testDestination)
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
	c.SetLastCheck(time.Now())
	return nil
}

func (m *outboundManagerImpl) prepareDialPacketConn(outboundName string) error {
	m.mu.RLock()
	cfg, exists := m.outbounds[outboundName]
	if !exists {
		m.mu.RUnlock()
		return ErrOutboundNotFound
	}

	if !cfg.Enabled {
		m.mu.RUnlock()
		return fmt.Errorf("outbound %s is disabled", outboundName)
	}
	if !outboundSupportsUDP(cfg) {
		m.mu.RUnlock()
		return fmt.Errorf("outbound %s does not support UDP packet relay", outboundName)
	}

	healthy := cfg.GetHealthy()
	lastErr := cfg.GetLastError()
	lastCheck := cfg.GetLastCheck()
	m.mu.RUnlock()

	if !healthy && lastErr != "" {
		if time.Since(lastCheck) < 30*time.Second {
			return fmt.Errorf("%w: %s - %s", ErrOutboundUnhealthy, outboundName, lastErr)
		}
		if _, err := m.recreateSingboxOutbound(outboundName); err != nil {
			return fmt.Errorf("%w: %s - failed to recreate: %v", ErrOutboundUnhealthy, outboundName, err)
		}
	}

	return nil
}

// DialPacketConn creates a UDP PacketConn through the specified outbound.
// Implements retry logic with exponential backoff (max 3 attempts).
// Fast-fails for unhealthy nodes without retrying.
// Requirements: 3.1, 3.3, 3.4, 6.1, 6.2, 6.4
func (m *outboundManagerImpl) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	if err := m.prepareDialPacketConn(outboundName); err != nil {
		return nil, err
	}

	// Attempt connection with retry logic
	// Requirements: 6.1, 6.2
	return m.dialWithRetry(ctx, outboundName, destination)
}

func (m *outboundManagerImpl) DialPacketConnNoRetry(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	if err := m.prepareDialPacketConn(outboundName); err != nil {
		return nil, err
	}
	return m.dialPacketConnOnce(ctx, outboundName, destination)
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
	m.mu.RLock()
	// Get the outbound configuration
	cfg, exists := m.outbounds[outboundName]
	m.mu.RUnlock()
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
			newOutbound, recreateErr := m.recreateSingboxOutbound(outboundName)
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
		cfg:        cfg,
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
func (m *outboundManagerImpl) getOrCreateSingboxOutbound(cfg *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
	if cfg == nil {
		return nil, ErrOutboundNotFound
	}

	m.mu.RLock()
	if existing, ok := m.singboxOutbounds[cfg.Name]; ok {
		m.mu.RUnlock()
		m.mu.Lock()
		if current, stillOK := m.singboxOutbounds[cfg.Name]; stillOK {
			m.singboxLastUsed[cfg.Name] = time.Now()
			existing = current
		} else {
			existing = nil
		}
		m.mu.Unlock()
		if existing != nil {
			return existing, nil
		}
	} else {
		m.mu.RUnlock()
	}

	result, err, _ := m.singboxInitGroup.Do(cfg.Name, func() (interface{}, error) {
		m.mu.RLock()
		if existing, ok := m.singboxOutbounds[cfg.Name]; ok {
			m.mu.RUnlock()
			m.mu.Lock()
			if current, stillOK := m.singboxOutbounds[cfg.Name]; stillOK {
				m.singboxLastUsed[cfg.Name] = time.Now()
				existing = current
			} else {
				existing = nil
			}
			m.mu.Unlock()
			if existing != nil {
				return existing, nil
			}
		} else {
			m.mu.RUnlock()
		}
		m.mu.RLock()
		currentCfg, exists := m.outbounds[cfg.Name]
		m.mu.RUnlock()
		if !exists || currentCfg == nil {
			return nil, ErrOutboundNotFound
		}

		singboxOutbound, createErr := m.singboxFactory.CreateUDPOutbound(context.Background(), currentCfg.Clone())
		if createErr != nil {
			return nil, createErr
		}

		m.mu.Lock()
		if existing, ok := m.singboxOutbounds[cfg.Name]; ok {
			m.singboxLastUsed[cfg.Name] = time.Now()
			m.mu.Unlock()
			_ = singboxOutbound.Close()
			return existing, nil
		}
		m.singboxOutbounds[cfg.Name] = singboxOutbound
		m.singboxLastUsed[cfg.Name] = time.Now()
		m.mu.Unlock()
		return singboxOutbound, nil
	})
	if err != nil {
		return nil, err
	}
	singboxOutbound, ok := result.(singboxcore.UDPOutbound)
	if !ok || singboxOutbound == nil {
		return nil, fmt.Errorf("failed to initialize sing-box outbound for %s", cfg.Name)
	}
	return singboxOutbound, nil
}

// recreateSingboxOutbound closes and recreates a sing-box outbound.
// This is useful for protocols like Hysteria2 that may need reconnection.
func (m *outboundManagerImpl) recreateSingboxOutbound(name string) (singboxcore.UDPOutbound, error) {
	result, err, _ := m.singboxInitGroup.Do(name, func() (interface{}, error) {
		m.mu.Lock()
		cfg, exists := m.outbounds[name]
		if !exists || cfg == nil {
			m.mu.Unlock()
			return nil, ErrOutboundNotFound
		}
		cfgCopy := cfg.Clone()
		existing := m.singboxOutbounds[name]
		delete(m.singboxOutbounds, name)
		delete(m.singboxLastUsed, name)
		m.mu.Unlock()

		if existing != nil {
			_ = existing.Close()
		}

		singboxOutbound, createErr := m.singboxFactory.CreateUDPOutbound(context.Background(), cfgCopy)
		if createErr != nil {
			return nil, createErr
		}

		m.mu.Lock()
		if current, ok := m.singboxOutbounds[name]; ok {
			m.singboxLastUsed[name] = time.Now()
			m.mu.Unlock()
			_ = singboxOutbound.Close()
			return current, nil
		}
		m.singboxOutbounds[name] = singboxOutbound
		m.singboxLastUsed[name] = time.Now()
		m.mu.Unlock()
		return singboxOutbound, nil
	})
	if err != nil {
		return nil, err
	}
	singboxOutbound, ok := result.(singboxcore.UDPOutbound)
	if !ok || singboxOutbound == nil {
		return nil, fmt.Errorf("failed to recreate sing-box outbound for %s", name)
	}
	return singboxOutbound, nil
}

// trackedPacketConn wraps a PacketConn to track when it's closed.
type trackedPacketConn struct {
	net.PacketConn
	onClose   func()
	closeOnce sync.Once
	closeErr  error
	cfg       *config.ProxyOutbound
}

func (c *trackedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if n > 0 && c.cfg != nil {
		c.cfg.AddBytesDown(int64(n))
	}
	return n, addr, err
}

func (c *trackedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	if n > 0 && c.cfg != nil {
		c.cfg.AddBytesUp(int64(n))
	}
	return n, err
}

// Close closes the connection and calls the onClose callback.
func (c *trackedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.PacketConn.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
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
			m.cleanupExpiredServerNodeLatencyHistory(now)
			m.cleanupExpiredOutboundLatencyHistory(now)
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
	m.singboxOutbounds = make(map[string]singboxcore.UDPOutbound)
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
			singboxOutbound, err := m.singboxFactory.CreateUDPOutbound(context.Background(), cfg)
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
		if outbound.Group == groupName && !isMetadataLikeOutboundName(outbound.Name) {
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
		if outbound.Group == groupName && !isMetadataLikeOutboundName(outbound.Name) {
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

		// Reserved token "direct" means "connect without any proxy". See
		// DirectNodeName doc on why this synthetic outbound is injected here.
		if nodeName == DirectNodeName {
			healthyNodes = append(healthyNodes, newDirectVirtualOutbound())
			continue
		}

		outbound, exists := m.outbounds[nodeName]
		if !exists {
			notFoundNodes = append(notFoundNodes, nodeName)
			continue
		}
		if !m.isSelectableOutboundLocked(outbound) {
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
			if !outboundSupportsSort(outbound, sortBy) {
				continue
			}
			if !m.isSelectableOutboundLocked(outbound) {
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
	if isMetadataLikeOutboundName(nodeName) {
		return nil, fmt.Errorf("%w: '%s'", ErrOutboundNotFound, nodeName)
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
