// Package config provides configuration management functionality.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LoadBalance strategy constants
const (
	LoadBalanceLeastLatency     = "least-latency"
	LoadBalanceRoundRobin       = "round-robin"
	LoadBalanceRandom           = "random"
	LoadBalanceLeastConnections = "least-connections"
)

// LoadBalanceSort type constants
const (
	LoadBalanceSortUDP  = "udp"
	LoadBalanceSortTCP  = "tcp"
	LoadBalanceSortHTTP = "http"
)

// ServerConfig represents a proxy target server configuration.
 type ServerConfig struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Target          string `json:"target"`
	Port            int    `json:"port"`
	ListenAddr      string `json:"listen_addr"`
	Protocol        string `json:"protocol"`
	Enabled         bool   `json:"enabled"`  // Whether to start the proxy listener
	Disabled        bool   `json:"disabled"` // Whether to reject new connections (when enabled=true)
	SendRealIP      bool   `json:"send_real_ip"`
	ResolveInterval int    `json:"resolve_interval"`  // seconds
	IdleTimeout     int    `json:"idle_timeout"`      // seconds
	BufferSize      int    `json:"buffer_size"`       // UDP buffer size, -1 for auto
	DisabledMessage string `json:"disabled_message"`  // Custom message when server is disabled
	CustomMOTD      string `json:"custom_motd"`       // Custom MOTD for ping response (empty = forward from remote)
	ProxyMode       string `json:"proxy_mode"`        // "transparent" (default) or "raknet" (full RakNet proxy)
	XboxAuthEnabled bool   `json:"xbox_auth_enabled"` // Enable Xbox Live authentication for remote connections
	XboxTokenPath   string `json:"xbox_token_path"`   // Custom token file path for Xbox Live tokens (optional)
	ProxyOutbound   string `json:"proxy_outbound"`    // Proxy outbound node name, "@group" for group selection, empty or "direct" for direct connection
	ShowRealLatency bool   `json:"show_real_latency"` // Show real latency through proxy in server list ping
	LoadBalance     string `json:"load_balance"`      // Load balance strategy: least-latency, round-robin, random, least-connections
	LoadBalanceSort string `json:"load_balance_sort"` // Latency sort type: udp, tcp, http
	ProtocolVersion int    `json:"protocol_version"`  // Override protocol version in Login packet (0 = don't modify)
	// Load balancing ping interval
	AutoPingEnabled         bool `json:"auto_ping_enabled"`
	AutoPingIntervalMinutes int  `json:"auto_ping_interval_minutes"` // Per-server ping interval in minutes
	resolvedIP             string
	lastResolved           time.Time
}

// GetProxyMode returns the proxy mode, defaulting to "transparent".
func (sc *ServerConfig) GetProxyMode() string {
	if sc.ProxyMode == "" {
		return "transparent"
	}
	return sc.ProxyMode
}

// Validate checks if all required fields are present and valid.
// Returns an error if any required field is missing or invalid.
func (sc *ServerConfig) Validate() error {
	if sc.ID == "" {
		return errors.New("id is required")
	}
	if sc.Name == "" {
		return errors.New("name is required")
	}
	if sc.Target == "" {
		return errors.New("target is required")
	}
	if sc.Port <= 0 || sc.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", sc.Port)
	}
	if sc.ListenAddr == "" {
		return errors.New("listen_addr is required")
	}
	if sc.Protocol == "" {
		return errors.New("protocol is required")
	}
	return nil
}

// GetTargetAddr returns the resolved target address with port.
func (sc *ServerConfig) GetTargetAddr() string {
	ip := sc.resolvedIP
	if ip == "" {
		ip = sc.Target
	}
	return fmt.Sprintf("%s:%d", ip, sc.Port)
}

// SetResolvedIP sets the resolved IP address.
func (sc *ServerConfig) SetResolvedIP(ip string) {
	sc.resolvedIP = ip
	sc.lastResolved = time.Now()
}

// GetResolvedIP returns the resolved IP address.
func (sc *ServerConfig) GetResolvedIP() string {
	return sc.resolvedIP
}

// GetLastResolved returns the last DNS resolution time.
func (sc *ServerConfig) GetLastResolved() time.Time {
	return sc.lastResolved
}

// ToJSON serializes the server config to JSON.
func (sc *ServerConfig) ToJSON() ([]byte, error) {
	return json.Marshal(sc)
}

// ServerConfigFromJSON deserializes a server config from JSON.
func ServerConfigFromJSON(data []byte) (*ServerConfig, error) {
	var sc ServerConfig
	if err := json.Unmarshal(data, &sc); err != nil {
		return nil, err
	}
	return &sc, nil
}

// ServerConfigDTO is the data transfer object for server config API responses.
 type ServerConfigDTO struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Target          string `json:"target"`
	Port            int    `json:"port"`
	ListenAddr      string `json:"listen_addr"`
	Protocol        string `json:"protocol"`
	Enabled         bool   `json:"enabled"`
	Disabled        bool   `json:"disabled"` // Whether to reject new connections
	SendRealIP      bool   `json:"send_real_ip"`
	ResolveInterval int    `json:"resolve_interval"`
	IdleTimeout     int    `json:"idle_timeout"`
	BufferSize      int    `json:"buffer_size"`
	DisabledMessage string `json:"disabled_message"`
	CustomMOTD      string `json:"custom_motd"`
	ProxyMode       string `json:"proxy_mode"` // "transparent", "passthrough", or "raknet"
	XboxAuthEnabled bool   `json:"xbox_auth_enabled"`
	XboxTokenPath   string `json:"xbox_token_path"`
	ProxyOutbound   string `json:"proxy_outbound"`    // Proxy outbound node name or "@group" for group selection
	ShowRealLatency bool   `json:"show_real_latency"` // Show real latency through proxy
	LoadBalance     string `json:"load_balance"`      // Load balance strategy
	LoadBalanceSort string `json:"load_balance_sort"` // Latency sort type
	Status          string `json:"status"`            // running, stopped
	ActiveSessions  int    `json:"active_sessions"`
	// Load balancing ping interval
	AutoPingEnabled         bool `json:"auto_ping_enabled"`
	AutoPingIntervalMinutes int  `json:"auto_ping_interval_minutes"` // Per-server ping interval
}

// ToDTO converts the server config to a DTO for API responses.
func (sc *ServerConfig) ToDTO(status string, activeSessions int) ServerConfigDTO {
	return ServerConfigDTO{
		ID:              sc.ID,
		Name:            sc.Name,
		Target:          sc.Target,
		Port:            sc.Port,
		ListenAddr:      sc.ListenAddr,
		Protocol:        sc.Protocol,
		Enabled:         sc.Enabled,
		Disabled:        sc.Disabled,
		SendRealIP:      sc.SendRealIP,
		ResolveInterval: sc.ResolveInterval,
		IdleTimeout:     sc.IdleTimeout,
		BufferSize:      sc.BufferSize,
		DisabledMessage: sc.DisabledMessage,
		CustomMOTD:      sc.CustomMOTD,
		ProxyMode:       sc.ProxyMode,
		XboxAuthEnabled: sc.XboxAuthEnabled,
		XboxTokenPath:   sc.XboxTokenPath,
		ProxyOutbound:   sc.ProxyOutbound,
		ShowRealLatency: sc.ShowRealLatency,
		LoadBalance:     sc.LoadBalance,
		LoadBalanceSort: sc.LoadBalanceSort,
		Status:          status,
		ActiveSessions:  activeSessions,
		AutoPingEnabled:         sc.AutoPingEnabled,
		AutoPingIntervalMinutes: sc.AutoPingIntervalMinutes,
	}
}

// IsShowRealLatency returns whether to show real latency through proxy.
func (sc *ServerConfig) IsShowRealLatency() bool {
	return sc.ShowRealLatency
}

// GetCustomMOTD returns the custom MOTD or empty string if not set.
func (sc *ServerConfig) GetCustomMOTD() string {
	return sc.CustomMOTD
}

// GetBufferSize returns the effective buffer size.
// Returns -1 for auto mode, otherwise the configured size.
func (sc *ServerConfig) GetBufferSize() int {
	if sc.BufferSize == 0 {
		return -1 // Default to auto
	}
	return sc.BufferSize
}

// GetDisabledMessage returns the custom disabled message or a default.
func (sc *ServerConfig) GetDisabledMessage() string {
	if sc.DisabledMessage == "" {
		return "Server is currently disabled"
	}
	return sc.DisabledMessage
}

// IsXboxAuthEnabled returns whether Xbox Live authentication is enabled for this server.
func (sc *ServerConfig) IsXboxAuthEnabled() bool {
	return sc.XboxAuthEnabled
}

// GetXboxTokenPath returns the Xbox token file path, or a default path if not set.
func (sc *ServerConfig) GetXboxTokenPath() string {
	if sc.XboxTokenPath == "" {
		return "xbox_token.json"
	}
	return sc.XboxTokenPath
}

// GetProxyOutbound returns the proxy outbound node name.
// Returns empty string for direct connection.
func (sc *ServerConfig) GetProxyOutbound() string {
	return sc.ProxyOutbound
}

// IsDirectConnection returns true if the server should use direct connection (no proxy).
// This is the case when ProxyOutbound is empty or "direct".
func (sc *ServerConfig) IsDirectConnection() bool {
	return sc.ProxyOutbound == "" || sc.ProxyOutbound == "direct"
}

// IsGroupSelection returns true if the proxy_outbound specifies a group (starts with "@").
func (sc *ServerConfig) IsGroupSelection() bool {
	return strings.HasPrefix(sc.ProxyOutbound, "@")
}

// IsMultiNodeSelection returns true if the proxy_outbound specifies multiple nodes (comma-separated).
func (sc *ServerConfig) IsMultiNodeSelection() bool {
	if sc.ProxyOutbound == "" || sc.ProxyOutbound == "direct" {
		return false
	}
	if strings.HasPrefix(sc.ProxyOutbound, "@") {
		return false
	}
	return strings.Contains(sc.ProxyOutbound, ",")
}

// GetNodeList returns the list of node names from proxy_outbound.
// Returns nil if not a multi-node selection.
func (sc *ServerConfig) GetNodeList() []string {
	if !sc.IsMultiNodeSelection() {
		return nil
	}
	nodes := strings.Split(sc.ProxyOutbound, ",")
	result := make([]string, 0, len(nodes))
	for _, node := range nodes {
		trimmed := strings.TrimSpace(node)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetGroupName returns the group name without the "@" prefix.
// Returns empty string if not a group selection.
func (sc *ServerConfig) GetGroupName() string {
	if sc.IsGroupSelection() {
		return strings.TrimPrefix(sc.ProxyOutbound, "@")
	}
	return ""
}

// GetProtocolVersion returns the protocol version override.
// Returns 0 if not set (don't modify).
func (sc *ServerConfig) GetProtocolVersion() int {
	return sc.ProtocolVersion
}

// GetLoadBalance returns the load balance strategy, defaulting to "least-latency".
func (sc *ServerConfig) GetLoadBalance() string {
	if sc.LoadBalance == "" {
		return LoadBalanceLeastLatency
	}
	return sc.LoadBalance
}

// GetLoadBalanceSort returns the latency sort type, defaulting to "udp".
func (sc *ServerConfig) GetLoadBalanceSort() string {
	if sc.LoadBalanceSort == "" {
		return LoadBalanceSortUDP
	}
	return sc.LoadBalanceSort
}

// DNSResolver handles DNS resolution for server targets.
type DNSResolver struct{}

// Resolve resolves a hostname to an IP address.
func (r *DNSResolver) Resolve(hostname string) (string, error) {
	// Check if it's already an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return hostname, nil
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %w", hostname, err)
	}

	// Prefer IPv4 addresses
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// Fall back to first IP if no IPv4 found
	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("no IP addresses found for %s", hostname)
}

// ConfigManager manages server configurations with hot reload support.
type ConfigManager struct {
	servers    map[string]*ServerConfig
	mu         sync.RWMutex
	configPath string
	watcher    *fsnotify.Watcher
	watcherMu  sync.Mutex
	resolver   *DNSResolver
	onChange   func() // callback when config changes
}

// NewConfigManager creates a new ConfigManager instance.
func NewConfigManager(configPath string) (*ConfigManager, error) {
	cm := &ConfigManager{
		servers:    make(map[string]*ServerConfig),
		configPath: configPath,
		resolver:   &DNSResolver{},
	}
	return cm, nil
}

// Load loads server configurations from the JSON file.
func (cm *ConfigManager) Load() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If config file doesn't exist, start with empty config.
			cm.servers = make(map[string]*ServerConfig)
			return nil
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var configs []*ServerConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate all configs before applying
	for _, config := range configs {
		if err := config.Validate(); err != nil {
			return fmt.Errorf("invalid config for server %s: %w", config.ID, err)
		}
	}

	// Clear existing and add new configs
	newServers := make(map[string]*ServerConfig)
	for _, config := range configs {
		// Resolve DNS for each server
		if ip, err := cm.resolver.Resolve(config.Target); err == nil {
			config.SetResolvedIP(ip)
		}
		newServers[config.ID] = config
	}

	cm.servers = newServers
	return nil
}

// Reload reloads configurations from the file.
func (cm *ConfigManager) Reload() error {
	if err := cm.Load(); err != nil {
		return err
	}
	if cm.onChange != nil {
		cm.onChange()
	}
	return nil
}

// GetServer returns a server configuration by ID.
func (cm *ConfigManager) GetServer(id string) (*ServerConfig, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	server, ok := cm.servers[id]
	if !ok {
		return nil, false
	}
	// Return a copy to prevent external modification
	copy := *server
	return &copy, true
}

// GetAllServers returns all server configurations.
func (cm *ConfigManager) GetAllServers() []*ServerConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	servers := make([]*ServerConfig, 0, len(cm.servers))
	for _, server := range cm.servers {
		copy := *server
		servers = append(servers, &copy)
	}
	return servers
}

// AddServer adds a new server configuration.
func (cm *ConfigManager) AddServer(config *ServerConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.servers[config.ID]; exists {
		return fmt.Errorf("server with ID %s already exists", config.ID)
	}

	// Resolve DNS
	if ip, err := cm.resolver.Resolve(config.Target); err == nil {
		config.SetResolvedIP(ip)
	}

	cm.servers[config.ID] = config
	return cm.saveToFile()
}

// UpdateServer updates an existing server configuration.
func (cm *ConfigManager) UpdateServer(id string, config *ServerConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.servers[id]; !exists {
		return fmt.Errorf("server with ID %s not found", id)
	}

	// Resolve DNS
	if ip, err := cm.resolver.Resolve(config.Target); err == nil {
		config.SetResolvedIP(ip)
	}

	// If ID changed, remove old entry
	if id != config.ID {
		delete(cm.servers, id)
	}
	cm.servers[config.ID] = config
	return cm.saveToFile()
}

// DeleteServer removes a server configuration.
func (cm *ConfigManager) DeleteServer(id string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, exists := cm.servers[id]; !exists {
		return fmt.Errorf("server with ID %s not found", id)
	}

	delete(cm.servers, id)
	return cm.saveToFile()
}

// UpdateServerProxyOutbound updates the proxy_outbound field for a server.
// This is used for cascade updates when deleting proxy outbounds.
// Requirements: 1.4
func (cm *ConfigManager) UpdateServerProxyOutbound(serverID string, proxyOutbound string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	server, exists := cm.servers[serverID]
	if !exists {
		return fmt.Errorf("server with ID %s not found", serverID)
	}

	server.ProxyOutbound = proxyOutbound
	if proxyOutbound == "" || proxyOutbound == "direct" {
		server.LoadBalance = ""
		server.LoadBalanceSort = ""
	}
	return cm.saveToFile()
}

// saveToFile persists the current configuration to the JSON file.
func (cm *ConfigManager) saveToFile() error {
	servers := make([]*ServerConfig, 0, len(cm.servers))
	for _, server := range cm.servers {
		servers = append(servers, server)
	}

	data, err := json.MarshalIndent(servers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// RefreshDNS re-resolves DNS for all servers that need refresh.
func (cm *ConfigManager) RefreshDNS() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now()
	for _, server := range cm.servers {
		if server.ResolveInterval <= 0 {
			continue
		}

		interval := time.Duration(server.ResolveInterval) * time.Second
		if now.Sub(server.GetLastResolved()) >= interval {
			if ip, err := cm.resolver.Resolve(server.Target); err == nil {
				server.SetResolvedIP(ip)
			}
		}
	}
}

// StartDNSRefresh starts a background goroutine to periodically refresh DNS.
func (cm *ConfigManager) StartDNSRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cm.RefreshDNS()
			}
		}
	}()
}

// SetOnChange sets a callback function to be called when configuration changes.
func (cm *ConfigManager) SetOnChange(callback func()) {
	cm.onChange = callback
}

// ServerCount returns the number of configured servers.
func (cm *ConfigManager) ServerCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.servers)
}

// GlobalConfig represents the global application configuration.
type GlobalConfig struct {
	MaxSessionRecords   int    `json:"max_session_records"`
	MaxAccessLogRecords int    `json:"max_access_log_records"`
	APIPort             int    `json:"api_port"`
	APIKey              string `json:"api_key"`        // Simple API key for dashboard access
	APIEntryPath        string `json:"api_entry_path"` // Entry path for web UI (e.g. /mcpe-admin)
	DatabasePath        string `json:"database_path"`
	DebugMode           bool   `json:"debug_mode"`          // Enable debug logging
	LogDir              string `json:"log_dir"`             // Directory for log files
	LogRetentionDays    int    `json:"log_retention_days"`  // Days to keep log files
	LogMaxSizeMB        int    `json:"log_max_size_mb"`     // Max size per log file in MB
	AuthVerifyEnabled   bool   `json:"auth_verify_enabled"` // Enable external auth verification
	AuthVerifyURL       string `json:"auth_verify_url"`     // External auth verification URL
	AuthCacheMinutes    int    `json:"auth_cache_minutes"`  // Cache duration for auth results
	ProxyPortsEnabled   bool   `json:"proxy_ports_enabled"` // Enable local proxy ports feature
	// PassthroughIdleTimeout is the global idle timeout (seconds) for passthrough online sessions.
	// 0 disables the override and falls back to per-server idle_timeout.
	PassthroughIdleTimeout int `json:"passthrough_idle_timeout"`
	// PublicPingTimeoutSeconds controls per-server ping timeout for /api/public/status.
	// 0 disables the timeout (wait indefinitely).
	PublicPingTimeoutSeconds int `json:"public_ping_timeout_seconds"`
}

// DefaultGlobalConfig returns a GlobalConfig with default values.
func DefaultGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		MaxSessionRecords:        100,
		MaxAccessLogRecords:      100,
		APIPort:                  8080,
		APIKey:                   "",
		APIEntryPath:             "/mcpe-admin",
		DatabasePath:             "data.db",
		LogDir:                   "logs",
		LogRetentionDays:         7,
		LogMaxSizeMB:             100,
		AuthVerifyEnabled:        false,
		AuthVerifyURL:            "",
		AuthCacheMinutes:         15,
		ProxyPortsEnabled:        true,
		PassthroughIdleTimeout:   30,
		PublicPingTimeoutSeconds: 5,
	}
}

// LoadGlobalConfig loads the global configuration from a JSON file.
// If the file doesn't exist, returns default configuration.
func LoadGlobalConfig(path string) (*GlobalConfig, error) {
	config := DefaultGlobalConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, fmt.Errorf("failed to read global config: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse global config: %w", err)
	}

	// Apply defaults for zero values
	if config.MaxSessionRecords <= 0 {
		config.MaxSessionRecords = 100
	}
	if config.MaxAccessLogRecords <= 0 {
		config.MaxAccessLogRecords = 100
	}
	if config.LogDir == "" {
		config.LogDir = "logs"
	}
	if config.LogRetentionDays <= 0 {
		config.LogRetentionDays = 7
	}
	if config.LogMaxSizeMB <= 0 {
		config.LogMaxSizeMB = 100
	}
	if config.AuthCacheMinutes <= 0 {
		config.AuthCacheMinutes = 15
	}

	return config, nil
}

// Save saves the global configuration to a JSON file.
func (gc *GlobalConfig) Save(path string) error {
	data, err := json.MarshalIndent(gc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal global config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write global config: %w", err)
	}

	return nil
}

// Validate validates the global configuration.
func (gc *GlobalConfig) Validate() error {
	if gc.MaxSessionRecords < 0 {
		return errors.New("max_session_records cannot be negative")
	}
	if gc.MaxAccessLogRecords < 0 {
		return errors.New("max_access_log_records cannot be negative")
	}
	if gc.APIPort < 0 || gc.APIPort > 65535 {
		return fmt.Errorf("api_port must be between 0 and 65535, got %d", gc.APIPort)
	}
	if gc.PassthroughIdleTimeout < 0 {
		return errors.New("passthrough_idle_timeout cannot be negative")
	}
	if gc.PublicPingTimeoutSeconds < 0 {
		return errors.New("public_ping_timeout_seconds cannot be negative")
	}
	return nil
}

// Watch starts watching the configuration file for changes.
// When changes are detected, it automatically reloads the configuration.
func (cm *ConfigManager) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	cm.watcherMu.Lock()
	cm.watcher = watcher
	cm.watcherMu.Unlock()

	// Ensure the config file exists before watching (same behavior as other config managers).
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(cm.configPath), 0755); err != nil {
			cm.closeWatcher()
			return fmt.Errorf("failed to create config dir: %w", err)
		}
		if err := os.WriteFile(cm.configPath, []byte("[]"), 0644); err != nil {
			cm.closeWatcher()
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	// Add the config file to the watcher
	if err := watcher.Add(cm.configPath); err != nil {
		cm.closeWatcher()
		return fmt.Errorf("failed to watch config file: %w", err)
	}

	go func() {
		defer cm.closeWatcher()

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Reload on write or create events
				if event.Op&fsnotify.Write == fsnotify.Write ||
					event.Op&fsnotify.Create == fsnotify.Create {
					// Small delay to ensure file write is complete
					time.Sleep(100 * time.Millisecond)
					if err := cm.Reload(); err != nil {
						// Log error but continue watching
						// In production, this would use a proper logger
						fmt.Printf("config reload error: %v\n", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				// Log error but continue watching
				fmt.Printf("config watcher error: %v\n", err)
			}
		}
	}()

	return nil
}

// StopWatch stops watching the configuration file.
func (cm *ConfigManager) StopWatch() {
	cm.closeWatcher()
}

// IsWatching returns true if the config manager is watching for file changes.
func (cm *ConfigManager) IsWatching() bool {
	cm.watcherMu.Lock()
	defer cm.watcherMu.Unlock()
	return cm.watcher != nil
}

func (cm *ConfigManager) closeWatcher() {
	cm.watcherMu.Lock()
	defer cm.watcherMu.Unlock()
	if cm.watcher != nil {
		cm.watcher.Close()
		cm.watcher = nil
	}
}
