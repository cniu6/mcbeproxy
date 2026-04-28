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

	"mcpeserverproxy/internal/logger"
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

const (
	AutoPingFullScanModeDisabled = ""
	AutoPingFullScanModeDaily    = "daily"
	AutoPingFullScanModeInterval = "interval"

	defaultAutoPingIntervalMinutes         = 10
	defaultAutoPingTopCandidates           = 10
	defaultAutoPingFullScanTime            = "04:00"
	defaultAutoPingFullScanIntervalHr      = 24
	defaultLatencyHistoryMinIntervalMinute = 10
	defaultLatencyHistoryRenderLimit       = 100
	defaultLatencyHistoryStorageLimit      = 1000
	defaultLatencyHistoryRetentionDays     = 5
)

const (
	ProxyModeTransparent = "transparent"
	ProxyModePassthrough = "passthrough"
	ProxyModeRakNet      = "raknet"
	ProxyModeRawUDP      = "raw_udp"
	ProxyModeMITM        = "mitm"
)

func normalizeProtocol(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

func normalizeProxyOutboundValue(proxyOutbound string) string {
	return strings.TrimSpace(proxyOutbound)
}

func normalizeServerProxyMode(protocol, mode string) string {
	normalizedProtocol := normalizeProtocol(protocol)
	if normalizedProtocol != "" && normalizedProtocol != ProxyModeRakNet {
		return ""
	}

	normalizedMode := strings.ToLower(strings.TrimSpace(mode))
	switch normalizedMode {
	case "", ProxyModeTransparent:
		return ""
	case ProxyModePassthrough, ProxyModeRakNet, ProxyModeRawUDP, ProxyModeMITM:
		return normalizedMode
	default:
		return ""
	}
}

// LatencyMode constants control optional UDP latency-acceleration behavior.
//
//   - LatencyModeNormal: current default behavior, no extra socket / pipeline tuning.
//   - LatencyModeAggressive: low-risk inline UDP optimizations (DSCP/EF marking
//     on UDP sockets, larger default UDP socket buffer when user did not override).
//   - LatencyModeFECTunnel: requires udp_speeder to be configured and enabled. The
//     existing speeder pipeline (FEC, retransmit) is the actual transport. This
//     mode is just a strict declaration that the operator wants speeder semantics
//     so misconfiguration is rejected at validation time instead of silently
//     falling back to plain UDP.
const (
	LatencyModeNormal     = "normal"
	LatencyModeAggressive = "aggressive"
	LatencyModeFECTunnel  = "fec_tunnel"
)

func isValidLatencyMode(mode string) bool {
	switch normalizeLatencyMode(mode) {
	case LatencyModeNormal, LatencyModeAggressive, LatencyModeFECTunnel:
		return true
	default:
		return false
	}
}

func normalizeLatencyMode(mode string) string {
	v := strings.ToLower(strings.TrimSpace(mode))
	if v == "" {
		return LatencyModeNormal
	}
	return v
}

// ServerConfig represents a proxy target server configuration.
type ServerConfig struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	Target              string            `json:"target"`
	Port                int               `json:"port"`
	ListenAddr          string            `json:"listen_addr"`
	Protocol            string            `json:"protocol"`
	Enabled             bool              `json:"enabled"`  // Whether to start the proxy listener
	Disabled            bool              `json:"disabled"` // Whether to reject new connections (when enabled=true)
	UDPSpeeder          *UDPSpeederConfig `json:"udp_speeder,omitempty"`
	SendRealIP          bool              `json:"send_real_ip"`
	ResolveInterval     int               `json:"resolve_interval"`       // seconds
	IdleTimeout         int               `json:"idle_timeout"`           // seconds
	BufferSize          int               `json:"buffer_size"`            // UDP buffer size, -1 for auto
	UDPSocketBufferSize int               `json:"udp_socket_buffer_size"` // UDP socket buffer size in bytes (0=auto, -1=OS default)
	DisabledMessage     string            `json:"disabled_message"`       // Custom message when server is disabled
	CustomMOTD          string            `json:"custom_motd"`            // Custom MOTD for ping response (empty = forward from remote)
	ProxyMode           string            `json:"proxy_mode"`             // "transparent" (default) or "raknet" (full RakNet proxy)
	ACLServerID         string            `json:"acl_server_id,omitempty"`
	RawUDPKickStrategy  string            `json:"raw_udp_kick_strategy,omitempty"`
	XboxAuthEnabled     bool              `json:"xbox_auth_enabled"`      // Enable Xbox Live authentication for remote connections
	XboxTokenPath       string            `json:"xbox_token_path"`        // Custom token file path for Xbox Live tokens (optional)
	ProxyOutbound       string            `json:"proxy_outbound"`         // Proxy outbound node name, "@group" for group selection, empty or "direct" for direct connection
	ShowRealLatency     bool              `json:"show_real_latency"`      // Show real latency through proxy in server list ping
	LoadBalance         string            `json:"load_balance"`           // Load balance strategy: least-latency, round-robin, random, least-connections
	LoadBalanceSort     string            `json:"load_balance_sort"`      // Latency sort type: udp, tcp, http
	ProtocolVersion     int               `json:"protocol_version"`       // Override protocol version in Login packet (0 = don't modify)
	LatencyMode         string            `json:"latency_mode,omitempty"` // "normal" (default), "aggressive", or "fec_tunnel"
	// Load balancing ping interval
	AutoPingEnabled               bool   `json:"auto_ping_enabled"`
	AutoPingIntervalMinutes       int    `json:"auto_ping_interval_minutes"`         // Per-server ping interval in minutes
	AutoPingTopCandidates         int    `json:"auto_ping_top_candidates"`           // Additional low-traffic candidates besides current node
	AutoPingFullScanMode          string `json:"auto_ping_full_scan_mode,omitempty"` // "", daily, interval
	AutoPingFullScanTime          string `json:"auto_ping_full_scan_time,omitempty"` // HH:MM for daily full scan
	AutoPingFullScanIntervalHours int    `json:"auto_ping_full_scan_interval_hours"` // Full-scan interval in hours when mode=interval
	resolvedIP                    string
	lastResolved                  time.Time
}

const (
	RawUDPKickStrategyDisconnectRakNet           = "disconnect_raknet"
	RawUDPKickStrategyDisconnectOnly             = "disconnect_only"
	RawUDPKickStrategyPlayStatusDisconnect       = "playstatus_disconnect"
	RawUDPKickStrategyPlayStatusDisconnectRakNet = "playstatus_disconnect_raknet"
	RawUDPKickStrategyCompressedDisconnectOnly   = "compressed_disconnect_only"
	RawUDPKickStrategyCompressedDisconnectRakNet = "compressed_disconnect_raknet"
	RawUDPKickStrategyRawBatchDisconnectOnly     = "raw_batch_disconnect_only"
	RawUDPKickStrategyRawBatchDisconnectRakNet   = "raw_batch_disconnect_raknet"
	RawUDPKickStrategyLegacyDisconnectOnly       = "legacy_disconnect_only"
	RawUDPKickStrategyLegacyDisconnectRakNet     = "legacy_disconnect_raknet"
)

func isValidRawUDPKickStrategy(strategy string) bool {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "",
		RawUDPKickStrategyDisconnectRakNet,
		RawUDPKickStrategyDisconnectOnly,
		RawUDPKickStrategyPlayStatusDisconnect,
		RawUDPKickStrategyPlayStatusDisconnectRakNet,
		RawUDPKickStrategyCompressedDisconnectOnly,
		RawUDPKickStrategyCompressedDisconnectRakNet,
		RawUDPKickStrategyRawBatchDisconnectOnly,
		RawUDPKickStrategyRawBatchDisconnectRakNet,
		RawUDPKickStrategyLegacyDisconnectOnly,
		RawUDPKickStrategyLegacyDisconnectRakNet:
		return true
	default:
		return false
	}
}

type UDPSpeederConfig struct {
	Enabled         bool     `json:"enabled"`
	BinaryPath      string   `json:"binary_path"`
	LocalListenAddr string   `json:"local_listen_addr"`
	RemoteAddr      string   `json:"remote_addr"`
	FEC             string   `json:"fec"`
	Key             string   `json:"key"`
	Mode            int      `json:"mode"`
	TimeoutMs       int      `json:"timeout_ms"`
	MTU             int      `json:"mtu"`
	DisableObscure  bool     `json:"disable_obscure"`
	DisableChecksum bool     `json:"disable_checksum"`
	ExtraArgs       []string `json:"extra_args"`
}

type UDPSpeederConfigDTO struct {
	Enabled         bool     `json:"enabled"`
	BinaryPath      string   `json:"binary_path"`
	LocalListenAddr string   `json:"local_listen_addr"`
	RemoteAddr      string   `json:"remote_addr"`
	FEC             string   `json:"fec"`
	Mode            int      `json:"mode"`
	TimeoutMs       int      `json:"timeout_ms"`
	MTU             int      `json:"mtu"`
	DisableObscure  bool     `json:"disable_obscure"`
	DisableChecksum bool     `json:"disable_checksum"`
	ExtraArgs       []string `json:"extra_args"`
}

func (c *UDPSpeederConfig) ToDTO() *UDPSpeederConfigDTO {
	if c == nil {
		return nil
	}
	return &UDPSpeederConfigDTO{
		Enabled:         c.Enabled,
		BinaryPath:      c.BinaryPath,
		LocalListenAddr: c.LocalListenAddr,
		RemoteAddr:      c.RemoteAddr,
		FEC:             c.FEC,
		Mode:            c.Mode,
		TimeoutMs:       c.TimeoutMs,
		MTU:             c.MTU,
		DisableObscure:  c.DisableObscure,
		DisableChecksum: c.DisableChecksum,
		ExtraArgs:       c.ExtraArgs,
	}
}

func (c *UDPSpeederConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.RemoteAddr == "" {
		return errors.New("udp_speeder.remote_addr is required when enabled")
	}
	if _, _, err := net.SplitHostPort(c.RemoteAddr); err != nil {
		return fmt.Errorf("udp_speeder.remote_addr invalid: %w", err)
	}
	if c.LocalListenAddr != "" {
		if _, _, err := net.SplitHostPort(c.LocalListenAddr); err != nil {
			return fmt.Errorf("udp_speeder.local_listen_addr invalid: %w", err)
		}
	}
	if c.Mode < 0 {
		return errors.New("udp_speeder.mode cannot be negative")
	}
	if c.TimeoutMs < 0 {
		return errors.New("udp_speeder.timeout_ms cannot be negative")
	}
	if c.MTU < 0 {
		return errors.New("udp_speeder.mtu cannot be negative")
	}
	return nil
}

// GetProxyMode returns the proxy mode, defaulting to "transparent".
func (sc *ServerConfig) GetProxyMode() string {
	if sc == nil {
		return ProxyModeTransparent
	}
	mode := normalizeServerProxyMode(sc.Protocol, sc.ProxyMode)
	if mode == "" {
		return ProxyModeTransparent
	}
	return mode
}

func (sc *ServerConfig) Normalize() {
	if sc == nil {
		return
	}
	sc.Protocol = normalizeProtocol(sc.Protocol)
	sc.ProxyOutbound = normalizeProxyOutboundValue(sc.ProxyOutbound)
	sc.ProxyMode = normalizeServerProxyMode(sc.Protocol, sc.ProxyMode)
	sc.AutoPingFullScanMode = normalizeAutoPingFullScanMode(sc.AutoPingFullScanMode)
	if !sc.SupportsAutoPing() {
		sc.AutoPingEnabled = false
		sc.AutoPingFullScanMode = AutoPingFullScanModeDisabled
	}
}

// GetLatencyMode returns the normalized latency mode. Empty / unknown values
// are treated as LatencyModeNormal so callers never have to re-check.
func (sc *ServerConfig) GetLatencyMode() string {
	if sc == nil {
		return LatencyModeNormal
	}
	mode := normalizeLatencyMode(sc.LatencyMode)
	switch mode {
	case LatencyModeNormal, LatencyModeAggressive, LatencyModeFECTunnel:
		return mode
	default:
		return LatencyModeNormal
	}
}

// IsAggressiveLatency reports whether the server opted into the inline
// aggressive UDP optimizations (DSCP marking, larger default socket buffer).
func (sc *ServerConfig) IsAggressiveLatency() bool {
	return sc.GetLatencyMode() == LatencyModeAggressive
}

// IsFECTunnelLatency reports whether the server requires udp_speeder semantics.
func (sc *ServerConfig) IsFECTunnelLatency() bool {
	return sc.GetLatencyMode() == LatencyModeFECTunnel
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
	protocol := normalizeProtocol(sc.Protocol)
	if protocol == "" {
		return errors.New("protocol is required")
	}
	if sc.UDPSocketBufferSize < -1 {
		return fmt.Errorf("udp_socket_buffer_size must be >= -1, got %d", sc.UDPSocketBufferSize)
	}
	if sc.AutoPingTopCandidates < 0 {
		return fmt.Errorf("auto_ping_top_candidates must be >= 0, got %d", sc.AutoPingTopCandidates)
	}
	switch normalizeAutoPingFullScanMode(sc.AutoPingFullScanMode) {
	case AutoPingFullScanModeDisabled:
	case AutoPingFullScanModeDaily:
		if _, err := parseAutoPingClock(sc.GetAutoPingFullScanTime()); err != nil {
			return err
		}
	case AutoPingFullScanModeInterval:
		if sc.GetAutoPingFullScanIntervalHours() < 1 {
			return fmt.Errorf("auto_ping_full_scan_interval_hours must be >= 1, got %d", sc.AutoPingFullScanIntervalHours)
		}
	default:
		return fmt.Errorf("invalid auto_ping_full_scan_mode: %s", sc.AutoPingFullScanMode)
	}
	if !isValidRawUDPKickStrategy(sc.RawUDPKickStrategy) {
		return fmt.Errorf("invalid raw_udp_kick_strategy: %s", sc.RawUDPKickStrategy)
	}
	if sc.UDPSpeeder != nil && sc.UDPSpeeder.Enabled {
		switch protocol {
		case "tcp", "tcp_udp":
			return fmt.Errorf("udp_speeder is not supported for protocol %s", sc.Protocol)
		}
		if err := sc.UDPSpeeder.Validate(); err != nil {
			return err
		}
	}
	if !isValidLatencyMode(sc.LatencyMode) {
		return fmt.Errorf("invalid latency_mode: %s", sc.LatencyMode)
	}
	switch normalizeLatencyMode(sc.LatencyMode) {
	case LatencyModeAggressive:
		// aggressive mode tunes UDP sockets; on pure TCP listeners it has no effect.
		// Reject the combination up front so operators are not misled.
		if protocol == "tcp" {
			return fmt.Errorf("latency_mode=aggressive is not supported for protocol tcp")
		}
	case LatencyModeFECTunnel:
		switch protocol {
		case "tcp", "tcp_udp":
			return fmt.Errorf("latency_mode=fec_tunnel is not supported for protocol %s", sc.Protocol)
		}
		if sc.UDPSpeeder == nil || !sc.UDPSpeeder.Enabled {
			return errors.New("latency_mode=fec_tunnel requires udp_speeder to be configured and enabled")
		}
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
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	Target              string               `json:"target"`
	Port                int                  `json:"port"`
	ListenAddr          string               `json:"listen_addr"`
	Protocol            string               `json:"protocol"`
	Enabled             bool                 `json:"enabled"`
	Disabled            bool                 `json:"disabled"` // Whether to reject new connections
	UDPSpeeder          *UDPSpeederConfigDTO `json:"udp_speeder,omitempty"`
	SendRealIP          bool                 `json:"send_real_ip"`
	ResolveInterval     int                  `json:"resolve_interval"`
	IdleTimeout         int                  `json:"idle_timeout"`
	BufferSize          int                  `json:"buffer_size"`
	UDPSocketBufferSize int                  `json:"udp_socket_buffer_size"`
	DisabledMessage     string               `json:"disabled_message"`
	CustomMOTD          string               `json:"custom_motd"`
	ProxyMode           string               `json:"proxy_mode"` // "transparent", "passthrough", or "raknet"
	ACLServerID         string               `json:"acl_server_id,omitempty"`
	RawUDPKickStrategy  string               `json:"raw_udp_kick_strategy,omitempty"`
	XboxAuthEnabled     bool                 `json:"xbox_auth_enabled"`
	XboxTokenPath       string               `json:"xbox_token_path"`
	ProxyOutbound       string               `json:"proxy_outbound"`         // Proxy outbound node name or "@group" for group selection
	ShowRealLatency     bool                 `json:"show_real_latency"`      // Show real latency through proxy
	LoadBalance         string               `json:"load_balance"`           // Load balance strategy
	LoadBalanceSort     string               `json:"load_balance_sort"`      // Latency sort type
	LatencyMode         string               `json:"latency_mode,omitempty"` // "normal", "aggressive", "fec_tunnel"
	Status              string               `json:"status"`                 // running, stopped
	ActiveSessions      int                  `json:"active_sessions"`
	// Load balancing ping interval
	AutoPingEnabled               bool   `json:"auto_ping_enabled"`
	AutoPingIntervalMinutes       int    `json:"auto_ping_interval_minutes"` // Per-server ping interval
	LastAutoPingAt               int64  `json:"last_auto_ping_at,omitempty"`
	NextAutoPingAt               int64  `json:"next_auto_ping_at,omitempty"`
	AutoPingTopCandidates         int    `json:"auto_ping_top_candidates"`
	AutoPingFullScanMode          string `json:"auto_ping_full_scan_mode,omitempty"`
	AutoPingFullScanTime          string `json:"auto_ping_full_scan_time,omitempty"`
	AutoPingFullScanIntervalHours int    `json:"auto_ping_full_scan_interval_hours"`
}

// ToDTO converts the server config to a DTO for API responses.
func (sc *ServerConfig) ToDTO(status string, activeSessions int) ServerConfigDTO {
	return ServerConfigDTO{
		ID:                            sc.ID,
		Name:                          sc.Name,
		Target:                        sc.Target,
		Port:                          sc.Port,
		ListenAddr:                    sc.ListenAddr,
		Protocol:                      normalizeProtocol(sc.Protocol),
		Enabled:                       sc.Enabled,
		Disabled:                      sc.Disabled,
		UDPSpeeder:                    sc.UDPSpeeder.ToDTO(),
		SendRealIP:                    sc.SendRealIP,
		ResolveInterval:               sc.ResolveInterval,
		IdleTimeout:                   sc.IdleTimeout,
		BufferSize:                    sc.BufferSize,
		UDPSocketBufferSize:           sc.UDPSocketBufferSize,
		DisabledMessage:               sc.DisabledMessage,
		CustomMOTD:                    sc.CustomMOTD,
		ProxyMode:                     sc.GetProxyMode(),
		ACLServerID:                   sc.GetACLServerID(),
		RawUDPKickStrategy:            sc.GetRawUDPKickStrategy(),
		XboxAuthEnabled:               sc.XboxAuthEnabled,
		XboxTokenPath:                 sc.XboxTokenPath,
		ProxyOutbound:                 sc.GetProxyOutbound(),
		ShowRealLatency:               sc.ShowRealLatency,
		LoadBalance:                   sc.LoadBalance,
		LoadBalanceSort:               sc.LoadBalanceSort,
		LatencyMode:                   sc.GetLatencyMode(),
		Status:                        status,
		ActiveSessions:                activeSessions,
		AutoPingEnabled:               sc.IsAutoPingEnabled(),
		AutoPingIntervalMinutes:       sc.GetAutoPingIntervalMinutes(),
		AutoPingTopCandidates:         sc.GetAutoPingTopCandidates(),
		AutoPingFullScanMode:          sc.GetAutoPingFullScanMode(),
		AutoPingFullScanTime:          sc.GetAutoPingFullScanTime(),
		AutoPingFullScanIntervalHours: sc.GetAutoPingFullScanIntervalHours(),
	}
}

func (sc *ServerConfig) IsShowRealLatency() bool {
	return sc.ShowRealLatency
}

func (sc *ServerConfig) GetCustomMOTD() string {
	return sc.CustomMOTD
}

func (sc *ServerConfig) GetBufferSize() int {
	if sc.BufferSize == 0 {
		return -1
	}
	return sc.BufferSize
}

func (sc *ServerConfig) GetUDPSocketBufferSize() int {
	if sc == nil {
		return 0
	}
	return sc.UDPSocketBufferSize
}

func (sc *ServerConfig) GetDisabledMessage() string {
	if sc.DisabledMessage == "" {
		return "Server is currently disabled"
	}
	return sc.DisabledMessage
}

func (sc *ServerConfig) IsXboxAuthEnabled() bool {
	return sc.XboxAuthEnabled
}

func (sc *ServerConfig) GetXboxTokenPath() string {
	if sc.XboxTokenPath == "" {
		return "xbox_token.json"
	}
	return sc.XboxTokenPath
}

func (sc *ServerConfig) GetProxyOutbound() string {
	if sc == nil {
		return ""
	}
	return normalizeProxyOutboundValue(sc.ProxyOutbound)
}

func (sc *ServerConfig) IsDirectConnection() bool {
	proxyOutbound := sc.GetProxyOutbound()
	return proxyOutbound == "" || strings.EqualFold(proxyOutbound, "direct")
}

func (sc *ServerConfig) IsGroupSelection() bool {
	return strings.HasPrefix(sc.GetProxyOutbound(), "@")
}

func (sc *ServerConfig) IsMultiNodeSelection() bool {
	proxyOutbound := sc.GetProxyOutbound()
	if proxyOutbound == "" || strings.EqualFold(proxyOutbound, "direct") {
		return false
	}
	if strings.HasPrefix(proxyOutbound, "@") {
		return false
	}
	return strings.Contains(proxyOutbound, ",")
}

func (sc *ServerConfig) GetNodeList() []string {
	if !sc.IsMultiNodeSelection() {
		return nil
	}
	nodes := strings.Split(sc.GetProxyOutbound(), ",")
	result := make([]string, 0, len(nodes))
	for _, node := range nodes {
		trimmed := strings.TrimSpace(node)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func (sc *ServerConfig) GetGroupName() string {
	if sc.IsGroupSelection() {
		return strings.TrimPrefix(sc.GetProxyOutbound(), "@")
	}
	return ""
}

func (sc *ServerConfig) SupportsAutoPing() bool {
	if sc == nil {
		return false
	}
	if sc.IsGroupSelection() {
		return true
	}
	return len(sc.GetNodeList()) > 1
}

func (sc *ServerConfig) IsAutoPingEnabled() bool {
	return sc != nil && sc.AutoPingEnabled && sc.SupportsAutoPing()
}

func (sc *ServerConfig) GetProtocolVersion() int {
	return sc.ProtocolVersion
}

func (sc *ServerConfig) GetAutoPingIntervalMinutes() int {
	if sc == nil {
		return defaultAutoPingIntervalMinutes
	}
	if sc.AutoPingIntervalMinutes <= 0 {
		return defaultAutoPingIntervalMinutes
	}
	return sc.AutoPingIntervalMinutes
}

func (sc *ServerConfig) GetACLServerID() string {
	aclServerID := strings.TrimSpace(sc.ACLServerID)
	if aclServerID == "" {
		return sc.ID
	}
	return aclServerID
}

func (sc *ServerConfig) GetRawUDPKickStrategy() string {
	strategy := strings.ToLower(strings.TrimSpace(sc.RawUDPKickStrategy))
	if strategy == "" {
		return RawUDPKickStrategyDisconnectOnly
	}
	return strategy
}

func (sc *ServerConfig) GetLoadBalance() string {
	if sc.LoadBalance == "" {
		return LoadBalanceLeastLatency
	}
	return sc.LoadBalance
}

func (sc *ServerConfig) GetLoadBalanceSort() string {
	if sc.LoadBalanceSort == "" {
		return LoadBalanceSortUDP
	}
	return sc.LoadBalanceSort
}

func (sc *ServerConfig) GetAutoPingTopCandidates() int {
	if sc == nil {
		return defaultAutoPingTopCandidates
	}
	if sc.AutoPingTopCandidates < 0 {
		return 0
	}
	if sc.AutoPingTopCandidates == 0 {
		return defaultAutoPingTopCandidates
	}
	return sc.AutoPingTopCandidates
}

func (sc *ServerConfig) GetAutoPingFullScanMode() string {
	if sc == nil {
		return AutoPingFullScanModeDisabled
	}
	return normalizeAutoPingFullScanMode(sc.AutoPingFullScanMode)
}

func (sc *ServerConfig) GetAutoPingFullScanTime() string {
	if sc == nil || strings.TrimSpace(sc.AutoPingFullScanTime) == "" {
		return defaultAutoPingFullScanTime
	}
	return strings.TrimSpace(sc.AutoPingFullScanTime)
}

func (sc *ServerConfig) GetAutoPingFullScanIntervalHours() int {
	if sc == nil || sc.AutoPingFullScanIntervalHours <= 0 {
		return defaultAutoPingFullScanIntervalHr
	}
	return sc.AutoPingFullScanIntervalHours
}

func normalizeAutoPingFullScanMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case AutoPingFullScanModeDisabled:
		return AutoPingFullScanModeDisabled
	case AutoPingFullScanModeDaily:
		return AutoPingFullScanModeDaily
	case AutoPingFullScanModeInterval:
		return AutoPingFullScanModeInterval
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func parseAutoPingClock(value string) (time.Time, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid auto_ping_full_scan_time %q: expected HH:MM", value)
	}
	return parsed, nil
}

// DNSResolver handles DNS resolution for server targets.
type DNSResolver struct{}

var dnsSpecialCIDRs = mustParseResolveCIDRs([]string{
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"0.0.0.0/8",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"2001:db8::/32",
	"ff00::/8",
})

var publicDNSServers = []string{"1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"}

func mustParseResolveCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}

func isSpecialResolveIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, ipnet := range dnsSpecialCIDRs {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func filterUsableResolveIPs(addrs []net.IPAddr) []net.IP {
	result := make([]net.IP, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil || isSpecialResolveIP(ip) {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ip)
	}
	return result
}

func preferredResolveIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	return nil
}

func newResolveDNSResolver(server string, timeout time.Duration) *net.Resolver {
	dialer := &net.Dialer{Timeout: timeout}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", server)
		},
	}
}

func resolveUsableIP(ctx context.Context, hostname string) (net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	usable := filterUsableResolveIPs(addrs)
	if ip := preferredResolveIP(usable); ip != nil {
		logger.Debug("Config DNS resolve ok: host=%s source=system ip=%s", hostname, ip.String())
		return ip, nil
	}
	if err != nil {
		logger.Debug("Config DNS resolve system failed: host=%s err=%v", hostname, err)
	} else if len(addrs) > 0 {
		resolved := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if addr.IP != nil {
				resolved = append(resolved, addr.IP.String())
			}
		}
		logger.Debug("Config DNS resolve system returned only special-use IPs: host=%s ips=%s", hostname, strings.Join(resolved, ","))
	}

	var lastErr error
	for _, dnsServer := range publicDNSServers {
		resolver := newResolveDNSResolver(dnsServer, 3*time.Second)
		addrs, err = resolver.LookupIPAddr(ctx, hostname)
		usable = filterUsableResolveIPs(addrs)
		if ip := preferredResolveIP(usable); ip != nil {
			logger.Debug("Config DNS resolve ok: host=%s source=public_dns server=%s ip=%s", hostname, dnsServer, ip.String())
			return ip, nil
		}
		if err != nil {
			lastErr = err
			logger.Debug("Config DNS resolve public dns failed: host=%s server=%s err=%v", hostname, dnsServer, err)
			continue
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable public IP found")
	}
	return nil, lastErr
}

// Resolve resolves a hostname to an IP address.
func (r *DNSResolver) Resolve(hostname string) (string, error) {
	// Check if it's already an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return hostname, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolvedIP, err := resolveUsableIP(ctx, hostname)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %w", hostname, err)
	}
	return resolvedIP.String(), nil
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
		config.Normalize()
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
	config.Normalize()
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
	config.Normalize()
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

	if err := atomicWriteFile(cm.configPath, data, 0644); err != nil {
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
	// Defaults for new server auto ping forms in the frontend.
	ServerAutoPingIntervalMinutesDefault       int    `json:"server_auto_ping_interval_minutes_default"`
	ServerAutoPingTopCandidatesDefault         int    `json:"server_auto_ping_top_candidates_default"`
	ServerAutoPingFullScanModeDefault          string `json:"server_auto_ping_full_scan_mode_default"`
	ServerAutoPingFullScanTimeDefault          string `json:"server_auto_ping_full_scan_time_default"`
	ServerAutoPingFullScanIntervalHoursDefault int    `json:"server_auto_ping_full_scan_interval_hours_default"`
	// Defaults for new proxy-port auto ping forms in the frontend.
	ProxyPortAutoPingIntervalMinutesDefault       int    `json:"proxy_port_auto_ping_interval_minutes_default"`
	ProxyPortAutoPingTopCandidatesDefault         int    `json:"proxy_port_auto_ping_top_candidates_default"`
	ProxyPortAutoPingFullScanModeDefault          string `json:"proxy_port_auto_ping_full_scan_mode_default"`
	ProxyPortAutoPingFullScanTimeDefault          string `json:"proxy_port_auto_ping_full_scan_time_default"`
	ProxyPortAutoPingFullScanIntervalHoursDefault int    `json:"proxy_port_auto_ping_full_scan_interval_hours_default"`
	LatencyHistoryMinIntervalMinutes              int    `json:"latency_history_min_interval_minutes"`
	LatencyHistoryRenderLimit                     int    `json:"latency_history_render_limit"`
	LatencyHistoryStorageLimit                    int    `json:"latency_history_storage_limit"`
	LatencyHistoryRetentionDays                   int    `json:"latency_history_retention_days"`
}

// DefaultGlobalConfig returns a GlobalConfig with default values.
func DefaultGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		MaxSessionRecords:                    100,
		MaxAccessLogRecords:                  100,
		APIPort:                              8080,
		APIKey:                               "",
		APIEntryPath:                         "/mcpe-admin",
		DatabasePath:                         "data.db",
		LogDir:                               "logs",
		LogRetentionDays:                     7,
		LogMaxSizeMB:                         100,
		AuthVerifyEnabled:                    false,
		AuthVerifyURL:                        "",
		AuthCacheMinutes:                     15,
		ProxyPortsEnabled:                    true,
		PassthroughIdleTimeout:               30,
		PublicPingTimeoutSeconds:             5,
		ServerAutoPingIntervalMinutesDefault: defaultAutoPingIntervalMinutes,
		ServerAutoPingTopCandidatesDefault:   defaultAutoPingTopCandidates,
		ServerAutoPingFullScanModeDefault:    AutoPingFullScanModeDisabled,
		ServerAutoPingFullScanTimeDefault:    defaultAutoPingFullScanTime,
		ServerAutoPingFullScanIntervalHoursDefault:    defaultAutoPingFullScanIntervalHr,
		ProxyPortAutoPingIntervalMinutesDefault:       defaultAutoPingIntervalMinutes,
		ProxyPortAutoPingTopCandidatesDefault:         defaultAutoPingTopCandidates,
		ProxyPortAutoPingFullScanModeDefault:          AutoPingFullScanModeDisabled,
		ProxyPortAutoPingFullScanTimeDefault:          defaultAutoPingFullScanTime,
		ProxyPortAutoPingFullScanIntervalHoursDefault: defaultAutoPingFullScanIntervalHr,
		LatencyHistoryMinIntervalMinutes:              defaultLatencyHistoryMinIntervalMinute,
		LatencyHistoryRenderLimit:                     defaultLatencyHistoryRenderLimit,
		LatencyHistoryStorageLimit:                    defaultLatencyHistoryStorageLimit,
		LatencyHistoryRetentionDays:                   defaultLatencyHistoryRetentionDays,
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
	if config.ServerAutoPingIntervalMinutesDefault <= 0 {
		config.ServerAutoPingIntervalMinutesDefault = defaultAutoPingIntervalMinutes
	}
	if config.ServerAutoPingTopCandidatesDefault <= 0 {
		config.ServerAutoPingTopCandidatesDefault = defaultAutoPingTopCandidates
	}
	config.ServerAutoPingFullScanModeDefault = normalizeAutoPingFullScanMode(config.ServerAutoPingFullScanModeDefault)
	if strings.TrimSpace(config.ServerAutoPingFullScanTimeDefault) == "" {
		config.ServerAutoPingFullScanTimeDefault = defaultAutoPingFullScanTime
	}
	if config.ServerAutoPingFullScanIntervalHoursDefault <= 0 {
		config.ServerAutoPingFullScanIntervalHoursDefault = defaultAutoPingFullScanIntervalHr
	}
	if config.ProxyPortAutoPingIntervalMinutesDefault <= 0 {
		config.ProxyPortAutoPingIntervalMinutesDefault = defaultAutoPingIntervalMinutes
	}
	if config.ProxyPortAutoPingTopCandidatesDefault <= 0 {
		config.ProxyPortAutoPingTopCandidatesDefault = defaultAutoPingTopCandidates
	}
	config.ProxyPortAutoPingFullScanModeDefault = normalizeAutoPingFullScanMode(config.ProxyPortAutoPingFullScanModeDefault)
	if strings.TrimSpace(config.ProxyPortAutoPingFullScanTimeDefault) == "" {
		config.ProxyPortAutoPingFullScanTimeDefault = defaultAutoPingFullScanTime
	}
	if config.ProxyPortAutoPingFullScanIntervalHoursDefault <= 0 {
		config.ProxyPortAutoPingFullScanIntervalHoursDefault = defaultAutoPingFullScanIntervalHr
	}
	if config.LatencyHistoryMinIntervalMinutes <= 0 {
		config.LatencyHistoryMinIntervalMinutes = defaultLatencyHistoryMinIntervalMinute
	}
	if config.LatencyHistoryRenderLimit <= 0 {
		config.LatencyHistoryRenderLimit = defaultLatencyHistoryRenderLimit
	}
	if config.LatencyHistoryStorageLimit <= 0 {
		config.LatencyHistoryStorageLimit = defaultLatencyHistoryStorageLimit
	}
	if config.LatencyHistoryRetentionDays <= 0 {
		config.LatencyHistoryRetentionDays = defaultLatencyHistoryRetentionDays
	}

	return config, nil
}

// Save saves the global configuration to a JSON file.
func (gc *GlobalConfig) Save(path string) error {
	data, err := json.MarshalIndent(gc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal global config: %w", err)
	}

	if err := atomicWriteFile(path, data, 0644); err != nil {
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
	if gc.GetServerAutoPingIntervalMinutesDefault() < 1 {
		return errors.New("server_auto_ping_interval_minutes_default must be >= 1")
	}
	if gc.GetServerAutoPingTopCandidatesDefault() < 0 {
		return errors.New("server_auto_ping_top_candidates_default must be >= 0")
	}
	switch gc.GetServerAutoPingFullScanModeDefault() {
	case AutoPingFullScanModeDisabled:
	case AutoPingFullScanModeDaily:
		if _, err := parseAutoPingClock(gc.GetServerAutoPingFullScanTimeDefault()); err != nil {
			return err
		}
	case AutoPingFullScanModeInterval:
		if gc.GetServerAutoPingFullScanIntervalHoursDefault() < 1 {
			return errors.New("server_auto_ping_full_scan_interval_hours_default must be >= 1")
		}
	default:
		return fmt.Errorf("invalid server_auto_ping_full_scan_mode_default: %s", gc.ServerAutoPingFullScanModeDefault)
	}
	if gc.GetProxyPortAutoPingIntervalMinutesDefault() < 1 {
		return errors.New("proxy_port_auto_ping_interval_minutes_default must be >= 1")
	}
	if gc.GetProxyPortAutoPingTopCandidatesDefault() < 0 {
		return errors.New("proxy_port_auto_ping_top_candidates_default must be >= 0")
	}
	switch gc.GetProxyPortAutoPingFullScanModeDefault() {
	case AutoPingFullScanModeDisabled:
	case AutoPingFullScanModeDaily:
		if _, err := parseAutoPingClock(gc.GetProxyPortAutoPingFullScanTimeDefault()); err != nil {
			return err
		}
	case AutoPingFullScanModeInterval:
		if gc.GetProxyPortAutoPingFullScanIntervalHoursDefault() < 1 {
			return errors.New("proxy_port_auto_ping_full_scan_interval_hours_default must be >= 1")
		}
	default:
		return fmt.Errorf("invalid proxy_port_auto_ping_full_scan_mode_default: %s", gc.ProxyPortAutoPingFullScanModeDefault)
	}
	if gc.GetLatencyHistoryMinIntervalMinutes() < 1 {
		return errors.New("latency_history_min_interval_minutes must be >= 1")
	}
	if gc.GetLatencyHistoryRenderLimit() < 1 {
		return errors.New("latency_history_render_limit must be >= 1")
	}
	if gc.GetLatencyHistoryStorageLimit() < 1 {
		return errors.New("latency_history_storage_limit must be >= 1")
	}
	if gc.GetLatencyHistoryRenderLimit() > gc.GetLatencyHistoryStorageLimit() {
		return errors.New("latency_history_render_limit cannot exceed latency_history_storage_limit")
	}
	if gc.GetLatencyHistoryRetentionDays() < 1 {
		return errors.New("latency_history_retention_days must be >= 1")
	}
	return nil
}

func (gc *GlobalConfig) GetServerAutoPingIntervalMinutesDefault() int {
	if gc == nil || gc.ServerAutoPingIntervalMinutesDefault <= 0 {
		return defaultAutoPingIntervalMinutes
	}
	return gc.ServerAutoPingIntervalMinutesDefault
}

func (gc *GlobalConfig) GetServerAutoPingTopCandidatesDefault() int {
	if gc == nil || gc.ServerAutoPingTopCandidatesDefault <= 0 {
		return defaultAutoPingTopCandidates
	}
	return gc.ServerAutoPingTopCandidatesDefault
}

func (gc *GlobalConfig) GetServerAutoPingFullScanModeDefault() string {
	if gc == nil {
		return AutoPingFullScanModeDisabled
	}
	return normalizeAutoPingFullScanMode(gc.ServerAutoPingFullScanModeDefault)
}

func (gc *GlobalConfig) GetServerAutoPingFullScanTimeDefault() string {
	if gc == nil || strings.TrimSpace(gc.ServerAutoPingFullScanTimeDefault) == "" {
		return defaultAutoPingFullScanTime
	}
	return strings.TrimSpace(gc.ServerAutoPingFullScanTimeDefault)
}

func (gc *GlobalConfig) GetServerAutoPingFullScanIntervalHoursDefault() int {
	if gc == nil || gc.ServerAutoPingFullScanIntervalHoursDefault <= 0 {
		return defaultAutoPingFullScanIntervalHr
	}
	return gc.ServerAutoPingFullScanIntervalHoursDefault
}

func (gc *GlobalConfig) GetProxyPortAutoPingIntervalMinutesDefault() int {
	if gc == nil || gc.ProxyPortAutoPingIntervalMinutesDefault <= 0 {
		return defaultAutoPingIntervalMinutes
	}
	return gc.ProxyPortAutoPingIntervalMinutesDefault
}

func (gc *GlobalConfig) GetProxyPortAutoPingTopCandidatesDefault() int {
	if gc == nil || gc.ProxyPortAutoPingTopCandidatesDefault <= 0 {
		return defaultAutoPingTopCandidates
	}
	return gc.ProxyPortAutoPingTopCandidatesDefault
}

func (gc *GlobalConfig) GetProxyPortAutoPingFullScanModeDefault() string {
	if gc == nil {
		return AutoPingFullScanModeDisabled
	}
	return normalizeAutoPingFullScanMode(gc.ProxyPortAutoPingFullScanModeDefault)
}

func (gc *GlobalConfig) GetProxyPortAutoPingFullScanTimeDefault() string {
	if gc == nil || strings.TrimSpace(gc.ProxyPortAutoPingFullScanTimeDefault) == "" {
		return defaultAutoPingFullScanTime
	}
	return strings.TrimSpace(gc.ProxyPortAutoPingFullScanTimeDefault)
}

func (gc *GlobalConfig) GetProxyPortAutoPingFullScanIntervalHoursDefault() int {
	if gc == nil || gc.ProxyPortAutoPingFullScanIntervalHoursDefault <= 0 {
		return defaultAutoPingFullScanIntervalHr
	}
	return gc.ProxyPortAutoPingFullScanIntervalHoursDefault
}

func (gc *GlobalConfig) GetLatencyHistoryMinIntervalMinutes() int {
	if gc == nil || gc.LatencyHistoryMinIntervalMinutes <= 0 {
		return defaultLatencyHistoryMinIntervalMinute
	}
	return gc.LatencyHistoryMinIntervalMinutes
}

func (gc *GlobalConfig) GetLatencyHistoryRenderLimit() int {
	if gc == nil || gc.LatencyHistoryRenderLimit <= 0 {
		return defaultLatencyHistoryRenderLimit
	}
	return gc.LatencyHistoryRenderLimit
}

func (gc *GlobalConfig) GetLatencyHistoryStorageLimit() int {
	if gc == nil || gc.LatencyHistoryStorageLimit <= 0 {
		return defaultLatencyHistoryStorageLimit
	}
	return gc.LatencyHistoryStorageLimit
}

func (gc *GlobalConfig) GetLatencyHistoryRetentionDays() int {
	if gc == nil || gc.LatencyHistoryRetentionDays <= 0 {
		return defaultLatencyHistoryRetentionDays
	}
	return gc.LatencyHistoryRetentionDays
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
		if err := writeFileAtomically(cm.configPath, []byte("[]"), 0644); err != nil {
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
