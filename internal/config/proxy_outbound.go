// Package config provides configuration management functionality.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Protocol types supported by ProxyOutbound
const (
	ProtocolShadowsocks = "shadowsocks"
	ProtocolVMess       = "vmess"
	ProtocolTrojan      = "trojan"
	ProtocolVLESS       = "vless"
	ProtocolSOCKS5      = "socks5"
	ProtocolHTTP        = "http"
	ProtocolHysteria2   = "hysteria2"
	ProtocolAnyTLS      = "anytls"
)

// Supported Shadowsocks encryption methods
var supportedSSMethods = map[string]bool{
	"aes-128-gcm":                   true,
	"aes-256-gcm":                   true,
	"chacha20-ietf-poly1305":        true,
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
}

type proxyOutboundRuntime struct {
	mu             sync.RWMutex
	healthy        bool
	lastCheck      time.Time
	latency        time.Duration
	connCount      int64
	lastError      string
	bytesUp        int64
	bytesDown      int64
	lastActive     time.Time
	activeSince    time.Time
	activeDuration time.Duration
}

// ProxyOutbound represents a proxy outbound node configuration.
type ProxyOutbound struct {
	Name    string `json:"name"`            // Node name, unique identifier
	Type    string `json:"type"`            // Protocol type: shadowsocks, vmess, trojan, vless, hysteria2
	Server  string `json:"server"`          // Server address
	Port    int    `json:"port"`            // Server port
	Enabled bool   `json:"enabled"`         // Whether enabled
	Group   string `json:"group,omitempty"` // Node group for organization

	SubscriptionID     string `json:"subscription_id,omitempty"`      // Source subscription ID if managed by a subscription
	SubscriptionName   string `json:"subscription_name,omitempty"`    // Source subscription display name
	SubscriptionNodeID string `json:"subscription_node_id,omitempty"` // Stable node key within the subscription

	// SOCKS5 / HTTP proxy auth fields
	Username string `json:"username,omitempty"`

	// Shadowsocks specific fields
	Method   string `json:"method,omitempty"`   // Encryption method
	Password string `json:"password,omitempty"` // Password

	// VMess specific fields
	UUID     string `json:"uuid,omitempty"`     // User UUID
	AlterID  int    `json:"alter_id,omitempty"` // AlterID
	Security string `json:"security,omitempty"` // Encryption method

	// VLESS specific fields
	// UUID is reused from VMess
	Flow string `json:"flow,omitempty"` // Flow control

	// Hysteria2 specific fields
	// Password is reused from Shadowsocks
	Obfs                     string `json:"obfs,omitempty"`             // Obfuscation type: salamander
	ObfsPassword             string `json:"obfs_password,omitempty"`    // Obfuscation password
	PortHopping              string `json:"port_hopping,omitempty"`     // Port hopping range (e.g., "20000-55000")
	HopInterval              int    `json:"hop_interval,omitempty"`     // Port hopping interval in seconds (default: 10)
	UpMbps                   int    `json:"up_mbps,omitempty"`          // Upload bandwidth limit in Mbps
	DownMbps                 int    `json:"down_mbps,omitempty"`        // Download bandwidth limit in Mbps
	ALPN                     string `json:"alpn,omitempty"`             // TLS ALPN (comma-separated, e.g., "h3,h2")
	CertFingerprint          string `json:"cert_fingerprint,omitempty"` // Server certificate SHA256 fingerprint for pinning
	DisableMTU               bool   `json:"disable_mtu,omitempty"`      // Disable Path MTU Discovery
	IdleSessionCheckInterval int    `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       int    `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int    `json:"min_idle_session,omitempty"`

	// TLS common fields
	TLS         bool   `json:"tls,omitempty"`         // Enable TLS
	SNI         string `json:"sni,omitempty"`         // TLS SNI
	Insecure    bool   `json:"insecure,omitempty"`    // Skip certificate verification
	Fingerprint string `json:"fingerprint,omitempty"` // TLS fingerprint

	// Reality specific fields (for VLESS)
	Reality          bool   `json:"reality,omitempty"`            // Enable Reality
	RealityPublicKey string `json:"reality_public_key,omitempty"` // Reality public key (pbk)
	RealityShortID   string `json:"reality_short_id,omitempty"`   // Reality short ID (sid)

	// Transport fields (WebSocket, gRPC, etc.)
	Network         string `json:"network,omitempty"`           // Transport type: tcp, ws, grpc, httpupgrade, xhttp
	WSPath          string `json:"ws_path,omitempty"`           // WebSocket/XHTTP path
	WSHost          string `json:"ws_host,omitempty"`           // WebSocket/XHTTP Host header
	XHTTPMode       string `json:"xhttp_mode,omitempty"`        // XHTTP mode override
	GRPCServiceName string `json:"grpc_service_name,omitempty"` // gRPC service name
	GRPCAuthority   string `json:"grpc_authority,omitempty"`    // gRPC authority / :authority header override

	// Test results (persisted)
	TCPLatencyMs  int64 `json:"tcp_latency_ms,omitempty"`  // TCP ping latency in milliseconds
	HTTPLatencyMs int64 `json:"http_latency_ms,omitempty"` // HTTP test latency in milliseconds
	UDPAvailable  *bool `json:"udp_available,omitempty"`   // UDP (MCBE) test result
	UDPLatencyMs  int64 `json:"udp_latency_ms,omitempty"`  // UDP (MCBE) latency in milliseconds

	AutoSelectBlocked        bool       `json:"auto_select_blocked,omitempty"`
	AutoSelectBlockReason    string     `json:"auto_select_block_reason,omitempty"`
	AutoSelectBlockExpiresAt *time.Time `json:"auto_select_block_expires_at,omitempty"`

	// Runtime state (not serialized)
	mu            sync.RWMutex          `json:"-"`
	runtime       *proxyOutboundRuntime `json:"-"`
	runtimeInitMu sync.Mutex            `json:"-"`
}

// Validate checks if all required fields are present and valid based on protocol type.
// Returns an error if any required field is missing or invalid.
func (p *ProxyOutbound) Validate() error {
	if p.Name == "" {
		return errors.New("missing required field: name")
	}
	if p.Type == "" {
		return errors.New("missing required field: type")
	}
	if p.Server == "" {
		return errors.New("missing required field: server")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("invalid field: port must be between 1 and 65535, got %d", p.Port)
	}

	// Protocol-specific validation
	switch strings.ToLower(p.Type) {
	case ProtocolShadowsocks:
		return p.validateShadowsocks()
	case ProtocolVMess:
		return p.validateVMess()
	case ProtocolTrojan:
		return p.validateTrojan()
	case ProtocolVLESS:
		return p.validateVLESS()
	case ProtocolSOCKS5:
		return p.validateSOCKS5()
	case ProtocolHTTP:
		return p.validateHTTP()
	case ProtocolHysteria2:
		return p.validateHysteria2()
	case ProtocolAnyTLS:
		return p.validateAnyTLS()
	default:
		return fmt.Errorf("invalid field: type must be one of shadowsocks, vmess, trojan, vless, socks5, http, hysteria2, anytls, got %s", p.Type)
	}
}

func (p *ProxyOutbound) validateShadowsocks() error {
	if p.Method == "" {
		return errors.New("missing required field: method (required for shadowsocks)")
	}
	if !supportedSSMethods[p.Method] {
		return fmt.Errorf("invalid field: method '%s' is not supported for shadowsocks", p.Method)
	}
	if p.Password == "" {
		return errors.New("missing required field: password (required for shadowsocks)")
	}
	return nil
}

func (p *ProxyOutbound) validateVMess() error {
	if p.UUID == "" {
		return errors.New("missing required field: uuid (required for vmess)")
	}
	return nil
}

func (p *ProxyOutbound) validateTrojan() error {
	if p.Password == "" {
		return errors.New("missing required field: password (required for trojan)")
	}
	return nil
}

func (p *ProxyOutbound) validateVLESS() error {
	if p.UUID == "" {
		return errors.New("missing required field: uuid (required for vless)")
	}
	if p.Reality && p.RealityPublicKey == "" {
		return errors.New("missing required field: reality_public_key (required when reality is enabled)")
	}
	return p.validateTransport()
}

func (p *ProxyOutbound) validateSOCKS5() error {
	return p.validateOptionalUsernamePassword()
}

func (p *ProxyOutbound) validateHTTP() error {
	return p.validateOptionalUsernamePassword()
}

func (p *ProxyOutbound) validateOptionalUsernamePassword() error {
	if p.Password != "" && p.Username == "" {
		return errors.New("missing required field: username (required when password is set)")
	}
	return nil
}

func (p *ProxyOutbound) validateTransport() error {
	switch strings.ToLower(strings.TrimSpace(p.Network)) {
	case "", "tcp", "ws", "httpupgrade", "http-upgrade", "xhttp":
		return nil
	case "grpc":
		if strings.TrimSpace(p.GRPCServiceName) == "" {
			return errors.New("missing required field: grpc_service_name (required when network is grpc)")
		}
		return nil
	default:
		return fmt.Errorf("invalid field: network must be one of tcp, ws, grpc, httpupgrade, xhttp, got %s", p.Network)
	}
}

func (p *ProxyOutbound) validateHysteria2() error {
	if p.Password == "" {
		return errors.New("missing required field: password (required for hysteria2)")
	}
	return nil
}

func (p *ProxyOutbound) validateAnyTLS() error {
	if p.Password == "" {
		return errors.New("missing required field: password (required for anytls)")
	}
	if !p.TLS {
		return errors.New("missing required field: tls must be enabled for anytls")
	}
	if p.Reality && p.RealityPublicKey == "" {
		return errors.New("missing required field: reality_public_key (required when reality is enabled)")
	}
	if p.IdleSessionCheckInterval < 0 {
		return errors.New("invalid field: idle_session_check_interval must be >= 0")
	}
	if p.IdleSessionTimeout < 0 {
		return errors.New("invalid field: idle_session_timeout must be >= 0")
	}
	if p.MinIdleSession < 0 {
		return errors.New("invalid field: min_idle_session must be >= 0")
	}
	return nil
}

// ToJSON serializes the ProxyOutbound to JSON.
func (p *ProxyOutbound) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// FromJSON deserializes a ProxyOutbound from JSON.
func FromJSON(data []byte) (*ProxyOutbound, error) {
	var p ProxyOutbound
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse proxy outbound JSON: %w", err)
	}
	return &p, nil
}

// Clone creates a deep copy of the ProxyOutbound (excluding runtime state).
func (p *ProxyOutbound) Clone() *ProxyOutbound {
	p.mu.RLock()
	clone := &ProxyOutbound{
		Name:                     p.Name,
		Type:                     p.Type,
		Server:                   p.Server,
		Port:                     p.Port,
		Enabled:                  p.Enabled,
		Group:                    p.Group,
		AutoSelectBlocked:        p.AutoSelectBlocked,
		AutoSelectBlockReason:    p.AutoSelectBlockReason,
		SubscriptionID:           p.SubscriptionID,
		SubscriptionName:         p.SubscriptionName,
		SubscriptionNodeID:       p.SubscriptionNodeID,
		Username:                 p.Username,
		Method:                   p.Method,
		Password:                 p.Password,
		UUID:                     p.UUID,
		AlterID:                  p.AlterID,
		Security:                 p.Security,
		Flow:                     p.Flow,
		Obfs:                     p.Obfs,
		ObfsPassword:             p.ObfsPassword,
		PortHopping:              p.PortHopping,
		HopInterval:              p.HopInterval,
		UpMbps:                   p.UpMbps,
		DownMbps:                 p.DownMbps,
		ALPN:                     p.ALPN,
		CertFingerprint:          p.CertFingerprint,
		DisableMTU:               p.DisableMTU,
		IdleSessionCheckInterval: p.IdleSessionCheckInterval,
		IdleSessionTimeout:       p.IdleSessionTimeout,
		MinIdleSession:           p.MinIdleSession,
		TLS:                      p.TLS,
		SNI:                      p.SNI,
		Insecure:                 p.Insecure,
		Fingerprint:              p.Fingerprint,
		Reality:                  p.Reality,
		RealityPublicKey:         p.RealityPublicKey,
		RealityShortID:           p.RealityShortID,
		Network:                  p.Network,
		WSPath:                   p.WSPath,
		WSHost:                   p.WSHost,
		XHTTPMode:                p.XHTTPMode,
		GRPCServiceName:          p.GRPCServiceName,
		GRPCAuthority:            p.GRPCAuthority,
		TCPLatencyMs:             p.TCPLatencyMs,
		HTTPLatencyMs:            p.HTTPLatencyMs,
		UDPLatencyMs:             p.UDPLatencyMs,
		runtime:                  p.runtimeState(),
	}
	if p.UDPAvailable != nil {
		udp := *p.UDPAvailable
		clone.UDPAvailable = &udp
	}
	if p.AutoSelectBlockExpiresAt != nil {
		expiresAt := *p.AutoSelectBlockExpiresAt
		clone.AutoSelectBlockExpiresAt = &expiresAt
	}
	p.mu.RUnlock()
	return clone
}

func (p *ProxyOutbound) IsAutoSelectBlocked() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.isAutoSelectBlockedLocked(time.Now())
}

func (p *ProxyOutbound) GetEffectiveAutoSelectBlock() (bool, string, *time.Time) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.isAutoSelectBlockedLocked(time.Now()) {
		return false, "", nil
	}
	if p.AutoSelectBlockExpiresAt == nil {
		return true, p.AutoSelectBlockReason, nil
	}
	expiresAt := *p.AutoSelectBlockExpiresAt
	return true, p.AutoSelectBlockReason, &expiresAt
}

func (p *ProxyOutbound) isAutoSelectBlockedLocked(now time.Time) bool {
	if !p.AutoSelectBlocked {
		return false
	}
	if p.AutoSelectBlockExpiresAt == nil {
		return true
	}
	return p.AutoSelectBlockExpiresAt.After(now)
}

func (p *ProxyOutbound) runtimeState() *proxyOutboundRuntime {
	if p.runtime != nil {
		return p.runtime
	}
	p.runtimeInitMu.Lock()
	defer p.runtimeInitMu.Unlock()
	if p.runtime == nil {
		p.runtime = &proxyOutboundRuntime{}
	}
	return p.runtime
}

// GetHealthy returns the health status.
func (p *ProxyOutbound) GetHealthy() bool {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.healthy
}

// SetHealthy sets the health status.
func (p *ProxyOutbound) SetHealthy(healthy bool) {
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.healthy = healthy
}

// GetLastCheck returns the last health check time.
func (p *ProxyOutbound) GetLastCheck() time.Time {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.lastCheck
}

// SetLastCheck sets the last health check time.
func (p *ProxyOutbound) SetLastCheck(t time.Time) {
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.lastCheck = t
}

// GetLatency returns the latency.
func (p *ProxyOutbound) GetLatency() time.Duration {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.latency
}

// SetLatency sets the latency.
func (p *ProxyOutbound) SetLatency(d time.Duration) {
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.latency = d
}

// GetConnCount returns the connection count.
func (p *ProxyOutbound) GetConnCount() int64 {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.connCount
}

// IncrConnCount increments the connection count.
func (p *ProxyOutbound) IncrConnCount() {
	now := time.Now()
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.connCount == 0 {
		rt.activeSince = now
	}
	rt.connCount++
	rt.lastActive = now
}

// DecrConnCount decrements the connection count.
func (p *ProxyOutbound) DecrConnCount() {
	now := time.Now()
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.connCount > 0 {
		rt.connCount--
		rt.lastActive = now
		if rt.connCount == 0 && !rt.activeSince.IsZero() {
			rt.activeDuration += now.Sub(rt.activeSince)
			rt.activeSince = time.Time{}
		}
	}
}

// GetLastError returns the last error message.
func (p *ProxyOutbound) GetLastError() string {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.lastError
}

// SetLastError sets the last error message.
func (p *ProxyOutbound) SetLastError(err string) {
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.lastError = err
}

func (p *ProxyOutbound) GetTCPLatencyMs() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.TCPLatencyMs
}

func (p *ProxyOutbound) SetTCPLatencyMs(ms int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.TCPLatencyMs = ms
}

// GetHTTPLatencyMs returns the HTTP latency in milliseconds.
func (p *ProxyOutbound) GetHTTPLatencyMs() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.HTTPLatencyMs
}

// SetHTTPLatencyMs sets the HTTP latency in milliseconds.
func (p *ProxyOutbound) SetHTTPLatencyMs(ms int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HTTPLatencyMs = ms
}

// GetUDPAvailable returns the UDP availability status.
func (p *ProxyOutbound) GetUDPAvailable() *bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.UDPAvailable
}

// SetUDPAvailable sets the UDP availability status.
func (p *ProxyOutbound) SetUDPAvailable(available *bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.UDPAvailable = available
}

func (p *ProxyOutbound) GetUDPLatencyMs() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.UDPLatencyMs
}

func (p *ProxyOutbound) SetUDPLatencyMs(ms int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.UDPLatencyMs = ms
}

func (p *ProxyOutbound) AddBytesUp(n int64) {
	if n <= 0 {
		return
	}
	now := time.Now()
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.bytesUp += n
	rt.lastActive = now
}

func (p *ProxyOutbound) AddBytesDown(n int64) {
	if n <= 0 {
		return
	}
	now := time.Now()
	rt := p.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.bytesDown += n
	rt.lastActive = now
}

func (p *ProxyOutbound) GetBytesUp() int64 {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.bytesUp
}

func (p *ProxyOutbound) GetBytesDown() int64 {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.bytesDown
}

func (p *ProxyOutbound) GetLastActive() time.Time {
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.lastActive
}

func (p *ProxyOutbound) GetActiveDuration() time.Duration {
	now := time.Now()
	rt := p.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if rt.connCount > 0 && !rt.activeSince.IsZero() {
		return rt.activeDuration + now.Sub(rt.activeSince)
	}
	return rt.activeDuration
}

// Equal checks if two ProxyOutbound configurations are equivalent (excluding runtime state).
func (p *ProxyOutbound) Equal(other *ProxyOutbound) bool {
	if other == nil {
		return false
	}
	return p.Name == other.Name &&
		p.Type == other.Type &&
		p.Server == other.Server &&
		p.Port == other.Port &&
		p.Enabled == other.Enabled &&
		p.Group == other.Group &&
		p.Username == other.Username &&
		p.Method == other.Method &&
		p.Password == other.Password &&
		p.UUID == other.UUID &&
		p.AlterID == other.AlterID &&
		p.Security == other.Security &&
		p.Flow == other.Flow &&
		p.Obfs == other.Obfs &&
		p.ObfsPassword == other.ObfsPassword &&
		p.PortHopping == other.PortHopping &&
		p.HopInterval == other.HopInterval &&
		p.UpMbps == other.UpMbps &&
		p.DownMbps == other.DownMbps &&
		p.ALPN == other.ALPN &&
		p.CertFingerprint == other.CertFingerprint &&
		p.DisableMTU == other.DisableMTU &&
		p.IdleSessionCheckInterval == other.IdleSessionCheckInterval &&
		p.IdleSessionTimeout == other.IdleSessionTimeout &&
		p.MinIdleSession == other.MinIdleSession &&
		p.TLS == other.TLS &&
		p.SNI == other.SNI &&
		p.Insecure == other.Insecure &&
		p.Fingerprint == other.Fingerprint &&
		p.Reality == other.Reality &&
		p.RealityPublicKey == other.RealityPublicKey &&
		p.RealityShortID == other.RealityShortID &&
		p.Network == other.Network &&
		p.WSPath == other.WSPath &&
		p.WSHost == other.WSHost &&
		p.XHTTPMode == other.XHTTPMode &&
		p.GRPCServiceName == other.GRPCServiceName &&
		p.GRPCAuthority == other.GRPCAuthority
}
