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
	ProtocolHysteria2   = "hysteria2"
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

// ProxyOutbound represents a proxy outbound node configuration.
type ProxyOutbound struct {
	Name    string `json:"name"`            // Node name, unique identifier
	Type    string `json:"type"`            // Protocol type: shadowsocks, vmess, trojan, vless, hysteria2
	Server  string `json:"server"`          // Server address
	Port    int    `json:"port"`            // Server port
	Enabled bool   `json:"enabled"`         // Whether enabled
	Group   string `json:"group,omitempty"` // Node group for organization

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
	Obfs            string `json:"obfs,omitempty"`             // Obfuscation type: salamander
	ObfsPassword    string `json:"obfs_password,omitempty"`    // Obfuscation password
	PortHopping     string `json:"port_hopping,omitempty"`     // Port hopping range (e.g., "20000-55000")
	HopInterval     int    `json:"hop_interval,omitempty"`     // Port hopping interval in seconds (default: 10)
	UpMbps          int    `json:"up_mbps,omitempty"`          // Upload bandwidth limit in Mbps
	DownMbps        int    `json:"down_mbps,omitempty"`        // Download bandwidth limit in Mbps
	ALPN            string `json:"alpn,omitempty"`             // TLS ALPN (comma-separated, e.g., "h3,h2")
	CertFingerprint string `json:"cert_fingerprint,omitempty"` // Server certificate SHA256 fingerprint for pinning
	DisableMTU      bool   `json:"disable_mtu,omitempty"`      // Disable Path MTU Discovery

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
	Network string `json:"network,omitempty"` // Transport type: tcp, ws, grpc
	WSPath  string `json:"ws_path,omitempty"` // WebSocket path
	WSHost  string `json:"ws_host,omitempty"` // WebSocket Host header

	// Test results (persisted)
	TCPLatencyMs  int64 `json:"tcp_latency_ms,omitempty"`  // TCP ping latency in milliseconds
	HTTPLatencyMs int64 `json:"http_latency_ms,omitempty"` // HTTP test latency in milliseconds
	UDPAvailable  *bool `json:"udp_available,omitempty"`   // UDP (MCBE) test result
	UDPLatencyMs  int64 `json:"udp_latency_ms,omitempty"`  // UDP (MCBE) latency in milliseconds

	// Runtime state (not serialized)
	mu        sync.RWMutex  `json:"-"`
	healthy   bool          `json:"-"`
	lastCheck time.Time     `json:"-"`
	latency   time.Duration `json:"-"`
	connCount int64         `json:"-"`
	lastError string        `json:"-"`
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
	case ProtocolHysteria2:
		return p.validateHysteria2()
	default:
		return fmt.Errorf("invalid field: type must be one of shadowsocks, vmess, trojan, vless, hysteria2, got %s", p.Type)
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
	return nil
}

func (p *ProxyOutbound) validateHysteria2() error {
	if p.Password == "" {
		return errors.New("missing required field: password (required for hysteria2)")
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
	clone := &ProxyOutbound{
		Name:             p.Name,
		Type:             p.Type,
		Server:           p.Server,
		Port:             p.Port,
		Enabled:          p.Enabled,
		Group:            p.Group,
		Method:           p.Method,
		Password:         p.Password,
		UUID:             p.UUID,
		AlterID:          p.AlterID,
		Security:         p.Security,
		Flow:             p.Flow,
		Obfs:             p.Obfs,
		ObfsPassword:     p.ObfsPassword,
		PortHopping:      p.PortHopping,
		HopInterval:      p.HopInterval,
		UpMbps:           p.UpMbps,
		DownMbps:         p.DownMbps,
		ALPN:             p.ALPN,
		CertFingerprint:  p.CertFingerprint,
		DisableMTU:       p.DisableMTU,
		TLS:              p.TLS,
		SNI:              p.SNI,
		Insecure:         p.Insecure,
		Fingerprint:      p.Fingerprint,
		Reality:          p.Reality,
		RealityPublicKey: p.RealityPublicKey,
		RealityShortID:   p.RealityShortID,
		Network:          p.Network,
		WSPath:           p.WSPath,
		WSHost:           p.WSHost,
		TCPLatencyMs:     p.TCPLatencyMs,
		HTTPLatencyMs:    p.HTTPLatencyMs,
		UDPLatencyMs:     p.UDPLatencyMs,
	}
	if p.UDPAvailable != nil {
		udp := *p.UDPAvailable
		clone.UDPAvailable = &udp
	}
	return clone
}

// GetHealthy returns the health status.
func (p *ProxyOutbound) GetHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy
}

// SetHealthy sets the health status.
func (p *ProxyOutbound) SetHealthy(healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthy = healthy
}

// GetLastCheck returns the last health check time.
func (p *ProxyOutbound) GetLastCheck() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastCheck
}

// SetLastCheck sets the last health check time.
func (p *ProxyOutbound) SetLastCheck(t time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastCheck = t
}

// GetLatency returns the latency.
func (p *ProxyOutbound) GetLatency() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.latency
}

// SetLatency sets the latency.
func (p *ProxyOutbound) SetLatency(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.latency = d
}

// GetConnCount returns the connection count.
func (p *ProxyOutbound) GetConnCount() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connCount
}

// IncrConnCount increments the connection count.
func (p *ProxyOutbound) IncrConnCount() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connCount++
}

// DecrConnCount decrements the connection count.
func (p *ProxyOutbound) DecrConnCount() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.connCount > 0 {
		p.connCount--
	}
}

// GetLastError returns the last error message.
func (p *ProxyOutbound) GetLastError() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastError
}

// SetLastError sets the last error message.
func (p *ProxyOutbound) SetLastError(err string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastError = err
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
		p.TLS == other.TLS &&
		p.SNI == other.SNI &&
		p.Insecure == other.Insecure &&
		p.Fingerprint == other.Fingerprint &&
		p.Reality == other.Reality &&
		p.RealityPublicKey == other.RealityPublicKey &&
		p.RealityShortID == other.RealityShortID &&
		p.Network == other.Network &&
		p.WSPath == other.WSPath &&
		p.WSHost == other.WSHost
}
