// Package api provides REST API functionality using Gin framework.
package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

// ProxyOutboundHandler handles REST API requests for proxy outbound management.
// Requirements: 5.3
type ProxyOutboundHandler struct {
	configMgr   *config.ProxyOutboundConfigManager
	outboundMgr proxy.OutboundManager
}

// NewProxyOutboundHandler creates a new ProxyOutboundHandler instance.
func NewProxyOutboundHandler(configMgr *config.ProxyOutboundConfigManager, outboundMgr proxy.OutboundManager) *ProxyOutboundHandler {
	return &ProxyOutboundHandler{
		configMgr:   configMgr,
		outboundMgr: outboundMgr,
	}
}

// ProxyOutboundDTO represents the API response for a proxy outbound.
type ProxyOutboundDTO struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Enabled       bool   `json:"enabled"`
	Group         string `json:"group,omitempty"`
	Healthy       bool   `json:"healthy"`
	LatencyMs     int64  `json:"latency_ms"`
	HTTPLatencyMs int64  `json:"http_latency_ms,omitempty"`
	UDPAvailable  *bool  `json:"udp_available,omitempty"`
	UDPLatencyMs  int64  `json:"udp_latency_ms,omitempty"`
	ConnCount     int64  `json:"conn_count"`
	LastCheck     string `json:"last_check,omitempty"`
	LastError     string `json:"last_error,omitempty"`

	// Protocol-specific fields (optional in response)
	Method       string `json:"method,omitempty"`
	Password     string `json:"password,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	AlterID      int    `json:"alter_id,omitempty"`
	Security     string `json:"security,omitempty"`
	Flow         string `json:"flow,omitempty"`
	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	TLS          bool   `json:"tls,omitempty"`
	SNI          string `json:"sni,omitempty"`
	Insecure     bool   `json:"insecure,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`

	// Hysteria2 specific fields
	PortHopping     string `json:"port_hopping,omitempty"`
	HopInterval     int    `json:"hop_interval,omitempty"`
	UpMbps          int    `json:"up_mbps,omitempty"`
	DownMbps        int    `json:"down_mbps,omitempty"`
	ALPN            string `json:"alpn,omitempty"`
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	DisableMTU      bool   `json:"disable_mtu,omitempty"`

	// Reality specific fields (for VLESS)
	Reality          bool   `json:"reality,omitempty"`
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	RealityShortID   string `json:"reality_short_id,omitempty"`

	// Transport fields
	Network string `json:"network,omitempty"`
	WSPath  string `json:"ws_path,omitempty"`
	WSHost  string `json:"ws_host,omitempty"`
}

// toDTO converts a ProxyOutbound to ProxyOutboundDTO with health status.
func (h *ProxyOutboundHandler) toDTO(cfg *config.ProxyOutbound) ProxyOutboundDTO {
	dto := ProxyOutboundDTO{
		Name:         cfg.Name,
		Type:         cfg.Type,
		Server:       cfg.Server,
		Port:         cfg.Port,
		Enabled:      cfg.Enabled,
		Group:        cfg.Group,
		Method:       cfg.Method,
		Password:     cfg.Password,
		UUID:         cfg.UUID,
		AlterID:      cfg.AlterID,
		Security:     cfg.Security,
		Flow:         cfg.Flow,
		Obfs:         cfg.Obfs,
		ObfsPassword: cfg.ObfsPassword,
		TLS:          cfg.TLS,
		SNI:          cfg.SNI,
		Insecure:     cfg.Insecure,
		Fingerprint:  cfg.Fingerprint,
		// Hysteria2 specific
		PortHopping:     cfg.PortHopping,
		HopInterval:     cfg.HopInterval,
		UpMbps:          cfg.UpMbps,
		DownMbps:        cfg.DownMbps,
		ALPN:            cfg.ALPN,
		CertFingerprint: cfg.CertFingerprint,
		DisableMTU:      cfg.DisableMTU,
		// Reality specific
		Reality:          cfg.Reality,
		RealityPublicKey: cfg.RealityPublicKey,
		RealityShortID:   cfg.RealityShortID,
		// Transport
		Network: cfg.Network,
		WSPath:  cfg.WSPath,
		WSHost:  cfg.WSHost,
	}

	// Use persisted test results from config
	dto.LatencyMs = cfg.TCPLatencyMs
	dto.HTTPLatencyMs = cfg.HTTPLatencyMs
	dto.UDPAvailable = cfg.UDPAvailable
	dto.UDPLatencyMs = cfg.UDPLatencyMs

	// Get runtime health status from outbound manager if available
	if h.outboundMgr != nil {
		if status := h.outboundMgr.GetHealthStatus(cfg.Name); status != nil {
			dto.Healthy = status.Healthy
			dto.ConnCount = status.ConnCount
			if !status.LastCheck.IsZero() {
				dto.LastCheck = status.LastCheck.Format(time.RFC3339)
			}
			dto.LastError = status.LastError
		}
	}

	return dto
}

// CreateProxyOutboundRequest represents the request body for creating a proxy outbound.
type CreateProxyOutboundRequest struct {
	Name         string `json:"name" binding:"required"`
	Type         string `json:"type" binding:"required"`
	Server       string `json:"server" binding:"required"`
	Port         int    `json:"port" binding:"required"`
	Enabled      bool   `json:"enabled"`
	Group        string `json:"group,omitempty"`
	Method       string `json:"method,omitempty"`
	Password     string `json:"password,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	AlterID      int    `json:"alter_id,omitempty"`
	Security     string `json:"security,omitempty"`
	Flow         string `json:"flow,omitempty"`
	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	TLS          bool   `json:"tls,omitempty"`
	SNI          string `json:"sni,omitempty"`
	Insecure     bool   `json:"insecure,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`

	// Hysteria2 specific fields
	PortHopping     string `json:"port_hopping,omitempty"`
	HopInterval     int    `json:"hop_interval,omitempty"`
	UpMbps          int    `json:"up_mbps,omitempty"`
	DownMbps        int    `json:"down_mbps,omitempty"`
	ALPN            string `json:"alpn,omitempty"`
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	DisableMTU      bool   `json:"disable_mtu,omitempty"`

	// Reality specific fields (for VLESS)
	Reality          bool   `json:"reality,omitempty"`
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	RealityShortID   string `json:"reality_short_id,omitempty"`

	// Transport fields (WebSocket, gRPC, etc.)
	Network string `json:"network,omitempty"`
	WSPath  string `json:"ws_path,omitempty"`
	WSHost  string `json:"ws_host,omitempty"`
}

// toProxyOutbound converts the request to a ProxyOutbound config.
func (r *CreateProxyOutboundRequest) toProxyOutbound() *config.ProxyOutbound {
	return &config.ProxyOutbound{
		Name:         r.Name,
		Type:         r.Type,
		Server:       r.Server,
		Port:         r.Port,
		Enabled:      r.Enabled,
		Group:        r.Group,
		Method:       r.Method,
		Password:     r.Password,
		UUID:         r.UUID,
		AlterID:      r.AlterID,
		Security:     r.Security,
		Flow:         r.Flow,
		Obfs:         r.Obfs,
		ObfsPassword: r.ObfsPassword,
		TLS:          r.TLS,
		SNI:          r.SNI,
		Insecure:     r.Insecure,
		Fingerprint:  r.Fingerprint,
		// Hysteria2 specific
		PortHopping:     r.PortHopping,
		HopInterval:     r.HopInterval,
		UpMbps:          r.UpMbps,
		DownMbps:        r.DownMbps,
		ALPN:            r.ALPN,
		CertFingerprint: r.CertFingerprint,
		DisableMTU:      r.DisableMTU,
		// Reality specific
		Reality:          r.Reality,
		RealityPublicKey: r.RealityPublicKey,
		RealityShortID:   r.RealityShortID,
		// Transport
		Network: r.Network,
		WSPath:  r.WSPath,
		WSHost:  r.WSHost,
	}
}

// TestResult represents the result of a proxy connection test.
type TestResult struct {
	Success   bool   `json:"success"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// NameRequest represents a request with just a name field.
type NameRequest struct {
	Name string `json:"name" binding:"required"`
}

// ListProxyOutbounds returns all configured proxy outbounds.
// GET /api/proxy-outbounds
// Requirements: 5.3
func (h *ProxyOutboundHandler) ListProxyOutbounds(c *gin.Context) {
	outbounds := h.configMgr.GetAllOutbounds()

	dtos := make([]ProxyOutboundDTO, 0, len(outbounds))
	for _, outbound := range outbounds {
		dtos = append(dtos, h.toDTO(outbound))
	}

	respondSuccess(c, dtos)
}

// CreateProxyOutbound creates a new proxy outbound configuration.
// POST /api/proxy-outbounds
// Requirements: 5.3
func (h *ProxyOutboundHandler) CreateProxyOutbound(c *gin.Context) {
	var req CreateProxyOutboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	cfg := req.toProxyOutbound()

	// Add to config manager (validates and persists)
	if err := h.configMgr.AddOutbound(cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to create proxy outbound", err.Error())
		return
	}

	// Also add to outbound manager for runtime use
	if h.outboundMgr != nil {
		if err := h.outboundMgr.AddOutbound(cfg); err != nil {
			// Log but don't fail - config is saved
			// The outbound manager will sync on next reload
		}
	}

	respondSuccess(c, h.toDTO(cfg))
}

// GetProxyOutbound returns a single proxy outbound by name.
// GET /api/proxy-outbounds/:name
// Requirements: 5.3
func (h *ProxyOutboundHandler) GetProxyOutbound(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	outbound, exists := h.configMgr.GetOutbound(name)
	if !exists {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}

	respondSuccess(c, h.toDTO(outbound))
}

// UpdateProxyOutbound updates an existing proxy outbound configuration.
// PUT /api/proxy-outbounds/:name
// Requirements: 5.3
func (h *ProxyOutboundHandler) UpdateProxyOutbound(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	var req CreateProxyOutboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	cfg := req.toProxyOutbound()

	// Update in config manager (validates and persists)
	if err := h.configMgr.UpdateOutbound(name, cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to update proxy outbound", err.Error())
		return
	}

	// Also update in outbound manager for runtime use
	if h.outboundMgr != nil {
		if err := h.outboundMgr.UpdateOutbound(name, cfg); err != nil {
			// Log but don't fail - config is saved
		}
	}

	respondSuccess(c, h.toDTO(cfg))
}

// DeleteProxyOutbound removes a proxy outbound configuration.
// DELETE /api/proxy-outbounds/:name
// Requirements: 5.3
func (h *ProxyOutboundHandler) DeleteProxyOutbound(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	// Delete from config manager (persists)
	if err := h.configMgr.DeleteOutbound(name); err != nil {
		respondError(c, http.StatusNotFound, "Failed to delete proxy outbound", err.Error())
		return
	}

	// Also delete from outbound manager
	if h.outboundMgr != nil {
		// This will also cascade update server configs
		_ = h.outboundMgr.DeleteOutbound(name)
	}

	respondSuccessWithMsg(c, "代理出站节点已删除", nil)
}

// TestProxyOutbound tests the connection to a proxy outbound.
// POST /api/proxy-outbounds/:name/test (legacy, kept for compatibility)
// Requirements: 4.3, 5.3
func (h *ProxyOutboundHandler) TestProxyOutbound(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	h.doTestOutbound(c, name)
}

// TestProxyOutboundByBody tests the connection to a proxy outbound using name from request body.
// POST /api/proxy-outbounds/test
// Requirements: 4.3, 5.3
func (h *ProxyOutboundHandler) TestProxyOutboundByBody(c *gin.Context) {
	var req NameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	h.doTestOutbound(c, req.Name)
}

// doTestOutbound performs the actual test logic
func (h *ProxyOutboundHandler) doTestOutbound(c *gin.Context, name string) {
	// Check if outbound exists
	_, exists := h.configMgr.GetOutbound(name)
	if !exists {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}

	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}

	// Perform health check with timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	startTime := time.Now()
	err := h.outboundMgr.CheckHealth(ctx, name)
	latency := time.Since(startTime)

	result := TestResult{
		Success:   err == nil,
		LatencyMs: latency.Milliseconds(),
	}

	if err != nil {
		result.Error = err.Error()
	}

	// Persist TCP latency to config file
	if outbound, ok := h.configMgr.GetOutbound(name); ok {
		if result.Success {
			outbound.TCPLatencyMs = result.LatencyMs
		} else {
			outbound.TCPLatencyMs = 0
		}
		h.configMgr.UpdateOutbound(name, outbound)
	}

	respondSuccess(c, result)
}

// GetProxyOutboundHealth returns the health status of a proxy outbound.
// GET /api/proxy-outbounds/:name/health (legacy, kept for compatibility)
// Requirements: 4.3, 5.3
func (h *ProxyOutboundHandler) GetProxyOutboundHealth(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	h.doGetHealth(c, name)
}

// GetProxyOutboundHealthByBody returns the health status using name from request body.
// POST /api/proxy-outbounds/health
// Requirements: 4.3, 5.3
func (h *ProxyOutboundHandler) GetProxyOutboundHealthByBody(c *gin.Context) {
	var req NameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	h.doGetHealth(c, req.Name)
}

// doGetHealth performs the actual health check logic
func (h *ProxyOutboundHandler) doGetHealth(c *gin.Context, name string) {
	// Check if outbound exists in config
	_, exists := h.configMgr.GetOutbound(name)
	if !exists {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}

	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}

	status := h.outboundMgr.GetHealthStatus(name)
	if status == nil {
		// Return default status if not yet checked
		status = &proxy.HealthStatus{
			Healthy:   false,
			ConnCount: 0,
		}
	}

	// Convert to response format
	response := map[string]interface{}{
		"healthy":    status.Healthy,
		"latency_ms": status.Latency.Milliseconds(),
		"conn_count": status.ConnCount,
	}

	if !status.LastCheck.IsZero() {
		response["last_check"] = status.LastCheck.Format(time.RFC3339)
	}

	if status.LastError != "" {
		response["last_error"] = status.LastError
	}

	respondSuccess(c, response)
}

// GetProxyOutboundByBody returns a single proxy outbound using name from request body.
// POST /api/proxy-outbounds/get
// Requirements: 5.3
func (h *ProxyOutboundHandler) GetProxyOutboundByBody(c *gin.Context) {
	var req NameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	outbound, exists := h.configMgr.GetOutbound(req.Name)
	if !exists {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}

	respondSuccess(c, h.toDTO(outbound))
}

// UpdateProxyOutboundByBody updates an existing proxy outbound using name from request body.
// POST /api/proxy-outbounds/update
// Requirements: 5.3
func (h *ProxyOutboundHandler) UpdateProxyOutboundByBody(c *gin.Context) {
	var req CreateProxyOutboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Use the name from the request body
	cfg := req.toProxyOutbound()

	// Update in config manager (validates and persists)
	if err := h.configMgr.UpdateOutbound(req.Name, cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to update proxy outbound", err.Error())
		return
	}

	// Also update in outbound manager for runtime use
	if h.outboundMgr != nil {
		if err := h.outboundMgr.UpdateOutbound(req.Name, cfg); err != nil {
			// Log but don't fail - config is saved
		}
	}

	respondSuccess(c, h.toDTO(cfg))
}

// DeleteProxyOutboundByBody removes a proxy outbound using name from request body.
// POST /api/proxy-outbounds/delete
// Requirements: 5.3
func (h *ProxyOutboundHandler) DeleteProxyOutboundByBody(c *gin.Context) {
	var req NameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Delete from config manager (persists)
	if err := h.configMgr.DeleteOutbound(req.Name); err != nil {
		respondError(c, http.StatusNotFound, "Failed to delete proxy outbound", err.Error())
		return
	}

	// Also delete from outbound manager
	if h.outboundMgr != nil {
		// This will also cascade update server configs
		_ = h.outboundMgr.DeleteOutbound(req.Name)
	}

	respondSuccessWithMsg(c, "代理出站节点已删除", nil)
}

// DetailedTestResult represents the result of a detailed proxy test.
type DetailedTestResult struct {
	Success    bool             `json:"success"`
	Name       string           `json:"name"`
	PingTest   *PingTestResult  `json:"ping_test,omitempty"`   // ICMP ping to proxy server
	UDPTest    *UDPTestResult   `json:"udp_test,omitempty"`    // UDP test (DNS query through proxy)
	HTTPTests  []HTTPTestResult `json:"http_tests,omitempty"`  // HTTP tests through proxy
	SpeedTest  *SpeedTestResult `json:"speed_test,omitempty"`  // Speed test
	CustomHTTP *HTTPTestResult  `json:"custom_http,omitempty"` // Custom HTTP request
	Error      string           `json:"error,omitempty"`
}

// UDPTestResult represents UDP test result (MCBE server ping through proxy).
type UDPTestResult struct {
	Target     string `json:"target"`
	Success    bool   `json:"success"`
	LatencyMs  int64  `json:"latency_ms"`
	ServerName string `json:"server_name,omitempty"`
	Players    string `json:"players,omitempty"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// MCBETestRequest represents a request for MCBE server UDP test.
type MCBETestRequest struct {
	Name    string `json:"name" binding:"required"`
	Address string `json:"address,omitempty"` // Default: mco.cubecraft.net:19132
}

// PingTestResult represents ICMP ping result to proxy server.
type PingTestResult struct {
	Host      string `json:"host"`
	LatencyMs int64  `json:"latency_ms"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// HTTPTestResult represents a single HTTP test result.
type HTTPTestResult struct {
	Target        string            `json:"target,omitempty"`
	URL           string            `json:"url,omitempty"`
	Success       bool              `json:"success"`
	StatusCode    int               `json:"status_code"`
	StatusText    string            `json:"status_text"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
	LatencyMs     int64             `json:"latency_ms"`
	Error         string            `json:"error,omitempty"`
}

// SpeedTestResult represents a speed test result.
type SpeedTestResult struct {
	URL               string  `json:"url"`
	DownloadSpeedMbps float64 `json:"download_speed_mbps"`
	DownloadBytes     int64   `json:"download_bytes"`
	DurationMs        int64   `json:"duration_ms"`
	Success           bool    `json:"success"`
	Error             string  `json:"error,omitempty"`
}

// DetailedTestRequest represents a request for detailed proxy testing.
type DetailedTestRequest struct {
	Name         string             `json:"name" binding:"required"`
	Targets      []string           `json:"targets,omitempty"`     // HTTP test targets: cloudflare, google, baidu, etc.
	SpeedTest    bool               `json:"speed_test"`            // Whether to run speed test
	SpeedTestURL string             `json:"speed_test_url"`        // Custom speed test URL (default: cloudflare)
	CustomHTTP   *CustomHTTPRequest `json:"custom_http,omitempty"` // Custom HTTP request
}

// CustomHTTPRequest represents a custom HTTP test request.
type CustomHTTPRequest struct {
	URL        string            `json:"url" binding:"required"`
	Method     string            `json:"method,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	DirectTest bool              `json:"direct_test,omitempty"` // If true, test without proxy
}

// HTTPTestTarget represents an HTTP test target.
type HTTPTestTarget struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// DefaultHTTPTestTargets are the default HTTP test targets.
var DefaultHTTPTestTargets = []HTTPTestTarget{
	{Name: "Cloudflare", URL: "https://1.1.1.1/cdn-cgi/trace"},
	{Name: "Google", URL: "https://www.google.com/generate_204"},
	{Name: "Baidu", URL: "https://www.baidu.com"},
	{Name: "GitHub", URL: "https://github.com"},
	{Name: "YouTube", URL: "https://www.youtube.com"},
	{Name: "Twitter", URL: "https://twitter.com"},
}

// DefaultSpeedTestURL is the default speed test URL.
const DefaultSpeedTestURL = "https://speed.cloudflare.com/__down?bytes=10000000"

// DetailedTestProxyOutbound performs a detailed test including multiple latency tests and optional speed test.
// POST /api/proxy-outbounds/detailed-test
func (h *ProxyOutboundHandler) DetailedTestProxyOutbound(c *gin.Context) {
	var req DetailedTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Check if outbound exists
	cfg, exists := h.configMgr.GetOutbound(req.Name)
	if !exists {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}

	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}

	result := DetailedTestResult{
		Name:      req.Name,
		HTTPTests: make([]HTTPTestResult, 0),
	}

	// 1. Ping test to proxy server using configured port
	pingResult := h.testPing(cfg)
	result.PingTest = &pingResult

	// Get the sing-box dialer for proxy connections
	dialer, err := proxy.CreateSingboxDialer(cfg)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create proxy dialer: %v", err)
		respondSuccess(c, result)
		return
	}
	defer dialer.Close()

	// 2. HTTP tests through proxy (concurrent)
	allSuccess := pingResult.Success
	targets := DefaultHTTPTestTargets
	if len(req.Targets) > 0 {
		targets = make([]HTTPTestTarget, 0, len(req.Targets))
		for _, t := range req.Targets {
			switch t {
			case "cloudflare":
				targets = append(targets, HTTPTestTarget{Name: "Cloudflare", URL: "https://1.1.1.1/cdn-cgi/trace"})
			case "google":
				targets = append(targets, HTTPTestTarget{Name: "Google", URL: "https://www.google.com/generate_204"})
			case "baidu":
				targets = append(targets, HTTPTestTarget{Name: "Baidu", URL: "https://www.baidu.com"})
			case "github":
				targets = append(targets, HTTPTestTarget{Name: "GitHub", URL: "https://github.com"})
			case "youtube":
				targets = append(targets, HTTPTestTarget{Name: "YouTube", URL: "https://www.youtube.com"})
			case "twitter":
				targets = append(targets, HTTPTestTarget{Name: "Twitter", URL: "https://twitter.com"})
			}
		}
		if len(targets) == 0 {
			targets = DefaultHTTPTestTargets[:3] // Default to first 3
		}
	}

	// Run HTTP tests concurrently
	httpResultsChan := make(chan HTTPTestResult, len(targets))
	for _, target := range targets {
		go func(t HTTPTestTarget) {
			httpResultsChan <- h.testHTTPThroughProxy(dialer, t)
		}(target)
	}

	// Collect results
	for range targets {
		httpResult := <-httpResultsChan
		result.HTTPTests = append(result.HTTPTests, httpResult)
		if !httpResult.Success {
			allSuccess = false
		}
	}

	// 3. Speed test if requested
	if req.SpeedTest {
		speedURL := req.SpeedTestURL
		if speedURL == "" {
			speedURL = DefaultSpeedTestURL
		}
		speedResult := h.testDownloadSpeed(dialer, speedURL)
		result.SpeedTest = &speedResult
		if !speedResult.Success {
			allSuccess = false
		}
	}

	// 4. Custom HTTP request if provided
	if req.CustomHTTP != nil && req.CustomHTTP.URL != "" {
		customResult := h.testCustomHTTP(dialer, req.CustomHTTP)
		result.CustomHTTP = &customResult
		if !customResult.Success {
			allSuccess = false
		}
	}

	result.Success = allSuccess

	// Update HTTP latency and persist to config file
	if len(result.HTTPTests) > 0 {
		var bestLatency int64 = -1
		for _, httpTest := range result.HTTPTests {
			if httpTest.Success && (bestLatency < 0 || httpTest.LatencyMs < bestLatency) {
				bestLatency = httpTest.LatencyMs
			}
		}
		if bestLatency >= 0 {
			// Update and persist the HTTP latency
			if outbound, ok := h.configMgr.GetOutbound(req.Name); ok {
				outbound.SetHTTPLatencyMs(bestLatency)
				h.configMgr.UpdateOutbound(req.Name, outbound)
			}
		}
	}

	respondSuccess(c, result)
}

// testPing performs connectivity test to the proxy server using the configured port.
// For Hysteria2 (QUIC-based), it uses UDP; for other protocols, it uses TCP.
// For Hysteria2 with port hopping, it tests a random port from the configured range.
func (h *ProxyOutboundHandler) testPing(cfg *config.ProxyOutbound) PingTestResult {
	result := PingTestResult{
		Host: cfg.Server,
	}

	port := cfg.Port
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Hysteria2 uses QUIC which is UDP-based
	if cfg.Type == config.ProtocolHysteria2 {
		// If port hopping is configured, use a random port from the range
		if cfg.PortHopping != "" {
			if start, end, err := parsePortRange(cfg.PortHopping); err == nil {
				// Use a random port from the range
				portRange := end - start + 1
				port = start + int(time.Now().UnixNano()%int64(portRange))
			}
		}
		addr := fmt.Sprintf("%s:%d", cfg.Server, port)
		return h.testUDPPing(ctx, addr)
	}

	// Other protocols use TCP
	addr := fmt.Sprintf("%s:%d", cfg.Server, port)
	startTime := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	latency := time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.LatencyMs = latency.Milliseconds()
		return result
	}
	defer conn.Close()

	result.Success = true
	result.LatencyMs = latency.Milliseconds()
	return result
}

// parsePortRange parses a port range string like "20000-55000" into start and end ports.
func parsePortRange(portRange string) (start, end int, err error) {
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format: %s", portRange)
	}
	start, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	end, err = strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	if start > end {
		return 0, 0, fmt.Errorf("start port %d > end port %d", start, end)
	}
	return start, end, nil
}

// testUDPPing performs UDP connectivity test by sending a probe packet.
// This is used for QUIC-based protocols like Hysteria2.
func (h *ProxyOutboundHandler) testUDPPing(ctx context.Context, addr string) PingTestResult {
	result := PingTestResult{
		Host: addr,
	}

	// Resolve address
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to resolve address: %v", err)
		return result
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create UDP connection: %v", err)
		return result
	}
	defer conn.Close()

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	startTime := time.Now()

	// Send a probe packet (QUIC initial packet-like, but simplified)
	// For Hysteria2/QUIC, we send a minimal probe to check if port is reachable
	probePacket := []byte{0xc0, 0x00, 0x00, 0x01, 0x00} // Simplified QUIC-like probe
	_, err = conn.Write(probePacket)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to send UDP probe: %v", err)
		result.LatencyMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Try to receive a response (with short timeout)
	// Note: Server may not respond to invalid QUIC packets, but we can detect ICMP unreachable
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	_, err = conn.Read(buf)
	latency := time.Since(startTime)

	// For UDP, we consider it successful if:
	// 1. We got a response (any response)
	// 2. We got a timeout (server is there but didn't respond to our invalid packet)
	// We consider it failed if we got ICMP unreachable (connection refused)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout is acceptable for UDP - server is likely there but didn't respond
			result.Success = true
			result.LatencyMs = latency.Milliseconds()
			return result
		}
		// Other errors (like ICMP unreachable) indicate the port is not reachable
		result.Success = false
		result.Error = fmt.Sprintf("UDP probe failed: %v", err)
		result.LatencyMs = latency.Milliseconds()
		return result
	}

	// Got a response
	result.Success = true
	result.LatencyMs = latency.Milliseconds()
	return result
}

// testHTTPThroughProxy performs an HTTP request through the proxy.
func (h *ProxyOutboundHandler) testHTTPThroughProxy(dialer *proxy.SingboxDialer, target HTTPTestTarget) HTTPTestResult {
	result := HTTPTestResult{
		Target:  target.Name,
		URL:     target.URL,
		Headers: make(map[string]string),
	}

	// Create HTTP client with the proxy dialer
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       60 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	startTime := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(startTime)
	result.LatencyMs = latency.Milliseconds()

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.ContentType = resp.Header.Get("Content-Type")
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400

	return result
}

// testDownloadSpeed tests download speed through the proxy.
func (h *ProxyOutboundHandler) testDownloadSpeed(dialer *proxy.SingboxDialer, speedURL string) SpeedTestResult {
	result := SpeedTestResult{
		URL: speedURL,
	}

	// Create HTTP client with the proxy dialer
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   180 * time.Second,
	}

	req, err := http.NewRequest("GET", speedURL, nil)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Success = false
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	// Read all data and measure time
	buffer := make([]byte, 32*1024)
	var totalBytes int64

	for {
		n, err := resp.Body.Read(buffer)
		totalBytes += int64(n)
		if err != nil {
			break
		}
	}

	duration := time.Since(startTime)

	result.Success = true
	result.DownloadBytes = totalBytes
	result.DurationMs = duration.Milliseconds()

	if duration.Seconds() > 0 {
		result.DownloadSpeedMbps = float64(totalBytes*8) / duration.Seconds() / 1000000
	}

	return result
}

// testCustomHTTP performs a custom HTTP request.
func (h *ProxyOutboundHandler) testCustomHTTP(dialer *proxy.SingboxDialer, req *CustomHTTPRequest) HTTPTestResult {
	result := HTTPTestResult{
		URL:     req.URL,
		Headers: make(map[string]string),
	}

	// Create transport
	var transport *http.Transport
	if req.DirectTest {
		transport = &http.Transport{
			DisableKeepAlives:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		}
	} else {
		transport = &http.Transport{
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       60 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   60 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 90 * time.Second,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var httpReq *http.Request
	var err error
	if req.Body != "" {
		httpReq, err = http.NewRequest(method, req.URL, strings.NewReader(req.Body))
	} else {
		httpReq, err = http.NewRequest(method, req.URL, nil)
	}
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result
	}

	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	httpReq.Header.Set("Accept", "*/*")

	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(ctx)

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	latency := time.Since(startTime)
	result.LatencyMs = latency.Milliseconds()

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength

	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	maxBodySize := int64(1024 * 1024)
	limitedReader := io.LimitReader(resp.Body, maxBodySize)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to read response body: %v", err)
		return result
	}

	result.Body = string(bodyBytes)
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400

	return result
}

// TestMCBEUDP tests UDP connectivity to a MCBE server through the proxy.
// POST /api/proxy-outbounds/test-mcbe
func (h *ProxyOutboundHandler) TestMCBEUDP(c *gin.Context) {
	var req MCBETestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Check if outbound exists
	cfg, exists := h.configMgr.GetOutbound(req.Name)
	if !exists {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}

	// Default MCBE server
	address := req.Address
	if address == "" {
		address = "mco.cubecraft.net:19132"
	}

	result := h.testMCBEServer(cfg, address)

	// Update UDP availability and latency, persist to config file
	if outbound, ok := h.configMgr.GetOutbound(req.Name); ok {
		available := result.Success
		outbound.SetUDPAvailable(&available)
		if result.Success {
			outbound.UDPLatencyMs = result.LatencyMs
		} else {
			outbound.UDPLatencyMs = 0
		}
		h.configMgr.UpdateOutbound(req.Name, outbound)
	}

	respondSuccess(c, result)
}

// testMCBEServer tests connectivity to a MCBE server through the proxy.
func (h *ProxyOutboundHandler) testMCBEServer(cfg *config.ProxyOutbound, address string) UDPTestResult {
	result := UDPTestResult{
		Target: address,
	}

	// Create outbound for UDP
	outbound, err := proxy.CreateSingboxOutbound(cfg)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create outbound: %v", err)
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	startTime := time.Now()

	// Create UDP connection through proxy
	packetConn, err := outbound.ListenPacket(ctx, address)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create UDP connection: %v", err)
		result.LatencyMs = time.Since(startTime).Milliseconds()
		return result
	}
	defer packetConn.Close()

	// Send RakNet unconnected ping
	pingPacket := buildRakNetPing()

	// Parse address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Invalid address: %v", err)
		return result
	}
	port, _ := strconv.Atoi(portStr)
	destAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if destAddr.IP == nil {
		// Resolve hostname
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to resolve host: %v", err)
			return result
		}
		destAddr.IP = ips[0]
	}

	// Send ping
	_, err = packetConn.WriteTo(pingPacket, destAddr)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to send ping: %v", err)
		result.LatencyMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Set read deadline
	packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read response
	buf := make([]byte, 1500)
	n, _, err := packetConn.ReadFrom(buf)
	latency := time.Since(startTime)
	result.LatencyMs = latency.Milliseconds()

	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to receive response: %v", err)
		return result
	}

	// Parse RakNet unconnected pong
	if n > 35 && buf[0] == 0x1c {
		// Parse MOTD string
		motdLen := int(buf[33])<<8 | int(buf[34])
		if 35+motdLen <= n {
			motd := string(buf[35 : 35+motdLen])
			parts := strings.Split(motd, ";")
			if len(parts) >= 6 {
				result.ServerName = parts[1]
				result.Version = parts[3]
				result.Players = fmt.Sprintf("%s/%s", parts[4], parts[5])
			}
		}
		result.Success = true
	} else if n > 0 {
		result.Success = true
		result.ServerName = "Unknown (got response)"
	} else {
		result.Success = false
		result.Error = "Empty response"
	}

	return result
}

// buildRakNetPing builds a RakNet unconnected ping packet.
func buildRakNetPing() []byte {
	packet := make([]byte, 33)
	packet[0] = 0x01 // Unconnected Ping

	// Timestamp (8 bytes)
	ts := time.Now().UnixNano() / int64(time.Millisecond)
	for i := 0; i < 8; i++ {
		packet[1+i] = byte(ts >> (56 - i*8))
	}

	// Magic (16 bytes)
	magic := []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}
	copy(packet[9:25], magic)

	// Client GUID (8 bytes)
	for i := 0; i < 8; i++ {
		packet[25+i] = byte(i)
	}

	return packet
}
