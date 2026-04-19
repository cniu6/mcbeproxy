// Package api provides REST API functionality using Gin framework.
package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

type bulkCreateProxyPortsRequest struct {
	Ports []*config.ProxyPortConfig `json:"ports"`
}

// testProxyPortRequest is the optional JSON body for POST /api/proxy-ports/:id/test.
// If URL is empty we fall back to defaultProxyPortTestURL.
type testProxyPortRequest struct {
	URL string `json:"url"`
}

// testProxyPortResult is the response payload of the proxy-port connectivity test.
// We keep it flat so the frontend can show one of: latency on success,
// status_code + latency when success is false but we got some HTTP response,
// or error otherwise.
type testProxyPortResult struct {
	PortID     string `json:"port_id"`
	URL        string `json:"url"`
	Success    bool   `json:"success"`
	LatencyMs  int64  `json:"latency_ms"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

type proxyPortRuntimeDTO struct {
	PortID            string `json:"port_id"`
	ActiveConnections int    `json:"active_connections"`
	CurrentNode       string `json:"current_node,omitempty"`
	HasNode           bool   `json:"has_node"`
	TCPMs             int64  `json:"tcp_ms,omitempty"`
	UDPMs             int64  `json:"udp_ms,omitempty"`
	HTTPMs            int64  `json:"http_ms,omitempty"`
	HasTCP            bool   `json:"has_tcp,omitempty"`
	HasUDP            bool   `json:"has_udp,omitempty"`
	HasHTTP           bool   `json:"has_http,omitempty"`
}

type proxyPortListDTO struct {
	*config.ProxyPortConfig
	proxyPortRuntimeDTO
}

// defaultProxyPortTestURL is used when the caller doesn't supply one.
// google.com/generate_204 is a well-known captive-portal test endpoint:
// fast, returns HTTP 204 on success, low payload, censored region safe as a reachability signal.
const defaultProxyPortTestURL = "https://www.google.com/generate_204"

// proxyPortTestTimeout covers DNS + TCP + TLS + HTTP for one test call.
const proxyPortTestTimeout = 15 * time.Second

func (a *APIServer) getProxyPorts(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	ports := a.proxyPortConfigMgr.GetAllPorts()
	dtos := make([]proxyPortListDTO, 0, len(ports))
	for _, port := range ports {
		if port == nil {
			continue
		}
		clone := port.Clone()
		dtos = append(dtos, proxyPortListDTO{
			ProxyPortConfig:     clone,
			proxyPortRuntimeDTO: a.buildProxyPortRuntimeSnapshot(clone),
		})
	}
	respondSuccess(c, dtos)
}

func (a *APIServer) getProxyPortRuntime(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}

	portID := strings.TrimSpace(c.Param("id"))
	if portID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "id parameter is required")
		return
	}

	port, exists := a.proxyPortConfigMgr.GetPort(portID)
	if !exists || port == nil {
		respondError(c, http.StatusNotFound, "Proxy port not found", "no proxy port with id "+portID)
		return
	}

	respondSuccess(c, a.buildProxyPortRuntimeSnapshot(port))
}

func (a *APIServer) buildProxyPortRuntimeSnapshot(port *config.ProxyPortConfig) proxyPortRuntimeDTO {
	dto := proxyPortRuntimeDTO{}
	if port == nil {
		return dto
	}

	dto.PortID = port.ID
	if a.proxyOutboundHandler != nil {
		ref := a.proxyOutboundHandler.buildProxyPortUsageRef(port)
		dto.ActiveConnections = ref.ActiveConnections
		dto.CurrentNode = ref.CurrentNode
		dto.HasNode = ref.HasNode
		dto.TCPMs = ref.TCPMs
		dto.UDPMs = ref.UDPMs
		dto.HTTPMs = ref.HTTPMs
		dto.HasTCP = ref.HasTCP
		dto.HasUDP = ref.HasUDP
		dto.HasHTTP = ref.HasHTTP
	}

	if port.IsDirectConnection() {
		dto.CurrentNode = proxy.DirectNodeName
		dto.HasNode = true
		dto.HasTCP = false
		dto.HasUDP = false
		dto.HasHTTP = false
	}

	return dto
}

func (a *APIServer) createProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	var cfg config.ProxyPortConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if cfg.ID == "" {
		cfg.ID = generateProxyPortID()
	}
	cfg.ApplyDefaults()
	if err := a.proxyPortConfigMgr.AddPort(&cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to create proxy port", err.Error())
		return
	}
	if a.proxyController != nil {
		_ = a.proxyController.ReloadProxyPorts()
	}
	respondSuccess(c, cfg)
}

func (a *APIServer) createProxyPortsBulk(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	var req bulkCreateProxyPortsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if len(req.Ports) == 0 {
		respondError(c, http.StatusBadRequest, "Invalid request body", "ports cannot be empty")
		return
	}
	prepared := make([]*config.ProxyPortConfig, 0, len(req.Ports))
	for _, port := range req.Ports {
		if port == nil {
			respondError(c, http.StatusBadRequest, "Invalid request body", "port config cannot be nil")
			return
		}
		clone := port.Clone()
		if clone.ID == "" {
			clone.ID = generateProxyPortID()
		}
		clone.ApplyDefaults()
		prepared = append(prepared, clone)
	}
	if err := a.proxyPortConfigMgr.AddPorts(prepared); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to create proxy ports", err.Error())
		return
	}
	if a.proxyController != nil {
		_ = a.proxyController.ReloadProxyPorts()
	}
	respondSuccess(c, prepared)
}

func (a *APIServer) updateProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	portID := c.Param("id")
	if portID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "id parameter is required")
		return
	}
	var cfg config.ProxyPortConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if cfg.ID == "" {
		cfg.ID = portID
	}
	cfg.ApplyDefaults()
	if err := a.proxyPortConfigMgr.UpdatePort(portID, &cfg); err != nil {
		respondError(c, http.StatusNotFound, "Failed to update proxy port", err.Error())
		return
	}
	if a.proxyController != nil {
		_ = a.proxyController.ReloadProxyPorts()
	}
	respondSuccess(c, cfg)
}

func (a *APIServer) deleteProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}
	portID := c.Param("id")
	if portID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "id parameter is required")
		return
	}
	if err := a.proxyPortConfigMgr.DeletePort(portID); err != nil {
		respondError(c, http.StatusNotFound, "Failed to delete proxy port", err.Error())
		return
	}
	if a.proxyController != nil {
		_ = a.proxyController.ReloadProxyPorts()
	}
	respondSuccessWithMsg(c, "已删除", nil)
}

func generateProxyPortID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "proxy-port"
	}
	return "proxy-" + hex.EncodeToString(buf)
}

// testProxyPort performs an end-to-end HTTP GET through the specified local
// proxy port, measuring latency. This goes through the ACTUAL listener (auth,
// allow-list, upstream outbound selection) so failures correctly reflect what
// real proxy clients would see, not just upstream reachability.
//
// POST /api/proxy-ports/:id/test
// Body (optional): {"url": "https://..."}
func (a *APIServer) testProxyPort(c *gin.Context) {
	if a.proxyPortConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy port config manager not initialized", "")
		return
	}

	id := c.Param("id")
	if id == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "id parameter is required")
		return
	}

	port, exists := a.proxyPortConfigMgr.GetPort(id)
	if !exists {
		respondError(c, http.StatusNotFound, "Proxy port not found", "no proxy port with id "+id)
		return
	}

	// Body is optional; missing/malformed body just means "use default URL".
	var req testProxyPortRequest
	_ = c.ShouldBindJSON(&req)

	testURL := strings.TrimSpace(req.URL)
	if testURL == "" {
		testURL = defaultProxyPortTestURL
	}

	parsedURL, err := url.Parse(testURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		respondError(c, http.StatusBadRequest, "Invalid test URL", "must be http:// or https://")
		return
	}

	result := testProxyPortResult{PortID: port.ID, URL: testURL}

	// Disabled listener cannot accept connections - short-circuit with a clear error.
	if !port.Enabled {
		result.Success = false
		result.Error = "proxy port is disabled; enable it before testing"
		respondSuccess(c, result)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), proxyPortTestTimeout)
	defer cancel()

	runProxyPortConnectivityTest(ctx, port, testURL, &result)
	respondSuccess(c, result)
}

// runProxyPortConnectivityTest fills `out` in place. Split out for unit testing
// against a hand-rolled local HTTP/SOCKS5 listener without requiring the full
// APIServer wiring.
func runProxyPortConnectivityTest(ctx context.Context, port *config.ProxyPortConfig, testURL string, out *testProxyPortResult) {
	// The user may configure listen_addr as 0.0.0.0:PORT or [::]:PORT for binding,
	// but we can't dial those from the server itself - rewrite to loopback.
	host, portStr, err := net.SplitHostPort(port.ListenAddr)
	if err != nil {
		out.Success = false
		out.Error = fmt.Sprintf("invalid listen_addr %q: %v", port.ListenAddr, err)
		return
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	dialTarget := net.JoinHostPort(host, portStr)

	// Map port.Type to a scheme http.Transport understands natively.
	// SOCKS4 lacks stdlib http.Transport support; we reject upfront instead of
	// silently behaving like SOCKS5, which would misreport a broken listener as OK.
	var scheme string
	switch strings.ToLower(port.Type) {
	case config.ProxyPortTypeHTTP:
		scheme = "http"
	case config.ProxyPortTypeSocks5, config.ProxyPortTypeMixed:
		scheme = "socks5"
	case config.ProxyPortTypeSocks4, config.ProxyPortTypeSock:
		out.Success = false
		out.Error = "SOCKS4 test not supported; switch the port to SOCKS5 or MIXED to test HTTP connectivity"
		return
	default:
		out.Success = false
		out.Error = fmt.Sprintf("unsupported proxy port type: %s", port.Type)
		return
	}

	proxyURL := &url.URL{
		Scheme: scheme,
		Host:   dialTarget,
	}
	if port.Username != "" || port.Password != "" {
		proxyURL.User = url.UserPassword(port.Username, port.Password)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   proxyPortTestTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		out.Success = false
		out.Error = err.Error()
		return
	}
	// Give the upstream something that looks less like a scripted bot but still
	// identifies us, so site-side rate-limiting doesn't silently block us.
	req.Header.Set("User-Agent", "mcpeserverproxy-port-test/1.0 (+connectivity probe)")
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	out.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		out.Success = false
		out.Error = err.Error()
		return
	}
	defer resp.Body.Close()
	// Drain a bounded slice so the connection can be reused / closed cleanly.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	out.StatusCode = resp.StatusCode
	// 2xx/3xx = healthy. generate_204 returns 204. We treat 4xx/5xx as "proxy reached
	// upstream but upstream complained", which is still useful signal but not a PASS.
	out.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	if !out.Success {
		out.Error = fmt.Sprintf("upstream returned %s", resp.Status)
	}
}
