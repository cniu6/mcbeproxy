// Package api provides REST API functionality using Gin framework.
package api

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/proxy"
	"mcpeserverproxy/internal/singboxcore"
	"mcpeserverproxy/internal/subscription"
)

// ProxyOutboundHandler handles REST API requests for proxy outbound management.
// Requirements: 5.3
type ProxyOutboundHandler struct {
	configMgr              *config.ProxyOutboundConfigManager
	subConfigMgr           *config.ProxySubscriptionConfigManager
	serverConfigMgr        *config.ConfigManager
	globalConfig           *config.GlobalConfig
	outboundMgr            proxy.OutboundManager
	singboxFactory         singboxcore.Factory
	subService             *subscription.Service
	activityProvider       proxyOutboundUsageActivityProvider
	subscriptionUpdateHook func(string)
}

type proxyOutboundUsageActivityProvider interface {
	GetActiveSessionsForServer(serverID string) int
	GetActiveConnectionsForProxyPort(portID string) int
}

var metadataLikeImportNamePattern = regexp.MustCompile(`(?i)^(剩余流量|套餐到期|到期时间|过期时间|流量重置|订阅信息|订阅更新时间|更新时间|使用说明|官网|公告|客服|telegram|tg|email|邮箱)\s*[：:]`)

// NewProxyOutboundHandler creates a new ProxyOutboundHandler instance.
func NewProxyOutboundHandler(configMgr *config.ProxyOutboundConfigManager, subConfigMgr *config.ProxySubscriptionConfigManager, serverConfigMgr *config.ConfigManager, outboundMgr proxy.OutboundManager) *ProxyOutboundHandler {
	return NewProxyOutboundHandlerWithConfig(configMgr, subConfigMgr, serverConfigMgr, nil, outboundMgr)
}

func NewProxyOutboundHandlerWithConfig(configMgr *config.ProxyOutboundConfigManager, subConfigMgr *config.ProxySubscriptionConfigManager, serverConfigMgr *config.ConfigManager, globalConfig *config.GlobalConfig, outboundMgr proxy.OutboundManager) *ProxyOutboundHandler {
	return NewProxyOutboundHandlerWithSingboxFactory(configMgr, subConfigMgr, serverConfigMgr, globalConfig, outboundMgr, nil)
}

func NewProxyOutboundHandlerWithSingboxFactory(configMgr *config.ProxyOutboundConfigManager, subConfigMgr *config.ProxySubscriptionConfigManager, serverConfigMgr *config.ConfigManager, globalConfig *config.GlobalConfig, outboundMgr proxy.OutboundManager, factory singboxcore.Factory) *ProxyOutboundHandler {
	if factory == nil {
		factory = proxy.NewSingboxCoreFactory()
	}
	return &ProxyOutboundHandler{
		configMgr:       configMgr,
		subConfigMgr:    subConfigMgr,
		serverConfigMgr: serverConfigMgr,
		globalConfig:    globalConfig,
		outboundMgr:     outboundMgr,
		singboxFactory:  factory,
		subService:      subscription.NewServiceWithSingboxFactory(configMgr, outboundMgr, factory),
	}
}

// SetUsageContext injects activity providers used by outbound/port usage views.
func (h *ProxyOutboundHandler) SetUsageContext(_ *config.ProxyPortConfigManager, activityProvider proxyOutboundUsageActivityProvider) {
	if h == nil {
		return
	}
	h.activityProvider = activityProvider
}

// SetSubscriptionUpdateHook injects a callback invoked after successful subscription node updates.
func (h *ProxyOutboundHandler) SetSubscriptionUpdateHook(hook func(string)) {
	if h == nil {
		return
	}
	h.subscriptionUpdateHook = hook
}

func (h *ProxyOutboundHandler) triggerSubscriptionUpdateHook(reason string) {
	if h == nil || h.subscriptionUpdateHook == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "subscription update"
	}
	h.subscriptionUpdateHook(reason)
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
	Username     string `json:"username,omitempty"`
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
	Network                  string     `json:"network,omitempty"`
	WSPath                   string     `json:"ws_path,omitempty"`
	WSHost                   string     `json:"ws_host,omitempty"`
	XHTTPMode                string     `json:"xhttp_mode,omitempty"`
	GRPCServiceName          string     `json:"grpc_service_name,omitempty"`
	GRPCAuthority            string     `json:"grpc_authority,omitempty"`
	AutoSelectBlocked        bool       `json:"auto_select_blocked,omitempty"`
	AutoSelectBlockReason    string     `json:"auto_select_block_reason,omitempty"`
	AutoSelectBlockExpiresAt *time.Time `json:"auto_select_block_expires_at,omitempty"`
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
		Username:     cfg.Username,
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
		Network:         cfg.Network,
		WSPath:          cfg.WSPath,
		WSHost:          cfg.WSHost,
		XHTTPMode:       cfg.XHTTPMode,
		GRPCServiceName: cfg.GRPCServiceName,
		GRPCAuthority:   cfg.GRPCAuthority,
	}
	blocked, blockReason, blockExpiresAt := cfg.GetEffectiveAutoSelectBlock()
	dto.AutoSelectBlocked = blocked
	dto.AutoSelectBlockReason = blockReason
	dto.AutoSelectBlockExpiresAt = blockExpiresAt

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
	Username     string `json:"username,omitempty"`
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
	Network                  string     `json:"network,omitempty"`
	WSPath                   string     `json:"ws_path,omitempty"`
	WSHost                   string     `json:"ws_host,omitempty"`
	XHTTPMode                string     `json:"xhttp_mode,omitempty"`
	GRPCServiceName          string     `json:"grpc_service_name,omitempty"`
	GRPCAuthority            string     `json:"grpc_authority,omitempty"`
	AutoSelectBlocked        bool       `json:"auto_select_blocked,omitempty"`
	AutoSelectBlockReason    string     `json:"auto_select_block_reason,omitempty"`
	AutoSelectBlockExpiresAt *time.Time `json:"auto_select_block_expires_at,omitempty"`
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
		Username:     r.Username,
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
		Network:                  r.Network,
		WSPath:                   r.WSPath,
		WSHost:                   r.WSHost,
		XHTTPMode:                r.XHTTPMode,
		GRPCServiceName:          r.GRPCServiceName,
		GRPCAuthority:            r.GRPCAuthority,
		AutoSelectBlocked:        r.AutoSelectBlocked,
		AutoSelectBlockReason:    r.AutoSelectBlockReason,
		AutoSelectBlockExpiresAt: r.AutoSelectBlockExpiresAt,
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
	Name     string `json:"name" binding:"required"`
	ServerID string `json:"server_id,omitempty"`
}

type ProxyOutboundAutoSelectBlockRequest struct {
	Name      string     `json:"name" binding:"required"`
	Reason    string     `json:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type BatchProxyOutboundAutoSelectBlockRequest struct {
	Names     []string   `json:"names" binding:"required"`
	Reason    string     `json:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type BatchProxyTestRequest struct {
	Names       []string           `json:"names" binding:"required"`
	Type        string             `json:"type" binding:"required"`
	IncludePing *bool              `json:"include_ping,omitempty"`
	Targets     []string           `json:"targets,omitempty"`
	CustomHTTP  *CustomHTTPRequest `json:"custom_http,omitempty"`
	ServerID    string             `json:"server_id,omitempty"`
	Address     string             `json:"address,omitempty"`
	Concurrency int                `json:"concurrency,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
}

type BatchProxyTestItem struct {
	Name          string `json:"name"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
	LatencyMs     int64  `json:"latency_ms,omitempty"`
	HTTPLatencyMs int64  `json:"http_latency_ms,omitempty"`
	UDPAvailable  *bool  `json:"udp_available,omitempty"`
	UDPLatencyMs  int64  `json:"udp_latency_ms,omitempty"`
	QueueWaitMs   int64  `json:"queue_wait_ms,omitempty"`
	DurationMs    int64  `json:"duration_ms,omitempty"`
}

type BatchProxyTestResponse struct {
	Type    string               `json:"type"`
	Total   int                  `json:"total"`
	Success int                  `json:"success"`
	Failed  int                  `json:"failed"`
	Items   []BatchProxyTestItem `json:"items"`
}

type BatchProxyTestStreamEvent struct {
	Event       string              `json:"event"`
	Type        string              `json:"type,omitempty"`
	Total       int                 `json:"total,omitempty"`
	Current     int                 `json:"current,omitempty"`
	Success     int                 `json:"success,omitempty"`
	Failed      int                 `json:"failed,omitempty"`
	Concurrency int                 `json:"concurrency,omitempty"`
	Item        *BatchProxyTestItem `json:"item,omitempty"`
}

type batchProxyTestProgress struct {
	Current int
	Success int
	Failed  int
}

var batchProxyTestGlobalLimiter = newBatchProxyTestLimiter(defaultBatchProxyTestGlobalBudget())
var batchProxyTestTCPLimiter = newBatchProxyTestLimiter(defaultBatchProxyTestTypeBudget("tcp"))
var batchProxyTestHTTPLimiter = newBatchProxyTestLimiter(defaultBatchProxyTestTypeBudget("http"))
var batchProxyTestUDPLimiter = newBatchProxyTestLimiter(defaultBatchProxyTestTypeBudget("udp"))

func (h *ProxyOutboundHandler) updateOutboundRuntime(name string, update func(outbound *config.ProxyOutbound)) {
	if h == nil || h.configMgr == nil {
		return
	}
	_ = h.configMgr.UpdateOutboundRuntime(name, update)
}

func (h *ProxyOutboundHandler) recordOutboundLatency(name, sortBy string, latencyMs int64) {
	if h == nil || h.outboundMgr == nil {
		return
	}
	h.outboundMgr.SetOutboundLatency(name, sortBy, latencyMs)
}

type ProxySubscriptionDTO struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	Enabled       bool   `json:"enabled"`
	Group         string `json:"group,omitempty"`
	ProxyName     string `json:"proxy_name,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	LastUpdatedAt string `json:"last_updated_at,omitempty"`
	LastNodeCount int    `json:"last_node_count,omitempty"`
	LastAdded     int    `json:"last_added,omitempty"`
	LastUpdated   int    `json:"last_updated,omitempty"`
	LastRemoved   int    `json:"last_removed,omitempty"`
	LastError     string `json:"last_error,omitempty"`
}

type ServerNodeLatencyHistoryItem struct {
	Name    string                          `json:"name"`
	Samples []proxy.ServerNodeLatencySample `json:"samples"`
}

type ProxyOutboundLatencyHistoryMetrics struct {
	TCP  []proxy.OutboundLatencySample `json:"tcp"`
	HTTP []proxy.OutboundLatencySample `json:"http"`
	UDP  []proxy.OutboundLatencySample `json:"udp"`
}

func (h *ProxyOutboundHandler) defaultLatencyHistoryLimit() int {
	if h == nil || h.globalConfig == nil {
		return 100
	}
	return h.globalConfig.GetLatencyHistoryRenderLimit()
}

func (h *ProxyOutboundHandler) maxLatencyHistoryLimit() int {
	if h == nil || h.globalConfig == nil {
		return 1000
	}
	return h.globalConfig.GetLatencyHistoryStorageLimit()
}

func (h *ProxyOutboundHandler) parseLatencyHistoryLimit(raw string) int {
	return parseHistoryLimit(raw, h.defaultLatencyHistoryLimit(), h.maxLatencyHistoryLimit())
}

func parseOptionalUnixMilli(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, false
	}
	return value, true
}

func filterServerNodeLatencyHistorySamples(samples []proxy.ServerNodeLatencySample, fromMs, toMs int64, limit int) []proxy.ServerNodeLatencySample {
	if len(samples) == 0 {
		return []proxy.ServerNodeLatencySample{}
	}
	if fromMs > 0 && toMs > 0 && fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	filtered := make([]proxy.ServerNodeLatencySample, 0, len(samples))
	for _, sample := range samples {
		if fromMs > 0 && sample.Timestamp < fromMs {
			continue
		}
		if toMs > 0 && sample.Timestamp > toMs {
			continue
		}
		if sample.LatencyMs < 0 {
			sample.LatencyMs = 0
		}
		filtered = append(filtered, sample)
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	return filtered
}

func filterOutboundLatencyHistorySamples(samples []proxy.OutboundLatencySample, fromMs, toMs int64, limit int) []proxy.OutboundLatencySample {
	if len(samples) == 0 {
		return []proxy.OutboundLatencySample{}
	}
	if fromMs > 0 && toMs > 0 && fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	filtered := make([]proxy.OutboundLatencySample, 0, len(samples))
	for _, sample := range samples {
		if fromMs > 0 && sample.Timestamp < fromMs {
			continue
		}
		if toMs > 0 && sample.Timestamp > toMs {
			continue
		}
		if sample.LatencyMs < 0 {
			sample.LatencyMs = 0
		}
		filtered = append(filtered, sample)
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	return filtered
}

func (h *ProxyOutboundHandler) getProxyOutboundLatencyHistoryMetrics(name string, fromMs, toMs int64, limit int) ProxyOutboundLatencyHistoryMetrics {
	if h == nil || h.outboundMgr == nil {
		return ProxyOutboundLatencyHistoryMetrics{
			TCP:  []proxy.OutboundLatencySample{},
			HTTP: []proxy.OutboundLatencySample{},
			UDP:  []proxy.OutboundLatencySample{},
		}
	}
	return ProxyOutboundLatencyHistoryMetrics{
		TCP:  filterOutboundLatencyHistorySamples(h.outboundMgr.GetOutboundLatencyHistory(name, config.LoadBalanceSortTCP), fromMs, toMs, limit),
		HTTP: filterOutboundLatencyHistorySamples(h.outboundMgr.GetOutboundLatencyHistory(name, config.LoadBalanceSortHTTP), fromMs, toMs, limit),
		UDP:  filterOutboundLatencyHistorySamples(h.outboundMgr.GetOutboundLatencyHistory(name, config.LoadBalanceSortUDP), fromMs, toMs, limit),
	}
}

func (h *ProxyOutboundHandler) buildProxyOutboundLatencyHistorySnapshot(outbounds []*config.ProxyOutbound, fromMs, toMs int64, limit int) map[string]ProxyOutboundLatencyHistoryMetrics {
	result := make(map[string]ProxyOutboundLatencyHistoryMetrics)
	if h == nil || h.outboundMgr == nil || len(outbounds) == 0 {
		return result
	}
	for _, outbound := range outbounds {
		if outbound == nil || strings.TrimSpace(outbound.Name) == "" {
			continue
		}
		result[outbound.Name] = h.getProxyOutboundLatencyHistoryMetrics(outbound.Name, fromMs, toMs, limit)
	}
	return result
}

type ProxySubscriptionRequest struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name" binding:"required"`
	URL       string `json:"url" binding:"required"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Group     string `json:"group,omitempty"`
	ProxyName string `json:"proxy_name,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type proxySubscriptionUpdateRequest struct {
	ProxyMode string `json:"proxy_mode,omitempty"`
	ProxyName string `json:"proxy_name,omitempty"`
}

func (r proxySubscriptionUpdateRequest) validate() error {
	mode := strings.ToLower(strings.TrimSpace(r.ProxyMode))
	switch mode {
	case "", "saved", "subscription", "default", "direct":
		return nil
	case "custom", "override", "proxy":
		if strings.TrimSpace(r.ProxyName) == "" {
			return fmt.Errorf("proxy_name is required when proxy_mode is custom")
		}
		return nil
	default:
		return fmt.Errorf("invalid proxy_mode: %s", r.ProxyMode)
	}
}

func (r proxySubscriptionUpdateRequest) effectiveProxyName(saved string) string {
	mode := strings.ToLower(strings.TrimSpace(r.ProxyMode))
	proxyName := strings.TrimSpace(r.ProxyName)
	saved = strings.TrimSpace(saved)
	switch mode {
	case "custom", "override", "proxy":
		return proxyName
	case "direct":
		return ""
	case "", "saved", "subscription", "default":
		if mode == "" && proxyName != "" {
			return proxyName
		}
		return saved
	default:
		return saved
	}
}

func (r proxySubscriptionUpdateRequest) applyTo(sub *config.ProxySubscription) (*config.ProxySubscription, error) {
	if sub == nil {
		return nil, fmt.Errorf("proxy subscription is nil")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	clone := sub.Clone()
	clone.ProxyName = r.effectiveProxyName(sub.ProxyName)
	return clone, nil
}

func readProxySubscriptionUpdateRequest(c *gin.Context) (proxySubscriptionUpdateRequest, error) {
	var req proxySubscriptionUpdateRequest
	if c.Request.ContentLength == 0 {
		return req, nil
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return req, err
	}
	return req, nil
}

func (r *ProxySubscriptionRequest) toConfig(existing *config.ProxySubscription) *config.ProxySubscription {
	var enabled bool
	if r.Enabled != nil {
		enabled = *r.Enabled
	} else if existing != nil {
		enabled = existing.Enabled
	} else {
		enabled = true
	}
	cfg := &config.ProxySubscription{
		ID:        strings.TrimSpace(r.ID),
		Name:      strings.TrimSpace(r.Name),
		URL:       strings.TrimSpace(r.URL),
		Enabled:   enabled,
		Group:     strings.TrimSpace(r.Group),
		ProxyName: strings.TrimSpace(r.ProxyName),
		UserAgent: strings.TrimSpace(r.UserAgent),
	}
	if existing != nil {
		cfg.LastUpdatedAt = existing.LastUpdatedAt
		cfg.LastNodeCount = existing.LastNodeCount
		cfg.LastAdded = existing.LastAdded
		cfg.LastUpdated = existing.LastUpdated
		cfg.LastRemoved = existing.LastRemoved
		cfg.LastError = existing.LastError
	}
	return cfg
}

func (h *ProxyOutboundHandler) toSubscriptionDTO(cfg *config.ProxySubscription) ProxySubscriptionDTO {
	dto := ProxySubscriptionDTO{
		ID:            cfg.ID,
		Name:          cfg.Name,
		URL:           cfg.URL,
		Enabled:       cfg.Enabled,
		Group:         cfg.Group,
		ProxyName:     cfg.ProxyName,
		UserAgent:     cfg.UserAgent,
		LastNodeCount: cfg.LastNodeCount,
		LastAdded:     cfg.LastAdded,
		LastUpdated:   cfg.LastUpdated,
		LastRemoved:   cfg.LastRemoved,
		LastError:     cfg.LastError,
	}
	if !cfg.LastUpdatedAt.IsZero() {
		dto.LastUpdatedAt = cfg.LastUpdatedAt.Format(time.RFC3339)
	}
	return dto
}

func (h *ProxyOutboundHandler) ListProxySubscriptions(c *gin.Context) {
	if h.subConfigMgr == nil {
		respondSuccess(c, []ProxySubscriptionDTO{})
		return
	}
	subscriptions := h.subConfigMgr.GetAllSubscriptions()
	result := make([]ProxySubscriptionDTO, 0, len(subscriptions))
	for _, sub := range subscriptions {
		result = append(result, h.toSubscriptionDTO(sub))
	}
	respondSuccess(c, result)
}

func (h *ProxyOutboundHandler) CreateProxySubscription(c *gin.Context) {
	if h.subConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Subscription manager not initialized", "")
		return
	}
	var req ProxySubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	cfg := req.toConfig(nil)
	if cfg.ID == "" {
		cfg.ID = uuid.NewString()
	}
	if err := h.subConfigMgr.AddSubscription(cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to create proxy subscription", err.Error())
		return
	}
	respondSuccess(c, h.toSubscriptionDTO(cfg))
}

func (h *ProxyOutboundHandler) UpdateProxySubscription(c *gin.Context) {
	if h.subConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Subscription manager not initialized", "")
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "subscription id is required")
		return
	}
	existing, ok := h.subConfigMgr.GetSubscription(id)
	if !ok {
		respondError(c, http.StatusNotFound, "Proxy subscription not found", "")
		return
	}
	var req ProxySubscriptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	cfg := req.toConfig(existing)
	if cfg.ID == "" {
		cfg.ID = id
	}
	if err := h.subConfigMgr.UpdateSubscription(id, cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to update proxy subscription", err.Error())
		return
	}
	respondSuccess(c, h.toSubscriptionDTO(cfg))
}

func (h *ProxyOutboundHandler) DeleteProxySubscription(c *gin.Context) {
	if h.subConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Subscription manager not initialized", "")
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "subscription id is required")
		return
	}
	sub, _ := h.subConfigMgr.GetSubscription(id)
	if _, ok := h.subConfigMgr.GetSubscription(id); !ok {
		respondError(c, http.StatusNotFound, "Proxy subscription not found", "")
		return
	}
	if h.subService != nil {
		if err := h.subService.RemoveSubscriptionNodes(id); err != nil {
			respondError(c, http.StatusInternalServerError, "Failed to remove subscription nodes", err.Error())
			return
		}
	}
	if err := h.subConfigMgr.DeleteSubscription(id); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to delete proxy subscription", err.Error())
		return
	}
	if sub != nil {
		h.triggerSubscriptionUpdateHook("subscription deleted: " + sub.Name)
	} else {
		h.triggerSubscriptionUpdateHook("subscription deleted")
	}
	respondSuccessWithMsg(c, "订阅已删除", nil)
}

func (h *ProxyOutboundHandler) UpdateProxySubscriptionNow(c *gin.Context) {
	if h.subConfigMgr == nil || h.subService == nil {
		respondError(c, http.StatusInternalServerError, "Subscription service not initialized", "")
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "subscription id is required")
		return
	}
	sub, ok := h.subConfigMgr.GetSubscription(id)
	if !ok {
		respondError(c, http.StatusNotFound, "Proxy subscription not found", "")
		return
	}
	if !sub.Enabled {
		respondError(c, http.StatusBadRequest, "Subscription is disabled", "")
		return
	}
	updateReq, err := readProxySubscriptionUpdateRequest(c)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	effectiveSub, err := updateReq.applyTo(sub)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	result, err := h.subService.UpdateSubscription(c.Request.Context(), effectiveSub)
	if err != nil {
		sub.LastError = err.Error()
		_ = h.subConfigMgr.UpdateSubscription(sub.ID, sub)
		respondError(c, http.StatusBadGateway, "Failed to update proxy subscription", err.Error())
		return
	}
	sub.LastUpdatedAt = time.Now()
	sub.LastNodeCount = result.NodeCount
	sub.LastAdded = result.AddedCount
	sub.LastUpdated = result.UpdatedCount
	sub.LastRemoved = result.RemovedCount
	sub.LastError = ""
	if err := h.subConfigMgr.UpdateSubscription(sub.ID, sub); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to persist proxy subscription state", err.Error())
		return
	}
	h.triggerSubscriptionUpdateHook("subscription update: " + sub.Name)
	respondSuccess(c, map[string]interface{}{
		"subscription": h.toSubscriptionDTO(sub),
		"result":       result,
	})
}

func (h *ProxyOutboundHandler) UpdateAllProxySubscriptions(c *gin.Context) {
	if h.subConfigMgr == nil || h.subService == nil {
		respondError(c, http.StatusInternalServerError, "Subscription service not initialized", "")
		return
	}
	updateReq, err := readProxySubscriptionUpdateRequest(c)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if err := updateReq.validate(); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	type itemResult struct {
		Subscription ProxySubscriptionDTO       `json:"subscription"`
		Result       *subscription.UpdateResult `json:"result,omitempty"`
		Error        string                     `json:"error,omitempty"`
	}
	items := make([]itemResult, 0)
	updated := 0
	failed := 0
	for _, sub := range h.subConfigMgr.GetAllSubscriptions() {
		if !sub.Enabled {
			continue
		}
		effectiveSub, err := updateReq.applyTo(sub)
		if err != nil {
			failed++
			sub.LastError = err.Error()
			_ = h.subConfigMgr.UpdateSubscription(sub.ID, sub)
			items = append(items, itemResult{Subscription: h.toSubscriptionDTO(sub), Error: err.Error()})
			continue
		}
		result, err := h.subService.UpdateSubscription(c.Request.Context(), effectiveSub)
		if err != nil {
			failed++
			sub.LastError = err.Error()
			_ = h.subConfigMgr.UpdateSubscription(sub.ID, sub)
			items = append(items, itemResult{Subscription: h.toSubscriptionDTO(sub), Error: err.Error()})
			continue
		}
		updated++
		sub.LastUpdatedAt = time.Now()
		sub.LastNodeCount = result.NodeCount
		sub.LastAdded = result.AddedCount
		sub.LastUpdated = result.UpdatedCount
		sub.LastRemoved = result.RemovedCount
		sub.LastError = ""
		_ = h.subConfigMgr.UpdateSubscription(sub.ID, sub)
		items = append(items, itemResult{Subscription: h.toSubscriptionDTO(sub), Result: result})
	}
	if updated > 0 {
		h.triggerSubscriptionUpdateHook("subscription update all")
	}
	respondSuccess(c, map[string]interface{}{
		"updated": updated,
		"failed":  failed,
		"items":   items,
	})
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

func isMetadataLikeImportName(name string) bool {
	return metadataLikeImportNamePattern.MatchString(strings.TrimSpace(name))
}

func filterImportableParsedOutbounds(parsed []subscription.ParsedOutbound) []*config.ProxyOutbound {
	items := make([]*config.ProxyOutbound, 0, len(parsed))
	for _, item := range parsed {
		if item.Outbound == nil {
			continue
		}
		items = append(items, item.Outbound.Clone())
	}
	return items
}

func (h *ProxyOutboundHandler) ParseImportContent(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		respondError(c, http.StatusBadRequest, "请输入要导入的内容", "")
		return
	}

	parsed, err := subscription.ParseSubscriptionContent([]byte(content))
	if err != nil {
		respondError(c, http.StatusBadRequest, "解析导入内容失败", err.Error())
		return
	}

	items := filterImportableParsedOutbounds(parsed)
	if len(items) == 0 {
		respondError(c, http.StatusBadRequest, "未找到可导入的代理节点", "")
		return
	}

	respondSuccess(c, map[string]interface{}{
		"items":    items,
		"count":    len(items),
		"filtered": len(parsed) - len(items),
	})
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

	h.doTestOutbound(c, name, "")
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

	h.doTestOutbound(c, req.Name, strings.TrimSpace(req.ServerID))
}

func (h *ProxyOutboundHandler) executeTCPTest(ctx context.Context, name string) TestResult {
	result := TestResult{}
	if h.outboundMgr == nil {
		result.Error = "Outbound manager not initialized"
		return result
	}
	startTime := time.Now()
	err := h.outboundMgr.CheckHealth(ctx, name)
	result.Success = err == nil
	result.LatencyMs = time.Since(startTime).Milliseconds()
	if err != nil {
		result.Error = err.Error()
	}
	h.updateOutboundRuntime(name, func(outbound *config.ProxyOutbound) {
		if result.Success {
			outbound.SetTCPLatencyMs(result.LatencyMs)
		} else {
			outbound.SetTCPLatencyMs(0)
		}
	})
	if result.Success {
		h.recordOutboundLatency(name, config.LoadBalanceSortTCP, result.LatencyMs)
	} else {
		h.recordOutboundLatency(name, config.LoadBalanceSortTCP, 0)
	}
	return result
}

// doTestOutbound performs the actual test logic
func (h *ProxyOutboundHandler) doTestOutbound(c *gin.Context, name, serverID string) {
	name = strings.TrimSpace(name)
	serverID = strings.TrimSpace(serverID)

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
	result := h.executeTCPTest(ctx, name)
	if serverID != "" && h.outboundMgr != nil {
		if result.Success {
			h.outboundMgr.SetServerNodeLatency(serverID, name, config.LoadBalanceSortTCP, result.LatencyMs)
		} else {
			h.outboundMgr.SetServerNodeLatency(serverID, name, config.LoadBalanceSortTCP, 0)
		}
	}
	respondSuccess(c, result)
}

func normalizeBatchProxyTestNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func normalizeBatchProxyTestType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func newBatchProxyTestLimiter(limit int) chan struct{} {
	if limit < 1 {
		limit = 1
	}
	return make(chan struct{}, limit)
}

func defaultBatchProxyTestGlobalBudget() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 4 {
		workers = 4
	}
	// Batch tests are almost entirely network-bound (UDP sends, TLS
	// handshakes, short HTTP GETs) so they can be heavily oversubscribed
	// relative to CPU cores. On a typical 4-core box this now gives 48
	// concurrent slots globally and scales up on bigger boxes. The ceiling
	// keeps us below quic-go / TLS session memory ballooning even if a user
	// runs UDP and HTTP batches back-to-back.
	budget := workers * 16
	if budget < 64 {
		budget = 64
	}
	if budget > 256 {
		budget = 256
	}
	return budget
}

func defaultBatchProxyTestTypeBudget(testType string) int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 4 {
		workers = 4
	}
	switch normalizeBatchProxyTestType(testType) {
	case "udp":
		// UDP tests are dominated by network RTT (QUIC handshake or UDP
		// session + RakNet ping). With Hysteria2/AnyTLS session reuse each
		// subsequent test finishes in ~RTT, so we can safely run many in
		// parallel. On a 4-core box this yields 32 simultaneous UDP tests.
		budget := workers * 6
		if budget < 24 {
			budget = 24
		}
		if budget > 96 {
			budget = 96
		}
		return budget
	case "tcp", "http":
		// TCP/HTTP tests are cheap and mostly wait for TLS handshake + a
		// single HTTP GET. Oversubscribe aggressively for faster batches.
		budget := workers * 12
		if budget < 48 {
			budget = 48
		}
		if budget > 128 {
			budget = 128
		}
		return budget
	default:
		return defaultBatchProxyTestGlobalBudget()
	}
}

func batchProxyTestTypeLimiter(testType string) chan struct{} {
	switch normalizeBatchProxyTestType(testType) {
	case "tcp":
		return batchProxyTestTCPLimiter
	case "http":
		return batchProxyTestHTTPLimiter
	case "udp":
		return batchProxyTestUDPLimiter
	default:
		return nil
	}
}

func acquireBatchProxyTestLimiterToken(ctx context.Context, limiter chan struct{}) error {
	if limiter == nil {
		return nil
	}
	select {
	case limiter <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseBatchProxyTestLimiterToken(limiter chan struct{}) {
	if limiter == nil {
		return
	}
	select {
	case <-limiter:
	default:
	}
}

func acquireBatchProxyTestPermit(ctx context.Context, testType string) (func(), error) {
	typeLimiter := batchProxyTestTypeLimiter(testType)
	if err := acquireBatchProxyTestLimiterToken(ctx, batchProxyTestGlobalLimiter); err != nil {
		return nil, err
	}
	if err := acquireBatchProxyTestLimiterToken(ctx, typeLimiter); err != nil {
		releaseBatchProxyTestLimiterToken(batchProxyTestGlobalLimiter)
		return nil, err
	}
	return func() {
		releaseBatchProxyTestLimiterToken(typeLimiter)
		releaseBatchProxyTestLimiterToken(batchProxyTestGlobalLimiter)
	}, nil
}

// defaultBatchProxyTestConcurrency returns the default per-request
// concurrency used when the caller did not pass `concurrency` in the batch
// request body. Batch tests are almost entirely network-bound (UDP RakNet
// pings or short TLS + HTTP GETs) and are already gated globally by the
// per-type shared limiter (`batchProxyTestUDPLimiter` etc.), so the per-
// request default is set to the per-type cap. This way a user who selects
// N nodes in the UI sees up to min(N, cap) actually running in parallel
// right away without needing to plumb a `concurrency` field through every
// frontend call site. Overlapping batches still queue cleanly on the
// shared limiter; see `batchProxyTestTypeLimiter`.
func defaultBatchProxyTestConcurrency(testType string) int {
	return defaultBatchProxyTestTypeBudget(testType)
}

func clampBatchProxyTestConcurrency(total, requested int, testType string) int {
	if total <= 0 {
		return 1
	}
	if requested <= 0 {
		requested = defaultBatchProxyTestConcurrency(testType)
	}
	// Keep the per-request ceiling in lockstep with the shared type budget.
	maxConcurrency := defaultBatchProxyTestTypeBudget(testType)
	if requested > maxConcurrency {
		requested = maxConcurrency
	}
	if requested > total {
		requested = total
	}
	if requested < 1 {
		requested = 1
	}
	return requested
}

func batchProxyTestItemTimeout(testType string) time.Duration {
	switch normalizeBatchProxyTestType(testType) {
	case "tcp":
		return 12 * time.Second
	case "http":
		return 20 * time.Second
	case "udp":
		return 12 * time.Second
	default:
		return 30 * time.Second
	}
}

func writeBatchProxyTestStreamEvent(encoder *json.Encoder, flusher http.Flusher, event BatchProxyTestStreamEvent) error {
	if err := encoder.Encode(event); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func buildHTTPTestTargets(requested []string) []HTTPTestTarget {
	targets := make([]HTTPTestTarget, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, target := range requested {
		key := strings.ToLower(strings.TrimSpace(target))
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		switch key {
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
	return targets
}

func bestHTTPLatency(httpTests []HTTPTestResult, custom *HTTPTestResult) int64 {
	var best int64 = -1
	for _, httpTest := range httpTests {
		if httpTest.Success && (best < 0 || httpTest.LatencyMs < best) {
			best = httpTest.LatencyMs
		}
	}
	if custom != nil && custom.Success && (best < 0 || custom.LatencyMs < best) {
		best = custom.LatencyMs
	}
	return best
}

func firstHTTPFailure(httpTests []HTTPTestResult, custom *HTTPTestResult) string {
	for _, httpTest := range httpTests {
		if !httpTest.Success && strings.TrimSpace(httpTest.Error) != "" {
			return httpTest.Error
		}
	}
	if custom != nil && !custom.Success && strings.TrimSpace(custom.Error) != "" {
		return custom.Error
	}
	return ""
}

type httpTestClientConfig struct {
	dialContext           func(ctx context.Context, network, address string) (net.Conn, error)
	requestTimeout        time.Duration
	tlsHandshakeTimeout   time.Duration
	responseHeaderTimeout time.Duration
	idleConnTimeout       time.Duration
}

func newHTTPTestClient(cfg httpTestClientConfig) (*http.Client, *http.Transport) {
	transport := &http.Transport{
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       8,
		IdleConnTimeout:       cfg.idleConnTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout:   cfg.tlsHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.responseHeaderTimeout,
	}
	if cfg.dialContext != nil {
		transport.DialContext = cfg.dialContext
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.requestTimeout,
	}
	return client, transport
}

func closeHTTPResponseBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64*1024))
	_ = body.Close()
}

func (h *ProxyOutboundHandler) resolveBatchMCBEAddress(req BatchProxyTestRequest) string {
	address := strings.TrimSpace(req.Address)
	if address != "" {
		return address
	}
	if strings.TrimSpace(req.ServerID) != "" && h.serverConfigMgr != nil {
		if serverCfg, ok := h.serverConfigMgr.GetServer(req.ServerID); ok {
			address = strings.TrimSpace(serverCfg.GetTargetAddr())
		}
	}
	if address == "" {
		address = defaultMCBEUDPTestAddress
	}
	return address
}

func (h *ProxyOutboundHandler) executeBatchProxyTests(ctx context.Context, names []string, req BatchProxyTestRequest, allowPrivate bool, onItem func(item BatchProxyTestItem, progress batchProxyTestProgress) error) (BatchProxyTestResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	batchStart := time.Now()
	type job struct {
		index      int
		name       string
		enqueuedAt time.Time
	}
	type result struct {
		index int
		item  BatchProxyTestItem
	}
	concurrency := clampBatchProxyTestConcurrency(len(names), req.Concurrency, req.Type)
	items := make([]BatchProxyTestItem, len(names))
	jobs := make(chan job)
	results := make(chan result, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					releasePermit, err := acquireBatchProxyTestPermit(ctx, req.Type)
					if err != nil {
						return
					}
					queueWait := time.Since(job.enqueuedAt)
					itemCtx, itemCancel := context.WithTimeout(ctx, batchProxyTestItemTimeout(req.Type))
					execStart := time.Now()
					item := h.executeBatchTestItem(itemCtx, job.name, req, allowPrivate)
					item.QueueWaitMs = queueWait.Milliseconds()
					item.DurationMs = time.Since(execStart).Milliseconds()
					releasePermit()
					itemCancel()
					select {
					case results <- result{index: job.index, item: item}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index, name := range names {
			queuedJob := job{index: index, name: name, enqueuedAt: time.Now()}
			select {
			case <-ctx.Done():
				return
			case jobs <- queuedJob:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	progress := batchProxyTestProgress{}
	var totalQueueWaitMs int64
	var maxQueueWaitMs int64
	var totalDurationMs int64
	var maxDurationMs int64
	for result := range results {
		items[result.index] = result.item
		progress.Current++
		totalQueueWaitMs += result.item.QueueWaitMs
		if result.item.QueueWaitMs > maxQueueWaitMs {
			maxQueueWaitMs = result.item.QueueWaitMs
		}
		totalDurationMs += result.item.DurationMs
		if result.item.DurationMs > maxDurationMs {
			maxDurationMs = result.item.DurationMs
		}
		if result.item.Success {
			progress.Success++
		} else {
			progress.Failed++
		}
		if onItem != nil {
			if err := onItem(result.item, progress); err != nil {
				cancel()
				return BatchProxyTestResponse{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil && progress.Current < len(names) {
		return BatchProxyTestResponse{}, err
	}
	avgQueueWaitMs := int64(0)
	avgDurationMs := int64(0)
	if progress.Current > 0 {
		avgQueueWaitMs = totalQueueWaitMs / int64(progress.Current)
		avgDurationMs = totalDurationMs / int64(progress.Current)
	}
	logger.Debug("Batch proxy test done: type=%s total=%d success=%d failed=%d concurrency=%d elapsed_ms=%d avg_queue_ms=%d max_queue_ms=%d avg_item_ms=%d max_item_ms=%d",
		req.Type,
		len(items),
		progress.Success,
		progress.Failed,
		concurrency,
		time.Since(batchStart).Milliseconds(),
		avgQueueWaitMs,
		maxQueueWaitMs,
		avgDurationMs,
		maxDurationMs,
	)
	return BatchProxyTestResponse{
		Type:    req.Type,
		Total:   len(items),
		Success: progress.Success,
		Failed:  progress.Failed,
		Items:   items,
	}, nil
}

func (h *ProxyOutboundHandler) executeBatchHTTPTest(ctx context.Context, name string, req BatchProxyTestRequest, allowPrivate bool) BatchProxyTestItem {
	item := BatchProxyTestItem{Name: name}
	cfg, exists := h.configMgr.GetOutbound(name)
	if !exists {
		item.Error = "proxy outbound not found"
		return item
	}
	if h.outboundMgr == nil {
		item.Error = "Outbound manager not initialized"
		return item
	}
	targets := buildHTTPTestTargets(req.Targets)
	if len(targets) == 0 && req.CustomHTTP == nil {
		targets = []HTTPTestTarget{DefaultHTTPTestTargets[0]}
	}
	includePing := true
	if req.IncludePing != nil {
		includePing = *req.IncludePing
	}
	var pingResult *PingTestResult
	if includePing {
		result := h.testPing(ctx, cfg)
		pingResult = &result
	}
	skipProxyHTTPDueToPingFailure := shouldShortCircuitProxyHTTPTests(cfg, pingResult)
	customHTTPURL := ""
	if req.CustomHTTP != nil {
		customHTTPURL = strings.TrimSpace(req.CustomHTTP.URL)
	}
	needsDialer := (!skipProxyHTTPDueToPingFailure && len(targets) > 0) || (customHTTPURL != "" && req.CustomHTTP != nil && !req.CustomHTTP.DirectTest && !skipProxyHTTPDueToPingFailure)
	var dialer singboxcore.Dialer
	var httpClient *http.Client
	var httpTransport *http.Transport
	if needsDialer {
		var err error
		dialer, err = h.singboxFactory.CreateDialer(ctx, cfg)
		if err != nil {
			item.Error = fmt.Sprintf("Failed to create proxy dialer: %v", err)
			h.updateOutboundRuntime(name, func(outbound *config.ProxyOutbound) {
				outbound.SetHTTPLatencyMs(0)
			})
			if strings.TrimSpace(req.ServerID) != "" && h.outboundMgr != nil {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, name, config.LoadBalanceSortHTTP, 0)
			}
			h.recordOutboundLatency(name, config.LoadBalanceSortHTTP, 0)
			return item
		}
		defer dialer.Close()
		httpClient, httpTransport = newHTTPTestClient(httpTestClientConfig{
			dialContext:           dialer.DialContext,
			requestTimeout:        10 * time.Second,
			tlsHandshakeTimeout:   8 * time.Second,
			responseHeaderTimeout: 10 * time.Second,
			idleConnTimeout:       60 * time.Second,
		})
		defer httpTransport.CloseIdleConnections()
	}
	httpTests := make([]HTTPTestResult, 0, len(targets))
	if len(targets) > 0 {
		if skipProxyHTTPDueToPingFailure {
			errText := proxyServerConnectivityFailureError(pingResult)
			for _, target := range targets {
				httpTests = append(httpTests, HTTPTestResult{Target: target.Name, URL: target.URL, Error: errText})
			}
		} else {
			resultsChan := make(chan HTTPTestResult, len(targets))
			var httpWG sync.WaitGroup
			for _, target := range targets {
				httpWG.Add(1)
				go func(target HTTPTestTarget) {
					defer httpWG.Done()
					resultsChan <- h.testHTTPWithClient(ctx, httpClient, cfg, target)
				}(target)
			}
			go func() {
				httpWG.Wait()
				close(resultsChan)
			}()
			for httpResult := range resultsChan {
				httpTests = append(httpTests, httpResult)
			}
		}
	}
	var customResult *HTTPTestResult
	if customHTTPURL != "" {
		if skipProxyHTTPDueToPingFailure && req.CustomHTTP != nil && !req.CustomHTTP.DirectTest {
			result := HTTPTestResult{URL: customHTTPURL, Error: proxyServerConnectivityFailureError(pingResult)}
			customResult = &result
		} else if err := validateURLForRequest(customHTTPURL, allowPrivate); err != nil {
			result := HTTPTestResult{URL: customHTTPURL, Error: err.Error()}
			customResult = &result
		} else {
			customReq := *req.CustomHTTP
			customReq.URL = customHTTPURL
			var result HTTPTestResult
			if customReq.DirectTest {
				result = h.testCustomHTTP(ctx, nil, &customReq)
			} else {
				result = h.testCustomHTTPWithClient(ctx, httpClient, &customReq)
			}
			customResult = &result
		}
	}
	bestLatency := bestHTTPLatency(httpTests, customResult)
	item.Success = bestLatency >= 0
	if item.Success {
		item.HTTPLatencyMs = bestLatency
	} else {
		item.Error = firstHTTPFailure(httpTests, customResult)
		if strings.TrimSpace(item.Error) == "" {
			item.Error = "http test failed"
		}
	}
	if strings.TrimSpace(req.ServerID) != "" && h.outboundMgr != nil {
		if bestLatency >= 0 {
			h.outboundMgr.SetServerNodeLatency(req.ServerID, name, config.LoadBalanceSortHTTP, bestLatency)
		} else {
			h.outboundMgr.SetServerNodeLatency(req.ServerID, name, config.LoadBalanceSortHTTP, 0)
		}
	}
	h.updateOutboundRuntime(name, func(outbound *config.ProxyOutbound) {
		if bestLatency >= 0 {
			outbound.SetHTTPLatencyMs(bestLatency)
		} else {
			outbound.SetHTTPLatencyMs(0)
		}
	})
	if bestLatency >= 0 {
		h.recordOutboundLatency(name, config.LoadBalanceSortHTTP, bestLatency)
	} else {
		h.recordOutboundLatency(name, config.LoadBalanceSortHTTP, 0)
	}
	return item
}

func (h *ProxyOutboundHandler) executeBatchUDPTest(ctx context.Context, name string, req BatchProxyTestRequest) BatchProxyTestItem {
	item := BatchProxyTestItem{Name: name}
	cfg, exists := h.configMgr.GetOutbound(name)
	if !exists {
		item.Error = "proxy outbound not found"
		return item
	}
	address := h.resolveBatchMCBEAddress(req)
	result := h.testMCBEServer(ctx, cfg, address)
	available := result.Success
	item.Success = result.Success
	item.UDPAvailable = &available
	if result.Success {
		item.UDPLatencyMs = result.LatencyMs
	} else {
		item.Error = result.Error
	}
	if strings.TrimSpace(req.ServerID) != "" && h.outboundMgr != nil {
		if result.Success {
			h.outboundMgr.SetServerNodeLatency(req.ServerID, name, config.LoadBalanceSortUDP, result.LatencyMs)
		} else {
			h.outboundMgr.SetServerNodeLatency(req.ServerID, name, config.LoadBalanceSortUDP, 0)
		}
	}
	h.updateOutboundRuntime(name, func(outbound *config.ProxyOutbound) {
		outbound.SetUDPAvailable(&available)
		if result.Success {
			outbound.SetUDPLatencyMs(result.LatencyMs)
		} else {
			outbound.SetUDPLatencyMs(0)
		}
	})
	if result.Success {
		h.recordOutboundLatency(name, config.LoadBalanceSortUDP, result.LatencyMs)
	} else {
		h.recordOutboundLatency(name, config.LoadBalanceSortUDP, 0)
	}
	return item
}

func (h *ProxyOutboundHandler) executeBatchTestItem(ctx context.Context, name string, req BatchProxyTestRequest, allowPrivate bool) BatchProxyTestItem {
	testType := normalizeBatchProxyTestType(req.Type)
	switch testType {
	case "tcp":
		result := h.executeTCPTest(ctx, name)
		return BatchProxyTestItem{Name: name, Success: result.Success, Error: result.Error, LatencyMs: result.LatencyMs}
	case "http":
		return h.executeBatchHTTPTest(ctx, name, req, allowPrivate)
	case "udp":
		return h.executeBatchUDPTest(ctx, name, req)
	default:
		return BatchProxyTestItem{Name: name, Error: fmt.Sprintf("unsupported batch test type: %s", req.Type)}
	}
}

func (h *ProxyOutboundHandler) BatchTestProxyOutbounds(c *gin.Context) {
	var req BatchProxyTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	names := normalizeBatchProxyTestNames(req.Names)
	if len(names) == 0 {
		respondError(c, http.StatusBadRequest, "Invalid request", "names is required")
		return
	}
	req.Type = normalizeBatchProxyTestType(req.Type)
	if req.Type != "tcp" && req.Type != "http" && req.Type != "udp" {
		respondError(c, http.StatusBadRequest, "Invalid request", "type must be tcp, http, or udp")
		return
	}
	allowPrivate := allowPrivateTargets(c)
	concurrency := clampBatchProxyTestConcurrency(len(names), req.Concurrency, req.Type)
	if req.Stream {
		flusher, ok := c.Writer.(http.Flusher)
		if !ok {
			respondError(c, http.StatusInternalServerError, "Streaming not supported", "response writer does not support flushing")
			return
		}
		c.Writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("X-Accel-Buffering", "no")
		c.Status(http.StatusOK)
		c.Writer.WriteHeaderNow()
		encoder := json.NewEncoder(c.Writer)
		if err := writeBatchProxyTestStreamEvent(encoder, flusher, BatchProxyTestStreamEvent{Event: "start", Type: req.Type, Total: len(names), Concurrency: concurrency}); err != nil {
			return
		}
		response, err := h.executeBatchProxyTests(c.Request.Context(), names, req, allowPrivate, func(item BatchProxyTestItem, progress batchProxyTestProgress) error {
			eventItem := item
			return writeBatchProxyTestStreamEvent(encoder, flusher, BatchProxyTestStreamEvent{Event: "item", Type: req.Type, Total: len(names), Current: progress.Current, Success: progress.Success, Failed: progress.Failed, Concurrency: concurrency, Item: &eventItem})
		})
		if err != nil {
			return
		}
		_ = writeBatchProxyTestStreamEvent(encoder, flusher, BatchProxyTestStreamEvent{Event: "done", Type: response.Type, Total: response.Total, Current: response.Total, Success: response.Success, Failed: response.Failed, Concurrency: concurrency})
		return
	}
	response, err := h.executeBatchProxyTests(c.Request.Context(), names, req, allowPrivate, nil)
	if err != nil {
		respondError(c, http.StatusRequestTimeout, "Batch test failed", err.Error())
		return
	}
	respondSuccess(c, response)
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

func (h *ProxyOutboundHandler) BlockProxyOutboundAutoSelectByBody(c *gin.Context) {
	var req ProxyOutboundAutoSelectBlockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		respondError(c, http.StatusBadRequest, "Invalid request body", "expires_at must be in the future")
		return
	}
	outbound, err := h.applyProxyOutboundAutoSelectBlock(req.Name, strings.TrimSpace(req.Reason), req.ExpiresAt, true)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Failed to update proxy outbound", err.Error())
		return
	}
	respondSuccess(c, h.toDTO(outbound))
}

func (h *ProxyOutboundHandler) UnblockProxyOutboundAutoSelectByBody(c *gin.Context) {
	var req NameRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	outbound, err := h.applyProxyOutboundAutoSelectBlock(req.Name, "", nil, false)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Failed to update proxy outbound", err.Error())
		return
	}
	respondSuccess(c, h.toDTO(outbound))
}

func (h *ProxyOutboundHandler) BatchBlockProxyOutboundAutoSelectByBody(c *gin.Context) {
	var req BatchProxyOutboundAutoSelectBlockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		respondError(c, http.StatusBadRequest, "Invalid request body", "expires_at must be in the future")
		return
	}
	items, updated, err := h.batchApplyProxyOutboundAutoSelectBlock(req.Names, strings.TrimSpace(req.Reason), req.ExpiresAt, true)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Failed to update proxy outbounds", err.Error())
		return
	}
	respondSuccess(c, map[string]interface{}{
		"updated":  updated,
		"outbounds": items,
	})
}

func (h *ProxyOutboundHandler) BatchUnblockProxyOutboundAutoSelectByBody(c *gin.Context) {
	var req struct {
		Names []string `json:"names" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	items, updated, err := h.batchApplyProxyOutboundAutoSelectBlock(req.Names, "", nil, false)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Failed to update proxy outbounds", err.Error())
		return
	}
	respondSuccess(c, map[string]interface{}{
		"updated":  updated,
		"outbounds": items,
	})
}

func (h *ProxyOutboundHandler) applyProxyOutboundAutoSelectBlock(name, reason string, expiresAt *time.Time, blocked bool) (*config.ProxyOutbound, error) {
	if h == nil || h.configMgr == nil {
		return nil, fmt.Errorf("proxy outbound config manager not initialized")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	outbound, exists := h.configMgr.GetOutbound(name)
	if !exists || outbound == nil {
		return nil, fmt.Errorf("proxy outbound %s not found", name)
	}
	if blocked {
		outbound.AutoSelectBlocked = true
		outbound.AutoSelectBlockReason = reason
		if expiresAt != nil {
			value := *expiresAt
			outbound.AutoSelectBlockExpiresAt = &value
		} else {
			outbound.AutoSelectBlockExpiresAt = nil
		}
	} else {
		outbound.AutoSelectBlocked = false
		outbound.AutoSelectBlockReason = ""
		outbound.AutoSelectBlockExpiresAt = nil
	}
	if err := h.configMgr.UpdateOutbound(name, outbound); err != nil {
		return nil, err
	}
	if h.outboundMgr != nil {
		_ = h.outboundMgr.UpdateOutbound(name, outbound)
	}
	return outbound, nil
}

func (h *ProxyOutboundHandler) batchApplyProxyOutboundAutoSelectBlock(names []string, reason string, expiresAt *time.Time, blocked bool) ([]ProxyOutboundDTO, int, error) {
	if h == nil || h.configMgr == nil {
		return nil, 0, fmt.Errorf("proxy outbound config manager not initialized")
	}
	unique := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		unique = append(unique, name)
	}
	if len(unique) == 0 {
		return nil, 0, fmt.Errorf("names are required")
	}
	items := make([]ProxyOutboundDTO, 0, len(unique))
	updated := 0
	for _, name := range unique {
		outbound, err := h.applyProxyOutboundAutoSelectBlock(name, reason, expiresAt, blocked)
		if err != nil {
			return nil, updated, err
		}
		items = append(items, h.toDTO(outbound))
		updated++
	}
	return items, updated, nil
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
	Name     string `json:"name" binding:"required"`
	ServerID string `json:"server_id,omitempty"`
	Address  string `json:"address,omitempty"` // Default: mco.cubecraft.net:19132
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
	ServerID     string             `json:"server_id,omitempty"`
	IncludePing  *bool              `json:"include_ping,omitempty"`
	IncludeUDP   *bool              `json:"include_udp,omitempty"`
	UDPAddress   string             `json:"udp_address,omitempty"`
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

func shouldShortCircuitProxyHTTPTests(cfg *config.ProxyOutbound, pingResult *PingTestResult) bool {
	if cfg == nil || pingResult == nil || pingResult.Success {
		return false
	}
	switch cfg.Type {
	case config.ProtocolShadowsocks, config.ProtocolVMess, config.ProtocolTrojan, config.ProtocolVLESS, config.ProtocolSOCKS5, config.ProtocolHTTP, config.ProtocolAnyTLS:
		return true
	default:
		return false
	}
}

func proxyServerConnectivityFailureError(pingResult *PingTestResult) string {
	if pingResult != nil && strings.TrimSpace(pingResult.Error) != "" {
		return fmt.Sprintf("skipped because proxy server connectivity test failed: %s", pingResult.Error)
	}
	return "skipped because proxy server connectivity test failed"
}

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
	testCtx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	result := DetailedTestResult{
		Name:      req.Name,
		HTTPTests: make([]HTTPTestResult, 0),
	}
	allowPrivate := allowPrivateTargets(c)
	includePing := true
	if req.IncludePing != nil {
		includePing = *req.IncludePing
	}
	includeUDP := false
	if req.IncludeUDP != nil {
		includeUDP = *req.IncludeUDP
	}
	udpAddress := strings.TrimSpace(req.UDPAddress)
	if udpAddress == "" {
		udpAddress = defaultMCBEUDPTestAddress
	}
	allSuccess := true

	// 1. Ping test to proxy server using configured port
	if includePing {
		pingResult := h.testPing(testCtx, cfg)
		result.PingTest = &pingResult
		if req.ServerID != "" && h.outboundMgr != nil {
			if pingResult.Success {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortTCP, pingResult.LatencyMs)
			} else {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortTCP, 0)
			}
		}
		h.updateOutboundRuntime(req.Name, func(outbound *config.ProxyOutbound) {
			if pingResult.Success {
				outbound.SetTCPLatencyMs(pingResult.LatencyMs)
			} else {
				outbound.SetTCPLatencyMs(0)
			}
		})
		if pingResult.Success {
			h.recordOutboundLatency(req.Name, config.LoadBalanceSortTCP, pingResult.LatencyMs)
		} else {
			h.recordOutboundLatency(req.Name, config.LoadBalanceSortTCP, 0)
		}
		if !pingResult.Success {
			allSuccess = false
		}
	}
	if includeUDP {
		udpResult := h.testMCBEServer(testCtx, cfg, udpAddress)
		result.UDPTest = &udpResult
		if !udpResult.Success {
			allSuccess = false
		}
	}

	targets := buildHTTPTestTargets(req.Targets)

	customHTTPURL := ""
	if req.CustomHTTP != nil {
		customHTTPURL = strings.TrimSpace(req.CustomHTTP.URL)
	}

	skipProxyHTTPDueToPingFailure := shouldShortCircuitProxyHTTPTests(cfg, result.PingTest)
	needsDialer := (!skipProxyHTTPDueToPingFailure && len(targets) > 0) || (customHTTPURL != "" && req.CustomHTTP != nil && !req.CustomHTTP.DirectTest && !skipProxyHTTPDueToPingFailure)
	var dialer singboxcore.Dialer
	var httpClient *http.Client
	var httpTransport *http.Transport
	if needsDialer {
		var err error
		dialer, err = h.singboxFactory.CreateDialer(testCtx, cfg)
		if err != nil {
			result.Success = false
			result.Error = fmt.Sprintf("Failed to create proxy dialer: %v", err)
			if req.ServerID != "" && h.outboundMgr != nil {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortHTTP, 0)
			}
			respondSuccess(c, result)
			return
		}
		defer dialer.Close()
		httpClient, httpTransport = newHTTPTestClient(httpTestClientConfig{
			dialContext:           dialer.DialContext,
			requestTimeout:        10 * time.Second,
			tlsHandshakeTimeout:   8 * time.Second,
			responseHeaderTimeout: 10 * time.Second,
			idleConnTimeout:       60 * time.Second,
		})
		defer httpTransport.CloseIdleConnections()
	}

	// 2. HTTP tests through proxy (concurrent)
	if len(targets) > 0 {
		if skipProxyHTTPDueToPingFailure {
			errText := proxyServerConnectivityFailureError(result.PingTest)
			for _, target := range targets {
				result.HTTPTests = append(result.HTTPTests, HTTPTestResult{
					Target:  target.Name,
					URL:     target.URL,
					Success: false,
					Error:   errText,
				})
			}
		} else {
			httpResultsChan := make(chan HTTPTestResult, len(targets))
			var httpWG sync.WaitGroup
			for _, target := range targets {
				httpWG.Add(1)
				go func(t HTTPTestTarget) {
					defer httpWG.Done()
					httpResultsChan <- h.testHTTPWithClient(testCtx, httpClient, cfg, t)
				}(target)
			}
			go func() {
				httpWG.Wait()
				close(httpResultsChan)
			}()

			for httpResult := range httpResultsChan {
				result.HTTPTests = append(result.HTTPTests, httpResult)
				if !httpResult.Success {
					allSuccess = false
				}
			}
		}
	}

	// 3. Speed test if requested
	if req.SpeedTest {
	}

	// 4. Custom HTTP request if provided
	if customHTTPURL != "" {
		if skipProxyHTTPDueToPingFailure && req.CustomHTTP != nil && !req.CustomHTTP.DirectTest {
			customResult := HTTPTestResult{
				URL:     customHTTPURL,
				Success: false,
				Error:   proxyServerConnectivityFailureError(result.PingTest),
			}
			result.CustomHTTP = &customResult
			allSuccess = false
		} else if err := validateURLForRequest(customHTTPURL, allowPrivate); err != nil {
			customResult := HTTPTestResult{
				URL:     customHTTPURL,
				Success: false,
				Error:   err.Error(),
			}
			result.CustomHTTP = &customResult
			allSuccess = false
		} else {
			customReq := *req.CustomHTTP
			customReq.URL = customHTTPURL
			var customResult HTTPTestResult
			if customReq.DirectTest {
				customResult = h.testCustomHTTP(testCtx, nil, &customReq)
			} else {
				customResult = h.testCustomHTTPWithClient(testCtx, httpClient, &customReq)
			}
			result.CustomHTTP = &customResult
			if !customResult.Success {
				allSuccess = false
			}
		}
	}

	result.Success = allSuccess

	// Update HTTP latency and persist to config file
	if len(result.HTTPTests) > 0 || result.CustomHTTP != nil {
		var bestLatency int64 = -1
		for _, httpTest := range result.HTTPTests {
			if httpTest.Success && (bestLatency < 0 || httpTest.LatencyMs < bestLatency) {
				bestLatency = httpTest.LatencyMs
			}
		}
		if result.CustomHTTP != nil && result.CustomHTTP.Success && (bestLatency < 0 || result.CustomHTTP.LatencyMs < bestLatency) {
			bestLatency = result.CustomHTTP.LatencyMs
		}
		if req.ServerID != "" && h.outboundMgr != nil {
			if bestLatency >= 0 {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortHTTP, bestLatency)
			} else {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortHTTP, 0)
			}
		}
		h.updateOutboundRuntime(req.Name, func(outbound *config.ProxyOutbound) {
			if bestLatency >= 0 {
				outbound.SetHTTPLatencyMs(bestLatency)
			} else {
				outbound.SetHTTPLatencyMs(0)
			}
		})
		if bestLatency >= 0 {
			h.recordOutboundLatency(req.Name, config.LoadBalanceSortHTTP, bestLatency)
		} else {
			h.recordOutboundLatency(req.Name, config.LoadBalanceSortHTTP, 0)
		}
	}
	if result.UDPTest != nil {
		udpAvailable := result.UDPTest.Success
		if req.ServerID != "" && h.outboundMgr != nil {
			if udpAvailable {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortUDP, result.UDPTest.LatencyMs)
			} else {
				h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortUDP, 0)
			}
		}
		h.updateOutboundRuntime(req.Name, func(outbound *config.ProxyOutbound) {
			outbound.SetUDPAvailable(&udpAvailable)
			if udpAvailable {
				outbound.SetUDPLatencyMs(result.UDPTest.LatencyMs)
			} else {
				outbound.SetUDPLatencyMs(0)
			}
		})
		if udpAvailable {
			h.recordOutboundLatency(req.Name, config.LoadBalanceSortUDP, result.UDPTest.LatencyMs)
		} else {
			h.recordOutboundLatency(req.Name, config.LoadBalanceSortUDP, 0)
		}
	}

	respondSuccess(c, result)
}

// testPing performs connectivity test to the proxy server using the configured port.
// For Hysteria2 (QUIC-based), it uses UDP; for other protocols, it uses TCP.
// For Hysteria2 with port hopping, it tests a random port from the configured range.
func (h *ProxyOutboundHandler) testPing(ctx context.Context, cfg *config.ProxyOutbound) PingTestResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := PingTestResult{
		Host: cfg.Server,
	}

	port := cfg.Port
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
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
		addr, err := proxy.ResolveOutboundServerAddress(ctx, cfg.Server, port)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			return result
		}
		logger.Debug("Ping test resolved: node=%s type=%s server=%s:%d resolved=%s", cfg.Name, cfg.Type, cfg.Server, port, addr)
		return h.testUDPPing(ctx, addr)
	}

	// Other protocols use TCP
	startTime := time.Now()
	conn, dialedAddr, err := proxy.DialOutboundServerTCP(ctx, cfg.Server, port, 8*time.Second)
	latency := time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.LatencyMs = latency.Milliseconds()
		return result
	}
	defer conn.Close()
	logger.Debug("Ping test resolved: node=%s type=%s server=%s:%d resolved=%s", cfg.Name, cfg.Type, cfg.Server, port, dialedAddr)

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

type packetConnWriter interface {
	Write([]byte) (int, error)
}

func writePacket(conn net.PacketConn, payload []byte, addr net.Addr) (int, error) {
	n, err := conn.WriteTo(payload, addr)
	if err == nil {
		return n, nil
	}
	if writer, ok := conn.(packetConnWriter); ok && shouldFallbackToConnectedPacketWrite(err) {
		return writer.Write(payload)
	}
	return n, err
}

func shouldFallbackToConnectedPacketWrite(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "pre-connected") ||
		strings.Contains(errText, "use of writeto with") ||
		strings.Contains(errText, "connected connection")
}

// shouldReuseCachedUDPTestOutbound reports whether MCBE UDP tests should
// borrow the long-lived singbox outbound from OutboundManager rather than
// create a fresh one per test. Reusing the cached outbound is critical for
// protocols with an expensive session-setup cost:
//
//   - AnyTLS: a fresh TLS session + anytls handshake per test is wasteful.
//   - Hysteria2: a fresh QUIC + TLS handshake per test can easily consume the
//     entire 8s UDP test budget on high-RTT paths (e.g. JP↔US), causing
//     spurious "QUIC handshake timed out" failures. Caching keeps the QUIC
//     connection alive across tests of the same node, which also removes
//     handshake packet-loss sensitivity on loaded links.
//
// For the other tunneled protocols (VMess/Trojan/VLESS/Shadowsocks/SOCKS5)
// each ListenPacket establishes a short-lived per-call TCP session, so
// caching the outbound saves only a tiny amount of config setup and isn't
// worth the extra coupling.
func shouldReuseCachedUDPTestOutbound(cfg *config.ProxyOutbound) bool {
	if cfg == nil {
		return false
	}
	switch cfg.Type {
	case config.ProtocolAnyTLS, config.ProtocolHysteria2:
		return true
	default:
		return false
	}
}

// shouldMeasureWarmUDPTestLatency reports whether a second "warm" RakNet
// ping should be issued to obtain a steady-state RTT after the first
// session-establishment cost. For Hysteria2 the first ping pays the QUIC
// handshake + UDP-session-create cost on a cold outbound, so the warm
// measurement better represents what the running proxy will see.
func shouldMeasureWarmUDPTestLatency(cfg *config.ProxyOutbound) bool {
	if cfg == nil {
		return false
	}
	switch cfg.Type {
	case config.ProtocolAnyTLS, config.ProtocolHysteria2:
		return true
	default:
		return false
	}
}

// outboundPacketConnNoRetryDialer is satisfied by outbound managers that
// expose a fast-failing DialPacketConn variant. We narrow to this interface
// so the handler stays decoupled from the concrete proxy.outboundManagerImpl
// while still skipping the outbound-manager retry loop during UDP tests.
type outboundPacketConnNoRetryDialer interface {
	DialPacketConnNoRetry(ctx context.Context, outboundName string, destination string) (net.PacketConn, error)
}

func (h *ProxyOutboundHandler) openMCBEPacketConn(ctx context.Context, cfg *config.ProxyOutbound, address string) (net.PacketConn, func(), error) {
	if h != nil && h.outboundMgr != nil && cfg != nil && strings.TrimSpace(cfg.Name) != "" && shouldReuseCachedUDPTestOutbound(cfg) {
		// Use NoRetry variant for tests when the manager supports it: the
		// outbound-manager's built-in exponential-backoff retry loop
		// compounds with Hysteria2's own internal UDP-session retry and
		// can burn the entire 10s test budget before the fallback path
		// gets a chance. Fast-failing here lets us cleanly fall through
		// to creating a fresh outbound when the cached one is dead.
		var (
			packetConn net.PacketConn
			err        error
		)
		if noRetry, ok := h.outboundMgr.(outboundPacketConnNoRetryDialer); ok {
			packetConn, err = noRetry.DialPacketConnNoRetry(ctx, cfg.Name, address)
		} else {
			packetConn, err = h.outboundMgr.DialPacketConn(ctx, cfg.Name, address)
		}
		if err == nil {
			return packetConn, func() {
				_ = packetConn.Close()
			}, nil
		}
		logger.Debug("MCBE UDP cache dial failed node=%s type=%s target=%s err=%v", cfg.Name, cfg.Type, address, err)
	}

	outbound, err := h.singboxFactory.CreateUDPOutbound(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	packetConn, err := outbound.ListenPacket(ctx, address)
	if err != nil {
		_ = outbound.Close()
		return nil, nil, err
	}

	return packetConn, func() {
		_ = packetConn.Close()
		_ = outbound.Close()
	}, nil
}

func performMCBEPing(ctx context.Context, packetConn net.PacketConn, destAddr net.Addr) UDPTestResult {
	pingPacket := buildRakNetPing()
	expectedTimestamp := binary.BigEndian.Uint64(pingPacket[1:9])
	startTime := time.Now()

	_, err := writePacket(packetConn, pingPacket, destAddr)
	if err != nil {
		return UDPTestResult{
			Success:   false,
			LatencyMs: time.Since(startTime).Milliseconds(),
			Error:     fmt.Sprintf("Failed to send ping: %v", err),
		}
	}

	// RakNet pong normally returns in well under a second even over a proxy
	// tunnel, but on cold QUIC sessions and far-flung Pacific paths the first
	// response packet can be delayed 2-3s by congestion/jitter or the first
	// cwnd growth step. Keep the read budget at 4s so we don't abandon a
	// healthy session that is simply slow on its first reply, and always
	// honor the caller-supplied deadline so we never block past the test
	// budget enforced by testMCBEServer / executeBatchUDPTest.
	readDeadline := time.Now().Add(4 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(readDeadline) {
		readDeadline = deadline
	}

	buf := make([]byte, 1500)
	for {
		_ = packetConn.SetReadDeadline(readDeadline)
		n, _, err := packetConn.ReadFrom(buf)
		latency := time.Since(startTime)
		if err != nil {
			return UDPTestResult{
				Success:   false,
				LatencyMs: latency.Milliseconds(),
				Error:     fmt.Sprintf("Failed to receive response: %v", err),
			}
		}

		if n > 9 && buf[0] == 0x1c {
			responseTimestamp := binary.BigEndian.Uint64(buf[1:9])
			if responseTimestamp != expectedTimestamp {
				if time.Now().Before(readDeadline) {
					continue
				}
				return UDPTestResult{
					Success:   false,
					LatencyMs: latency.Milliseconds(),
					Error:     "Received stale response",
				}
			}
		}

		result := UDPTestResult{
			Success:   true,
			LatencyMs: latency.Milliseconds(),
		}

		if n > 35 && buf[0] == 0x1c {
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
		} else if n > 0 {
			result.ServerName = "Unknown (got response)"
		} else {
			result.Success = false
			result.Error = "Empty response"
		}

		return result
	}
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
func (h *ProxyOutboundHandler) testHTTPThroughProxy(ctx context.Context, cfg *config.ProxyOutbound, dialer singboxcore.Dialer, target HTTPTestTarget) HTTPTestResult {
	client, transport := newHTTPTestClient(httpTestClientConfig{
		dialContext:           dialer.DialContext,
		requestTimeout:        10 * time.Second,
		tlsHandshakeTimeout:   8 * time.Second,
		responseHeaderTimeout: 10 * time.Second,
		idleConnTimeout:       60 * time.Second,
	})
	defer transport.CloseIdleConnections()
	return h.testHTTPWithClient(ctx, client, cfg, target)
}

func (h *ProxyOutboundHandler) testHTTPWithClient(ctx context.Context, client *http.Client, cfg *config.ProxyOutbound, target HTTPTestTarget) HTTPTestResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := HTTPTestResult{
		Target:  target.Name,
		URL:     target.URL,
		Headers: make(map[string]string),
	}
	logger.Debug("HTTP test start: node=%s type=%s target=%s url=%s server=%s:%d tls=%v sni=%s fingerprint=%s", cfg.Name, cfg.Type, target.Name, target.URL, cfg.Server, cfg.Port, cfg.TLS, cfg.SNI, cfg.Fingerprint)
	if client == nil {
		result.Success = false
		result.Error = "http client is nil"
		return result
	}

	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")

	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req = req.WithContext(testCtx)

	startTime := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(startTime)
	result.LatencyMs = latency.Milliseconds()

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		logger.Debug("HTTP test failed: node=%s type=%s target=%s url=%s latency=%dms err=%v", cfg.Name, cfg.Type, target.Name, target.URL, result.LatencyMs, err)
		return result
	}
	defer closeHTTPResponseBody(resp.Body)

	result.StatusCode = resp.StatusCode
	result.StatusText = resp.Status
	result.ContentType = resp.Header.Get("Content-Type")
	result.Success = resp.StatusCode >= 200 && resp.StatusCode < 400
	logger.Debug("HTTP test completed: node=%s type=%s target=%s url=%s latency=%dms status=%d success=%v", cfg.Name, cfg.Type, target.Name, target.URL, result.LatencyMs, result.StatusCode, result.Success)

	return result
}

// testDownloadSpeed tests download speed through the proxy.
func (h *ProxyOutboundHandler) testDownloadSpeed(dialer singboxcore.Dialer, speedURL string) SpeedTestResult {
	result := SpeedTestResult{
		URL: speedURL,
	}

	client, transport := newHTTPTestClient(httpTestClientConfig{
		dialContext:           dialer.DialContext,
		requestTimeout:        180 * time.Second,
		tlsHandshakeTimeout:   30 * time.Second,
		responseHeaderTimeout: 120 * time.Second,
		idleConnTimeout:       90 * time.Second,
	})
	defer transport.CloseIdleConnections()

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
	defer closeHTTPResponseBody(resp.Body)

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
func (h *ProxyOutboundHandler) testCustomHTTP(ctx context.Context, dialer singboxcore.Dialer, req *CustomHTTPRequest) HTTPTestResult {
	clientCfg := httpTestClientConfig{
		requestTimeout:        20 * time.Second,
		tlsHandshakeTimeout:   30 * time.Second,
		responseHeaderTimeout: 60 * time.Second,
		idleConnTimeout:       60 * time.Second,
	}
	if !req.DirectTest && dialer != nil {
		clientCfg.dialContext = dialer.DialContext
		clientCfg.tlsHandshakeTimeout = 10 * time.Second
		clientCfg.responseHeaderTimeout = 15 * time.Second
	}
	client, transport := newHTTPTestClient(clientCfg)
	defer transport.CloseIdleConnections()
	return h.testCustomHTTPWithClient(ctx, client, req)
}

func (h *ProxyOutboundHandler) testCustomHTTPWithClient(ctx context.Context, client *http.Client, req *CustomHTTPRequest) HTTPTestResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := HTTPTestResult{
		URL:     req.URL,
		Headers: make(map[string]string),
	}
	if client == nil {
		result.Success = false
		result.Error = "http client is nil"
		return result
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

	testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	httpReq = httpReq.WithContext(testCtx)

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	latency := time.Since(startTime)
	result.LatencyMs = latency.Milliseconds()

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result
	}
	defer closeHTTPResponseBody(resp.Body)

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
		if req.ServerID != "" && h.serverConfigMgr != nil {
			if serverCfg, ok := h.serverConfigMgr.GetServer(req.ServerID); ok {
				address = serverCfg.GetTargetAddr()
			}
		}
		if address == "" {
			address = "mco.cubecraft.net:19132"
		}
	}

	testCtx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
	defer cancel()
	result := h.testMCBEServer(testCtx, cfg, address)
	if req.ServerID != "" && h.outboundMgr != nil {
		if result.Success {
			h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortUDP, result.LatencyMs)
		} else {
			h.outboundMgr.SetServerNodeLatency(req.ServerID, req.Name, config.LoadBalanceSortUDP, 0)
		}
	}

	// Update UDP availability and latency, persist to config file
	h.updateOutboundRuntime(req.Name, func(outbound *config.ProxyOutbound) {
		available := result.Success
		outbound.SetUDPAvailable(&available)
		if result.Success {
			outbound.SetUDPLatencyMs(result.LatencyMs)
		} else {
			outbound.SetUDPLatencyMs(0)
		}
	})
	if result.Success {
		h.recordOutboundLatency(req.Name, config.LoadBalanceSortUDP, result.LatencyMs)
	} else {
		h.recordOutboundLatency(req.Name, config.LoadBalanceSortUDP, 0)
	}

	respondSuccess(c, result)
}

func (h *ProxyOutboundHandler) GetProxyOutboundLatencyOverview(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}
	if h.configMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy outbound config manager not initialized", "")
		return
	}
	fromMs, _ := parseOptionalUnixMilli(c.Query("from"))
	toMs, _ := parseOptionalUnixMilli(c.Query("to"))
	limit := h.parseLatencyHistoryLimit(c.Query("limit"))
	outbounds := h.configMgr.GetAllOutbounds()
	respondSuccess(c, map[string]interface{}{
		"from":            fromMs,
		"to":              toMs,
		"limit":           limit,
		"latency_history": h.buildProxyOutboundLatencyHistorySnapshot(outbounds, fromMs, toMs, limit),
	})
}

func (h *ProxyOutboundHandler) GetProxyOutboundLatencyHistory(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}
	if h.configMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy outbound config manager not initialized", "")
		return
	}
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}
	outbound, exists := h.configMgr.GetOutbound(name)
	if !exists || outbound == nil {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}
	fromMs, _ := parseOptionalUnixMilli(c.Query("from"))
	toMs, _ := parseOptionalUnixMilli(c.Query("to"))
	limit := h.parseLatencyHistoryLimit(c.Query("limit"))
	respondSuccess(c, map[string]interface{}{
		"name":     name,
		"from":     fromMs,
		"to":       toMs,
		"limit":    limit,
		"outbound": h.toDTO(outbound),
		"metrics":  h.getProxyOutboundLatencyHistoryMetrics(name, fromMs, toMs, limit),
	})
}

// testMCBEServer tests connectivity to a MCBE server through the proxy.
//
// The total UDP-test budget is 10s. This accommodates a cold Hysteria2
// QUIC handshake (~1-4s on trans-Pacific paths) plus the RakNet request
// with a 4s read window, while still staying under the per-item batch
// timeout of 12s. Subsequent tests against the same Hysteria2/AnyTLS node
// reuse the cached outbound and finish in ~RTT, so this upper bound only
// matters for cold first-hit measurements.
func (h *ProxyOutboundHandler) testMCBEServer(ctx context.Context, cfg *config.ProxyOutbound, address string) UDPTestResult {
	if ctx == nil {
		ctx = context.Background()
	}
	result := UDPTestResult{
		Target: address,
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	packetConn, cleanup, err := h.openMCBEPacketConn(ctx, cfg, address)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Failed to create UDP connection: %v", err)
		return result
	}
	defer cleanup()

	// Parse address
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("Invalid address: %v", err)
		return result
	}
	port, _ := strconv.Atoi(portStr)

	// Build the destination net.Addr without doing a local DNS lookup. The
	// proxy-tunneled PacketConns returned by openMCBEPacketConn bake the inner
	// destination in at ListenPacket time (as a sing Socksaddr carrying the
	// FQDN) and ignore the addr passed to WriteTo, so we can forward the raw
	// hostname through the tunnel and let the remote end resolve it. Resolving
	// locally would be rewritten by any running TUN proxy into the fake-IP
	// ranges (100.64/10, 198.18/15, ...) and fail our special-use IP filter,
	// which is exactly what used to break cases like mco.cubecraft.net.
	var destAddr net.Addr
	if ip := net.ParseIP(host); ip != nil {
		destAddr = &net.UDPAddr{IP: ip, Port: port}
	} else {
		destAddr = &proxy.HostnamePortAddr{Host: host, Port: port}
	}

	result = performMCBEPing(ctx, packetConn, destAddr)
	result.Target = address
	if !result.Success {
		return result
	}

	if shouldMeasureWarmUDPTestLatency(cfg) {
		warmCtx, warmCancel := context.WithTimeout(ctx, 2*time.Second)
		defer warmCancel()
		warmResult := performMCBEPing(warmCtx, packetConn, destAddr)
		if warmResult.Success {
			logger.Debug("MCBE UDP warm latency node=%s type=%s target=%s cold=%d warm=%d", cfg.Name, cfg.Type, address, result.LatencyMs, warmResult.LatencyMs)
			warmResult.Target = address
			if warmResult.ServerName == "" {
				warmResult.ServerName = result.ServerName
			}
			if warmResult.Players == "" {
				warmResult.Players = result.Players
			}
			if warmResult.Version == "" {
				warmResult.Version = result.Version
			}
			result = warmResult
		} else {
			logger.Debug("MCBE UDP warm ping failed node=%s type=%s target=%s cold=%d err=%s", cfg.Name, cfg.Type, address, result.LatencyMs, warmResult.Error)
		}
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

// ListGroupsResponse represents the response for listing all groups.
type ListGroupsResponse struct {
	Success bool                `json:"success"`
	Data    []*proxy.GroupStats `json:"data"`
}

// GetGroupResponse represents the response for getting a single group.
type GetGroupResponse struct {
	Success bool              `json:"success"`
	Data    *proxy.GroupStats `json:"data"`
}

// ListGroups returns statistics for all proxy outbound groups.
// GET /api/proxy-outbounds/groups
// Requirements: 8.1, 8.4
func (h *ProxyOutboundHandler) ListGroups(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}

	groups := h.outboundMgr.ListGroups()
	if groups == nil {
		groups = []*proxy.GroupStats{}
	}

	respondSuccess(c, groups)
}

// GetGroup returns statistics for a specific proxy outbound group.
// GET /api/proxy-outbounds/groups/:name
// Requirements: 8.2, 8.3
func (h *ProxyOutboundHandler) GetGroup(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}

	groupName := c.Param("name")

	// Get group statistics
	stats := h.outboundMgr.GetGroupStats(groupName)
	if stats == nil {
		respondError(c, http.StatusNotFound, "Group not found", fmt.Sprintf("No group found with name '%s'", groupName))
		return
	}

	respondSuccess(c, stats)
}

type ServerNodeLatencyItem struct {
	Name      string `json:"name"`
	LatencyMs int64  `json:"latency_ms"`
	OK        bool   `json:"ok"`
}

func (h *ProxyOutboundHandler) listServerCandidateNodes(serverCfg *config.ServerConfig) []string {
	if h == nil || h.configMgr == nil || serverCfg == nil {
		return nil
	}
	proxyOutbound := strings.TrimSpace(serverCfg.ProxyOutbound)
	if proxyOutbound == "" || proxyOutbound == proxy.DirectNodeName {
		return nil
	}
	candidateNodes := make([]string, 0)
	if serverCfg.IsGroupSelection() {
		groupName := serverCfg.GetGroupName()
		outbounds := h.configMgr.GetByGroup(groupName)
		for _, o := range outbounds {
			if o != nil && o.Enabled {
				candidateNodes = append(candidateNodes, o.Name)
			}
		}
	} else if serverCfg.IsMultiNodeSelection() {
		for _, name := range serverCfg.GetNodeList() {
			if name == "" {
				continue
			}
			o, exists := h.configMgr.GetOutbound(name)
			if !exists || o == nil || !o.Enabled {
				continue
			}
			candidateNodes = append(candidateNodes, name)
		}
	} else {
		o, exists := h.configMgr.GetOutbound(proxyOutbound)
		if exists && o != nil && o.Enabled {
			candidateNodes = append(candidateNodes, proxyOutbound)
		}
	}
	return candidateNodes
}

// GetServerNodeLatency returns per-server per-node cached latency for the server's selected nodes.
// GET /api/servers/:id/node-latency?sort_by=udp
func (h *ProxyOutboundHandler) GetServerNodeLatency(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}
	if h.serverConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Server config manager not initialized", "")
		return
	}

	serverID := strings.TrimSpace(c.Param("id"))
	if serverID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "server id is required")
		return
	}

	serverCfg, ok := h.serverConfigMgr.GetServer(serverID)
	if !ok || serverCfg == nil {
		respondError(c, http.StatusNotFound, "Server not found", "")
		return
	}

	sortBy := strings.TrimSpace(c.Query("sort_by"))
	if sortBy == "" {
		sortBy = serverCfg.GetLoadBalanceSort()
	}
	order := strings.ToLower(strings.TrimSpace(c.Query("order")))
	if order != "desc" {
		order = "asc"
	}

	candidateNodes := h.listServerCandidateNodes(serverCfg)
	if len(candidateNodes) == 0 {
		respondSuccess(c, map[string]interface{}{
			"server_id": serverID,
			"sort_by":   sortBy,
			"order":     order,
			"nodes":     []ServerNodeLatencyItem{},
		})
		return
	}

	items := make([]ServerNodeLatencyItem, 0, len(candidateNodes))
	for _, nodeName := range candidateNodes {
		latency, ok := h.outboundMgr.GetServerNodeLatency(serverID, nodeName, sortBy)
		items = append(items, ServerNodeLatencyItem{Name: nodeName, LatencyMs: latency, OK: ok})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a := items[i]
		b := items[j]
		if a.OK != b.OK {
			return a.OK
		}
		if a.OK && b.OK && a.LatencyMs != b.LatencyMs {
			if order == "desc" {
				return a.LatencyMs > b.LatencyMs
			}
			return a.LatencyMs < b.LatencyMs
		}
		return a.Name < b.Name
	})

	respondSuccess(c, map[string]interface{}{
		"server_id": serverID,
		"sort_by":   sortBy,
		"order":     order,
		"nodes":     items,
	})
}

func (h *ProxyOutboundHandler) GetServerNodeLatencyHistory(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}
	if h.serverConfigMgr == nil {
		respondError(c, http.StatusInternalServerError, "Server config manager not initialized", "")
		return
	}

	serverID := strings.TrimSpace(c.Param("id"))
	if serverID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "server id is required")
		return
	}

	serverCfg, ok := h.serverConfigMgr.GetServer(serverID)
	if !ok || serverCfg == nil {
		respondError(c, http.StatusNotFound, "Server not found", "")
		return
	}

	sortBy := strings.TrimSpace(c.Query("sort_by"))
	if sortBy == "" {
		sortBy = serverCfg.GetLoadBalanceSort()
	}
	fromMs, _ := parseOptionalUnixMilli(c.Query("from"))
	toMs, _ := parseOptionalUnixMilli(c.Query("to"))
	limit := h.parseLatencyHistoryLimit(c.Query("limit"))

	candidateNodes := h.listServerCandidateNodes(serverCfg)
	items := make([]ServerNodeLatencyHistoryItem, 0, len(candidateNodes))
	for _, nodeName := range candidateNodes {
		samples := h.outboundMgr.GetServerNodeLatencyHistory(serverID, nodeName, sortBy)
		items = append(items, ServerNodeLatencyHistoryItem{
			Name:    nodeName,
			Samples: filterServerNodeLatencyHistorySamples(samples, fromMs, toMs, limit),
		})
	}

	respondSuccess(c, map[string]interface{}{
		"server_id": serverID,
		"sort_by":   sortBy,
		"from":      fromMs,
		"to":        toMs,
		"limit":     limit,
		"nodes":     items,
	})
}

// GetServerCurrentNode returns the currently pinned/selected node for a server.
// GET /api/servers/:id/current-node
func (h *ProxyOutboundHandler) GetServerCurrentNode(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}
	serverID := strings.TrimSpace(c.Param("id"))
	if serverID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "server id is required")
		return
	}

	serverCfg, ok := h.serverConfigMgr.GetServer(serverID)
	if !ok || serverCfg == nil {
		respondError(c, http.StatusNotFound, "Server not found", "")
		return
	}

	sortBy := serverCfg.GetLoadBalanceSort()
	nodeName, hasNode := h.outboundMgr.GetServerSelectedNode(serverID)

	// Collect all three latency types for current node
	var tcpMs, udpMs, httpMs int64
	var hasTcp, hasUdp, hasHttp bool
	if hasNode {
		tcpMs, hasTcp = h.outboundMgr.GetServerNodeLatency(serverID, nodeName, "tcp")
		udpMs, hasUdp = h.outboundMgr.GetServerNodeLatency(serverID, nodeName, "udp")
		httpMs, hasHttp = h.outboundMgr.GetServerNodeLatency(serverID, nodeName, "http")

		// Fallback to the outbound's own global latency when per-server cache is empty
		if !hasTcp || !hasUdp || !hasHttp {
			if ob, exists := h.configMgr.GetOutbound(nodeName); exists && ob != nil {
				if !hasTcp && ob.TCPLatencyMs > 0 {
					tcpMs = ob.TCPLatencyMs
					hasTcp = true
				}
				if !hasUdp && ob.UDPLatencyMs > 0 {
					udpMs = ob.UDPLatencyMs
					hasUdp = true
				}
				if !hasHttp && ob.HTTPLatencyMs > 0 {
					httpMs = ob.HTTPLatencyMs
					hasHttp = true
				}
			}
		}
	}

	// Also provide the best node for comparison
	proxyOutbound := strings.TrimSpace(serverCfg.ProxyOutbound)
	bestNode, bestLatency := h.outboundMgr.GetBestNodeForServer(serverID, proxyOutbound, sortBy)

	// Collect latencies for best node too (with global fallback)
	var bestTcp, bestUdp, bestHttp int64
	if bestNode != "" {
		bestTcp, _ = h.outboundMgr.GetServerNodeLatency(serverID, bestNode, "tcp")
		bestUdp, _ = h.outboundMgr.GetServerNodeLatency(serverID, bestNode, "udp")
		bestHttp, _ = h.outboundMgr.GetServerNodeLatency(serverID, bestNode, "http")
		if bestTcp == 0 || bestUdp == 0 || bestHttp == 0 {
			if ob, exists := h.configMgr.GetOutbound(bestNode); exists && ob != nil {
				if bestTcp == 0 && ob.TCPLatencyMs > 0 {
					bestTcp = ob.TCPLatencyMs
				}
				if bestUdp == 0 && ob.UDPLatencyMs > 0 {
					bestUdp = ob.UDPLatencyMs
				}
				if bestHttp == 0 && ob.HTTPLatencyMs > 0 {
					bestHttp = ob.HTTPLatencyMs
				}
			}
		}
	}

	respondSuccess(c, map[string]interface{}{
		"server_id":    serverID,
		"current_node": nodeName,
		"has_node":     hasNode,
		"tcp_ms":       tcpMs,
		"udp_ms":       udpMs,
		"http_ms":      httpMs,
		"has_tcp":      hasTcp,
		"has_udp":      hasUdp,
		"has_http":     hasHttp,
		"best_node":    bestNode,
		"best_latency": bestLatency,
		"best_tcp":     bestTcp,
		"best_udp":     bestUdp,
		"best_http":    bestHttp,
		"sort_by":      sortBy,
	})
}

// SwitchServerNode manually forces the server to switch to the current best node.
// POST /api/servers/:id/switch-node
func (h *ProxyOutboundHandler) SwitchServerNode(c *gin.Context) {
	if h.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}
	serverID := strings.TrimSpace(c.Param("id"))
	if serverID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "server id is required")
		return
	}

	serverCfg, ok := h.serverConfigMgr.GetServer(serverID)
	if !ok || serverCfg == nil {
		respondError(c, http.StatusNotFound, "Server not found", "")
		return
	}

	proxyOutbound := strings.TrimSpace(serverCfg.ProxyOutbound)
	if proxyOutbound == "" || proxyOutbound == "direct" {
		respondError(c, http.StatusBadRequest, "Server is in direct mode", "")
		return
	}

	sortBy := serverCfg.GetLoadBalanceSort()
	strategy := serverCfg.GetLoadBalance()
	bestNode, bestLatency := h.outboundMgr.GetBestNodeForServer(serverID, proxyOutbound, sortBy)

	// If no latency data, fall back to dynamic selection
	if bestNode == "" {
		selected, err := h.outboundMgr.SelectOutboundWithFailoverForServer(serverID, proxyOutbound, strategy, sortBy, nil)
		if err != nil || selected == nil {
			respondError(c, http.StatusBadRequest, "暂无可用节点，请确认代理节点配置正确且已启用", "")
			return
		}
		bestNode = selected.Name
		bestLatency = 0
	}

	oldNode, _ := h.outboundMgr.GetServerSelectedNode(serverID)
	h.outboundMgr.SetServerSelectedNode(serverID, bestNode)

	respondSuccess(c, map[string]interface{}{
		"server_id":  serverID,
		"old_node":   oldNode,
		"new_node":   bestNode,
		"latency_ms": bestLatency,
		"sort_by":    sortBy,
	})
}

type proxyPortUsageRef struct {
	ActiveConnections int
	CurrentNode       string
	HasNode           bool
	TCPMs             int64
	UDPMs             int64
	HTTPMs            int64
	HasTCP            bool
	HasUDP            bool
	HasHTTP           bool
}

func proxyPortSelectorIDForAPI(portID string) string {
	portID = strings.TrimSpace(portID)
	if portID == "" {
		return ""
	}
	return "proxy-port:" + portID
}

func (h *ProxyOutboundHandler) buildProxyPortUsageRef(port *config.ProxyPortConfig) proxyPortUsageRef {
	ref := proxyPortUsageRef{}
	if port == nil {
		return ref
	}
	if h.activityProvider != nil {
		ref.ActiveConnections = h.activityProvider.GetActiveConnectionsForProxyPort(port.ID)
	}
	if h.outboundMgr == nil {
		return ref
	}
	selectorID := proxyPortSelectorIDForAPI(port.ID)
	nodeName, hasNode := h.outboundMgr.GetServerSelectedNode(selectorID)
	ref.CurrentNode = nodeName
	ref.HasNode = hasNode
	if !hasNode {
		return ref
	}
	ref.TCPMs, ref.HasTCP = h.outboundMgr.GetServerNodeLatency(selectorID, nodeName, config.LoadBalanceSortTCP)
	ref.UDPMs, ref.HasUDP = h.outboundMgr.GetServerNodeLatency(selectorID, nodeName, config.LoadBalanceSortUDP)
	ref.HTTPMs, ref.HasHTTP = h.outboundMgr.GetServerNodeLatency(selectorID, nodeName, config.LoadBalanceSortHTTP)
	if (!ref.HasTCP || !ref.HasUDP || !ref.HasHTTP) && h.configMgr != nil {
		if outbound, exists := h.configMgr.GetOutbound(nodeName); exists && outbound != nil {
			if !ref.HasTCP && outbound.TCPLatencyMs > 0 {
				ref.TCPMs = outbound.TCPLatencyMs
				ref.HasTCP = true
			}
			if !ref.HasUDP && outbound.UDPLatencyMs > 0 {
				ref.UDPMs = outbound.UDPLatencyMs
				ref.HasUDP = true
			}
			if !ref.HasHTTP && outbound.HTTPLatencyMs > 0 {
				ref.HTTPMs = outbound.HTTPLatencyMs
				ref.HasHTTP = true
			}
		}
	}
	return ref
}

// FetchSubscription fetches a subscription URL, optionally through a proxy outbound.
// POST /api/proxy-outbounds/fetch-subscription
func (h *ProxyOutboundHandler) FetchSubscription(c *gin.Context) {
	var req struct {
		URL       string `json:"url"`
		ProxyName string `json:"proxy_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		respondError(c, http.StatusBadRequest, "请输入订阅地址", "")
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		respondError(c, http.StatusBadRequest, "订阅地址必须以 http:// 或 https:// 开头", "")
		return
	}

	// Build HTTP client, optionally through proxy
	var httpClient *http.Client
	var dialerToClose singboxcore.Dialer

	proxyName := strings.TrimSpace(req.ProxyName)
	if proxyName != "" && h.outboundMgr != nil {
		cfg, exists := h.outboundMgr.GetOutbound(proxyName)
		if !exists || cfg == nil {
			respondError(c, http.StatusBadRequest, "代理节点不存在: "+proxyName, "")
			return
		}
		if !cfg.Enabled {
			respondError(c, http.StatusBadRequest, "代理节点未启用: "+proxyName, "")
			return
		}
		dialer, err := h.singboxFactory.CreateDialer(c.Request.Context(), cfg)
		if err != nil {
			respondError(c, http.StatusInternalServerError, "创建代理连接失败: "+err.Error(), "")
			return
		}
		dialerToClose = dialer
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: dialer.DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	} else {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	// Ensure dialer is closed after use
	if dialerToClose != nil {
		defer dialerToClose.Close()
	}

	// Fetch subscription
	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		respondError(c, http.StatusBadRequest, "无效的订阅地址: "+err.Error(), "")
		return
	}
	httpReq.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		respondError(c, http.StatusBadGateway, "获取订阅失败: "+err.Error(), "")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respondError(c, http.StatusBadGateway, fmt.Sprintf("订阅服务器返回错误: HTTP %d", resp.StatusCode), "")
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		respondError(c, http.StatusInternalServerError, "读取订阅内容失败: "+err.Error(), "")
		return
	}

	respondSuccess(c, map[string]interface{}{
		"content":    string(body),
		"size":       len(body),
		"proxy_used": proxyName,
	})
}
