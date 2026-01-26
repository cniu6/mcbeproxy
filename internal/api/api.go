// Package api provides REST API functionality using Gin framework.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	runtimePprof "runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/pprof/profile"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sandertv/go-raknet"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/session"
)

// APIServer provides REST API endpoints for proxy management.
type APIServer struct {
	router       *gin.Engine
	server       *http.Server
	globalConfig *config.GlobalConfig
	configMgr    *config.ConfigManager
	sessionMgr   *session.SessionManager
	db           *db.Database
	keyRepo      *db.APIKeyRepository
	playerRepo   *db.PlayerRepository
	sessionRepo  *db.SessionRepository
	monitor      *monitor.Monitor
	promMetrics  *monitor.PrometheusMetrics
	// ProxyController interface for start/stop operations
	proxyController ProxyController
	// ACL manager for access control
	aclManager *acl.ACLManager
	// Proxy outbound handler for managing proxy outbound nodes
	proxyOutboundHandler *ProxyOutboundHandler
	// Proxy port config manager
	proxyPortConfigMgr *config.ProxyPortConfigManager
}

// ProxyController defines the interface for controlling proxy servers.
type ProxyController interface {
	StartServer(serverID string) error
	StopServer(serverID string) error
	ReloadServer(serverID string) error
	IsServerRunning(serverID string) bool
	GetServerStatus(serverID string) string
	GetActiveSessionsForServer(serverID string) int
	GetAllServerStatuses() []config.ServerConfigDTO
	KickPlayer(playerName string, reason string) int // Kick player by name with reason, returns count of kicked sessions
	GetServerLatency(serverID string) (int64, bool)  // Get cached latency for a server, returns (latency_ms, ok)
	ReloadProxyPorts() error
}

// LatencyInfoProvider is an optional interface for getting detailed latency info with MOTD
type LatencyInfoProvider interface {
	GetServerLatencyInfoRaw(serverID string) (latency int64, online bool, motd string, ok bool)
}

// NewAPIServer creates a new API server instance.
func NewAPIServer(
	globalConfig *config.GlobalConfig,
	configMgr *config.ConfigManager,
	sessionMgr *session.SessionManager,
	database *db.Database,
	keyRepo *db.APIKeyRepository,
	playerRepo *db.PlayerRepository,
	sessionRepo *db.SessionRepository,
	mon *monitor.Monitor,
	proxyController ProxyController,
	aclManager *acl.ACLManager,
	proxyOutboundHandler *ProxyOutboundHandler,
	proxyPortConfigMgr *config.ProxyPortConfigManager,
) *APIServer {
	// Set Gin to release mode for production
	gin.SetMode(gin.ReleaseMode)

	// Create Prometheus metrics if monitor is available
	var promMetrics *monitor.PrometheusMetrics
	if mon != nil {
		promMetrics = monitor.NewPrometheusMetrics(mon)
	}

	api := &APIServer{
		router:               gin.New(),
		globalConfig:         globalConfig,
		configMgr:            configMgr,
		sessionMgr:           sessionMgr,
		db:                   database,
		keyRepo:              keyRepo,
		playerRepo:           playerRepo,
		sessionRepo:          sessionRepo,
		monitor:              mon,
		promMetrics:          promMetrics,
		proxyController:      proxyController,
		aclManager:           aclManager,
		proxyOutboundHandler: proxyOutboundHandler,
		proxyPortConfigMgr:   proxyPortConfigMgr,
	}

	api.setupRoutes()
	return api
}

// setupRoutes configures all API routes.
func (a *APIServer) setupRoutes() {
	// Add recovery middleware
	a.router.Use(gin.Recovery())

	// Dynamic dashboard routing - checks config on each request
	a.router.NoRoute(a.dynamicDashboardHandler())

	// Public (no-auth) endpoints for status display
	public := a.router.Group("/api/public")
	{
		public.GET("/status", a.getPublicStatus)
	}

	// API routes group
	api := a.router.Group("/api")
	{
		// Apply authentication middleware
		api.Use(a.authMiddleware())

		// Prometheus metrics endpoint (moved to /api/metrics)
		api.GET("/metrics", a.getMetrics)

		// Server management endpoints
		api.GET("/servers", a.getServers)
		api.POST("/servers", a.createServer)
		api.PUT("/servers/:id", a.updateServer)
		api.DELETE("/servers/:id", a.deleteServer)
		api.POST("/servers/:id/start", a.startServer)
		api.POST("/servers/:id/stop", a.stopServer)
		api.POST("/servers/:id/reload", a.reloadServer)
		api.POST("/servers/:id/disable", a.disableServer)
		api.POST("/servers/:id/enable", a.enableServer)
		api.GET("/servers/:id/latency", a.getServerLatency)

		// Session endpoints
		api.GET("/sessions", a.getSessions)
		api.GET("/sessions/history", a.getSessionHistory)
		api.DELETE("/sessions/history", a.clearSessionHistory)
		api.DELETE("/sessions/history/:id", a.deleteSessionHistory)
		api.DELETE("/sessions/:id", a.kickSession)

		// Log endpoints
		api.GET("/logs", a.getLogFiles)
		api.GET("/logs/:filename", a.getLogContent)
		api.DELETE("/logs", a.clearAllLogs)
		api.DELETE("/logs/:filename", a.deleteLogFile)

		// Player endpoints
		api.GET("/players", a.getPlayers)
		api.GET("/players/:name", a.getPlayer)
		api.POST("/players/:name/kick", a.kickPlayer)
		api.DELETE("/players/:name", a.deletePlayer)

		// API key management endpoints
		api.POST("/keys", a.createAPIKey)
		api.DELETE("/keys/:key", a.deleteAPIKey)

		// System stats endpoints
		api.GET("/stats/system", a.getSystemStats)
		api.GET("/config", a.getConfig)
		api.PUT("/config", a.updateConfig)
		api.PUT("/config/entry-path", a.updateEntryPath)

		// Goroutine management endpoints (for debugging)
		debugGroup := api.Group("/debug")
		{
			debugGroup.Use(a.requireAdminMiddleware())
			debugGroup.GET("/goroutines", a.getGoroutines)
			debugGroup.GET("/goroutines/stats", a.getGoroutineStats)
			debugGroup.GET("/goroutines/pprof", a.getGoroutinePprof)
			debugGroup.Any("/pprof/*action", a.handlePprof)
			debugGroup.POST("/goroutines/cancel/:id", a.cancelGoroutine)
			debugGroup.POST("/goroutines/cancel-all", a.cancelAllGoroutines)
			debugGroup.POST("/goroutines/cancel-component/:component", a.cancelGoroutinesByComponent)
			debugGroup.POST("/gc", a.forceGC)
		}

		// Ping endpoint for checking remote server status
		api.GET("/ping/:address", a.pingServer)
		api.POST("/ping", a.pingServerPost)

		// ACL (Access Control List) endpoints
		// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8
		aclGroup := api.Group("/acl")
		{
			// Blacklist endpoints
			aclGroup.GET("/blacklist", a.getBlacklist)
			aclGroup.POST("/blacklist", a.addToBlacklist)
			aclGroup.DELETE("/blacklist/:name", a.removeFromBlacklist)

			// Whitelist endpoints
			aclGroup.GET("/whitelist", a.getWhitelist)
			aclGroup.POST("/whitelist", a.addToWhitelist)
			aclGroup.DELETE("/whitelist/:name", a.removeFromWhitelist)

			// Settings endpoints
			aclGroup.GET("/settings", a.getACLSettings)
			aclGroup.PUT("/settings", a.updateACLSettings)
		}

		// Proxy outbound endpoints
		// Requirements: 4.3, 5.3
		if a.proxyOutboundHandler != nil {
			proxyOutboundGroup := api.Group("/proxy-outbounds")
			{
				proxyOutboundGroup.GET("", a.proxyOutboundHandler.ListProxyOutbounds)
				proxyOutboundGroup.POST("", a.proxyOutboundHandler.CreateProxyOutbound)
				// New endpoints with name in body (recommended for special characters)
				proxyOutboundGroup.POST("/test", a.proxyOutboundHandler.TestProxyOutboundByBody)
				proxyOutboundGroup.POST("/detailed-test", a.proxyOutboundHandler.DetailedTestProxyOutbound)
				proxyOutboundGroup.POST("/test-mcbe", a.proxyOutboundHandler.TestMCBEUDP)
				proxyOutboundGroup.POST("/health", a.proxyOutboundHandler.GetProxyOutboundHealthByBody)
				proxyOutboundGroup.POST("/get", a.proxyOutboundHandler.GetProxyOutboundByBody)
				proxyOutboundGroup.POST("/update", a.proxyOutboundHandler.UpdateProxyOutboundByBody)
				proxyOutboundGroup.POST("/delete", a.proxyOutboundHandler.DeleteProxyOutboundByBody)
				// Group statistics endpoints (must be before /:name to avoid conflicts)
				// Requirements: 8.1, 8.2, 8.3, 8.4
				proxyOutboundGroup.GET("/groups", a.proxyOutboundHandler.ListGroups)
				proxyOutboundGroup.GET("/groups/:name", a.proxyOutboundHandler.GetGroup)
				// Legacy endpoints with name in URL (kept for compatibility)
				proxyOutboundGroup.GET("/:name", a.proxyOutboundHandler.GetProxyOutbound)
				proxyOutboundGroup.PUT("/:name", a.proxyOutboundHandler.UpdateProxyOutbound)
				proxyOutboundGroup.DELETE("/:name", a.proxyOutboundHandler.DeleteProxyOutbound)
				proxyOutboundGroup.POST("/:name/test", a.proxyOutboundHandler.TestProxyOutbound)
				proxyOutboundGroup.GET("/:name/health", a.proxyOutboundHandler.GetProxyOutboundHealth)
			}
		}

		// Proxy port endpoints
		if a.proxyPortConfigMgr != nil {
			proxyPortGroup := api.Group("/proxy-ports")
			{
				proxyPortGroup.GET("", a.getProxyPorts)
				proxyPortGroup.POST("", a.createProxyPort)
				proxyPortGroup.PUT("/:id", a.updateProxyPort)
				proxyPortGroup.DELETE("/:id", a.deleteProxyPort)
			}
		}
	}
}

// Start starts the API server on the specified address.
func (a *APIServer) Start(addr string) error {
	a.server = &http.Server{
		Addr:    addr,
		Handler: a.router,
	}

	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("API server error: %v\n", err)
		}
	}()

	return nil
}

// Stop gracefully stops the API server.
func (a *APIServer) Stop() error {
	if a.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return a.server.Shutdown(ctx)
}

// APIResponse represents a unified API response format.
type APIResponse struct {
	Success bool        `json:"success"`
	Msg     string      `json:"msg"`
	Data    interface{} `json:"data,omitempty"`
}

// respondError sends an error response with unified format.
func respondError(c *gin.Context, code int, message string, details string) {
	msg := message
	if details != "" {
		msg = message + ": " + details
	}
	c.JSON(code, APIResponse{
		Success: false,
		Msg:     msg,
		Data:    nil,
	})
}

// respondSuccess sends a success response with unified format.
func respondSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Msg:     "操作成功",
		Data:    data,
	})
}

// respondSuccessWithMsg sends a success response with custom message.
func respondSuccessWithMsg(c *gin.Context, msg string, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Msg:     msg,
		Data:    data,
	})
}

// authMiddleware validates API key authentication.
// If no API keys are configured, authentication is skipped.
func (a *APIServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get API key from header
		apiKey := c.GetHeader("X-API-Key")
		isLocal := isLocalRequest(c)
		c.Set(ctxAuthIsLocal, isLocal)

		// Check config.json api_key first
		configKeySet := a.globalConfig != nil && a.globalConfig.APIKey != ""
		if configKeySet {
			if apiKey == a.globalConfig.APIKey {
				c.Set(ctxAuthAnyKeyConfigured, true)
				c.Set(ctxAuthIsAdmin, true)
				c.Next()
				return
			}
		}

		// Check if any API keys exist in database
		dbHasKeys := false
		if a.keyRepo != nil {
			keys, err := a.keyRepo.List()
			if err != nil {
				respondError(c, http.StatusInternalServerError, "检查 API Key 失败", err.Error())
				c.Abort()
				return
			}
			dbHasKeys = len(keys) > 0
		}

		// If no API keys configured (neither in config nor database), skip authentication
		anyKeyConfigured := configKeySet || dbHasKeys
		c.Set(ctxAuthAnyKeyConfigured, anyKeyConfigured)
		if !anyKeyConfigured {
			if !isLocal {
				respondError(c, http.StatusUnauthorized, "未配置 API Key，禁止远程访问", "")
				c.Abort()
				return
			}
			c.Next()
			return
		}

		// API key is required at this point
		if apiKey == "" {
			respondError(c, http.StatusUnauthorized, "需要 API Key", "缺少 X-API-Key 请求头")
			c.Abort()
			return
		}

		// Validate API key from database
		if a.keyRepo == nil {
			respondError(c, http.StatusInternalServerError, "API Key 存储未初始化", "")
			c.Abort()
			return
		}
		key, err := a.keyRepo.GetByKey(apiKey)
		if err != nil {
			if err == sql.ErrNoRows {
				respondError(c, http.StatusUnauthorized, "API Key 无效", "提供的 API Key 不正确")
				c.Abort()
				return
			}
			respondError(c, http.StatusInternalServerError, "验证 API Key 失败", err.Error())
			c.Abort()
			return
		}

		// Log access (Requirements 10.4)
		if err := a.keyRepo.LogAccess(apiKey, c.Request.URL.Path); err != nil {
			// Log error but don't fail the request
			fmt.Printf("Failed to log API access: %v\n", err)
		}

		// Store key info in context for later use
		c.Set("api_key", key)
		c.Set(ctxAuthIsAdmin, key.IsAdmin)
		c.Next()
	}
}

func (a *APIServer) requireAdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isAdminRequest(c) {
			c.Next()
			return
		}
		respondError(c, http.StatusForbidden, "需要管理员权限", "")
		c.Abort()
	}
}

// ValidateAPIKey checks if an API key is valid.
// Returns true if valid, false otherwise.
func (a *APIServer) ValidateAPIKey(apiKey string) bool {
	if apiKey == "" {
		return false
	}

	// Check if any API keys exist
	keys, err := a.keyRepo.List()
	if err != nil {
		return false
	}

	// If no API keys configured, all requests are allowed
	if len(keys) == 0 {
		return true
	}

	// Validate the key
	_, err = a.keyRepo.GetByKey(apiKey)
	return err == nil
}

// Server Management Handlers

// getServers returns the list of all server configurations.
// GET /api/servers
func (a *APIServer) getServers(c *gin.Context) {
	servers := a.proxyController.GetAllServerStatuses()
	respondSuccess(c, servers)
}

// createServer creates a new server configuration.
// POST /api/servers
func (a *APIServer) createServer(c *gin.Context) {
	var serverCfg config.ServerConfig
	if err := c.ShouldBindJSON(&serverCfg); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := a.configMgr.AddServer(&serverCfg); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to create server", err.Error())
		return
	}

	// Return the created server with status
	status := a.proxyController.GetServerStatus(serverCfg.ID)
	activeSessions := a.proxyController.GetActiveSessionsForServer(serverCfg.ID)
	respondSuccess(c, serverCfg.ToDTO(status, activeSessions))
}

// updateServer updates an existing server configuration.
// PUT /api/servers/:id
func (a *APIServer) updateServer(c *gin.Context) {
	serverID := c.Param("id")

	var serverCfg config.ServerConfig
	if err := c.ShouldBindJSON(&serverCfg); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if err := a.configMgr.UpdateServer(serverID, &serverCfg); err != nil {
		respondError(c, http.StatusNotFound, "Failed to update server", err.Error())
		return
	}

	// Reload the server to apply new configuration
	// This will stop and restart the listener with the new config
	if a.proxyController.IsServerRunning(serverID) {
		if err := a.proxyController.ReloadServer(serverCfg.ID); err != nil {
			// Log the error but don't fail the request - config was saved successfully
			fmt.Printf("Warning: failed to reload server %s after config update: %v\n", serverCfg.ID, err)
		}
	}

	// Return the updated server with status
	status := a.proxyController.GetServerStatus(serverCfg.ID)
	activeSessions := a.proxyController.GetActiveSessionsForServer(serverCfg.ID)
	respondSuccess(c, serverCfg.ToDTO(status, activeSessions))
}

// deleteServer removes a server configuration.
// DELETE /api/servers/:id
func (a *APIServer) deleteServer(c *gin.Context) {
	serverID := c.Param("id")

	// Stop the server if running
	if a.proxyController.IsServerRunning(serverID) {
		if err := a.proxyController.StopServer(serverID); err != nil {
			respondError(c, http.StatusInternalServerError, "Failed to stop server before deletion", err.Error())
			return
		}
	}

	if err := a.configMgr.DeleteServer(serverID); err != nil {
		respondError(c, http.StatusNotFound, "Failed to delete server", err.Error())
		return
	}

	respondSuccessWithMsg(c, "服务器删除成功", nil)
}

// startServer starts the proxy for a specific server.
// POST /api/servers/:id/start
func (a *APIServer) startServer(c *gin.Context) {
	serverID := c.Param("id")

	if err := a.proxyController.StartServer(serverID); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to start server", err.Error())
		return
	}

	respondSuccess(c, map[string]string{"status": "running"})
}

// stopServer stops the proxy for a specific server.
// POST /api/servers/:id/stop
func (a *APIServer) stopServer(c *gin.Context) {
	serverID := c.Param("id")

	if err := a.proxyController.StopServer(serverID); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to stop server", err.Error())
		return
	}

	respondSuccess(c, map[string]string{"status": "stopped"})
}

// reloadServer reloads a specific server configuration without affecting others.
// POST /api/servers/:id/reload
func (a *APIServer) reloadServer(c *gin.Context) {
	serverID := c.Param("id")

	if err := a.proxyController.ReloadServer(serverID); err != nil {
		respondError(c, http.StatusBadRequest, "Failed to reload server", err.Error())
		return
	}

	// Get updated status
	status := a.proxyController.GetServerStatus(serverID)
	respondSuccess(c, map[string]string{"status": status})
}

// disableServer disables a server (rejects new connections while keeping listener running).
// POST /api/servers/:id/disable
func (a *APIServer) disableServer(c *gin.Context) {
	serverID := c.Param("id")

	serverCfg, exists := a.configMgr.GetServer(serverID)
	if !exists {
		respondError(c, http.StatusNotFound, "Server not found", "No server found with the specified ID")
		return
	}

	serverCfg.Disabled = true
	if err := a.configMgr.UpdateServer(serverID, serverCfg); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to disable server", err.Error())
		return
	}

	respondSuccess(c, map[string]bool{"disabled": true})
}

// enableServer enables a server (allows new connections).
// POST /api/servers/:id/enable
func (a *APIServer) enableServer(c *gin.Context) {
	serverID := c.Param("id")

	serverCfg, exists := a.configMgr.GetServer(serverID)
	if !exists {
		respondError(c, http.StatusNotFound, "Server not found", "No server found with the specified ID")
		return
	}

	serverCfg.Disabled = false
	if err := a.configMgr.UpdateServer(serverID, serverCfg); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to enable server", err.Error())
		return
	}

	respondSuccess(c, map[string]bool{"disabled": false})
}

// buildServerLatencyInfo builds latency/MOTD info for a server without writing a response.
func (a *APIServer) buildServerLatencyInfo(serverID string) map[string]interface{} {
	// Try to get detailed latency info with MOTD if available
	if provider, ok := a.proxyController.(LatencyInfoProvider); ok {
		latency, online, motd, found := provider.GetServerLatencyInfoRaw(serverID)
		if found {
			response := map[string]interface{}{
				"server_id": serverID,
				"latency":   latency,
				"online":    online,
				"motd":      motd,
				"source":    "proxy",
			}
			// Parse MOTD if available
			if motd != "" {
				response["parsed_motd"] = parseMOTD(motd)
			}
			return response
		}
	}

	// Fallback to simple latency
	latency, ok := a.proxyController.GetServerLatency(serverID)
	if ok {
		online := latency >= 0
		return map[string]interface{}{
			"server_id": serverID,
			"latency":   latency,
			"online":    online,
			"source":    "proxy",
		}
	}

	if a.configMgr != nil {
		if serverCfg, exists := a.configMgr.GetServer(serverID); exists {
			host := serverCfg.GetResolvedIP()
			if host == "" {
				host = serverCfg.Target
			}
			port := serverCfg.Port
			if port <= 0 {
				port = 19132
			}
			if strings.TrimSpace(host) != "" {
				address := net.JoinHostPort(host, strconv.Itoa(port))
				ping := a.doPing(address)
				response := map[string]interface{}{
					"server_id": serverID,
					"latency":   ping.Latency,
					"online":    ping.Online,
					"motd":      ping.MOTD,
					"source":    "direct",
				}
				if ping.ParsedMOTD != nil {
					response["parsed_motd"] = ping.ParsedMOTD
				}
				if ping.Error != "" {
					response["error"] = ping.Error
				}
				return response
			}
		}
	}

	// Return not_found flag to avoid browser console errors
	return map[string]interface{}{
		"server_id": serverID,
		"latency":   -1,
		"online":    false,
		"not_found": true,
	}
}

// getServerLatency returns the cached latency for a server.
// GET /api/servers/:id/latency
func (a *APIServer) getServerLatency(c *gin.Context) {
	serverID := c.Param("id")
	respondSuccess(c, a.buildServerLatencyInfo(serverID))
}

// Session and Player Handlers

// getSessions returns the list of all active sessions.
// GET /api/sessions
func (a *APIServer) getSessions(c *gin.Context) {
	sessions := a.sessionMgr.GetAllSessions()
	dtos := make([]session.SessionDTO, 0, len(sessions))
	for _, sess := range sessions {
		dtos = append(dtos, sess.ToDTO())
	}
	respondSuccess(c, dtos)
}

// getSessionHistory returns historical session records from database.
// GET /api/sessions/history
// Query params: player (optional) - filter by player display name
func (a *APIServer) getSessionHistory(c *gin.Context) {
	if a.sessionRepo == nil {
		respondError(c, http.StatusInternalServerError, "Session repository not initialized", "")
		return
	}

	playerName := c.Query("player")

	var records []*session.SessionRecord
	var err error

	if playerName != "" {
		records, err = a.sessionRepo.GetByPlayerName(playerName)
	} else {
		records, err = a.sessionRepo.List(100, 0)
	}

	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to get session history", err.Error())
		return
	}

	respondSuccess(c, records)
}

// kickSession terminates a session (kicks the player).
// DELETE /api/sessions/:id
func (a *APIServer) kickSession(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		respondError(c, http.StatusBadRequest, "Session ID required", "")
		return
	}

	// Find and remove the session
	removed := a.sessionMgr.RemoveByID(sessionID)
	if !removed {
		respondError(c, http.StatusNotFound, "Session not found", "")
		return
	}

	respondSuccess(c, map[string]string{"message": "Session terminated"})
}

// getPlayers returns the list of all known players.
// GET /api/players
func (a *APIServer) getPlayers(c *gin.Context) {
	// Default pagination
	limit := 100
	offset := 0

	players, err := a.playerRepo.List(limit, offset)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to get players", err.Error())
		return
	}

	dtos := make([]db.PlayerDTO, 0, len(players))
	for _, player := range players {
		dtos = append(dtos, player.ToDTO())
	}
	respondSuccess(c, dtos)
}

// getPlayer returns detailed statistics for a specific player.
// GET /api/players/:name
func (a *APIServer) getPlayer(c *gin.Context) {
	name := c.Param("name")

	player, err := a.playerRepo.GetByDisplayName(name)
	if err != nil {
		if err == sql.ErrNoRows {
			respondError(c, http.StatusNotFound, "Player not found", "No player found with the specified name")
			return
		}
		respondError(c, http.StatusInternalServerError, "Failed to get player", err.Error())
		return
	}

	respondSuccess(c, player.ToDTO())
}

// KickPlayerRequest represents the request body for kicking a player.
type KickPlayerRequest struct {
	Reason string `json:"reason"`
}

// kickPlayer kicks a player by name with an optional reason.
// POST /api/players/:name/kick
func (a *APIServer) kickPlayer(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	var req KickPlayerRequest
	// Bind JSON but don't require it (reason is optional)
	_ = c.ShouldBindJSON(&req)

	kickedCount := 0
	if a.proxyController != nil {
		kickedCount = a.proxyController.KickPlayer(name, req.Reason)
	}

	if kickedCount == 0 {
		respondError(c, http.StatusNotFound, "玩家不在线", "Player is not online")
		return
	}

	respondSuccessWithMsg(c, "玩家已被踢出", map[string]interface{}{
		"player_name":  name,
		"kicked_count": kickedCount,
	})
}

// deletePlayer deletes a player record from the database.
// DELETE /api/players/:name
func (a *APIServer) deletePlayer(c *gin.Context) {
	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	if err := a.playerRepo.DeleteByDisplayName(name); err != nil {
		if err == sql.ErrNoRows {
			respondError(c, http.StatusNotFound, "玩家不存在", "Player not found")
			return
		}
		respondError(c, http.StatusInternalServerError, "删除失败", err.Error())
		return
	}

	respondSuccessWithMsg(c, "玩家记录已删除", nil)
}

// API Key Management Handlers

// CreateAPIKeyRequest represents the request body for creating an API key.
type CreateAPIKeyRequest struct {
	Name    string `json:"name"`
	IsAdmin bool   `json:"is_admin"`
}

// createAPIKey creates a new API key.
// POST /api/keys
func (a *APIServer) createAPIKey(c *gin.Context) {
	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	if !isAdminRequest(c) {
		req.IsAdmin = false
	}

	// Generate a random API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to generate API key", err.Error())
		return
	}
	keyStr := hex.EncodeToString(keyBytes)

	apiKey := &db.APIKey{
		Key:       keyStr,
		Name:      req.Name,
		CreatedAt: time.Now(),
		IsAdmin:   req.IsAdmin,
	}

	if err := a.keyRepo.Create(apiKey); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to create API key", err.Error())
		return
	}

	respondSuccess(c, apiKey)
}

// deleteAPIKey deletes an API key.
// DELETE /api/keys/:key
func (a *APIServer) deleteAPIKey(c *gin.Context) {
	if !isAdminRequest(c) {
		respondError(c, http.StatusForbidden, "需要管理员权限", "")
		return
	}
	key := c.Param("key")

	if err := a.keyRepo.Delete(key); err != nil {
		if err == sql.ErrNoRows {
			respondError(c, http.StatusNotFound, "API key not found", "No API key found with the specified value")
			return
		}
		respondError(c, http.StatusInternalServerError, "Failed to delete API key", err.Error())
		return
	}

	respondSuccessWithMsg(c, "API key 已删除", nil)
}

// GetRouter returns the Gin router for testing purposes.
func (a *APIServer) GetRouter() *gin.Engine {
	return a.router
}

// System Stats Handlers

// getSystemStats returns system statistics including CPU, memory, disk, network, process, and Go runtime info.
// GET /api/stats/system
// Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
func (a *APIServer) getSystemStats(c *gin.Context) {
	if a.monitor == nil {
		respondError(c, http.StatusInternalServerError, "Monitor not initialized", "System monitoring is not available")
		return
	}

	stats, err := a.monitor.GetSystemStats()
	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to get system stats", err.Error())
		return
	}

	respondSuccess(c, stats)
}

// getPublicStatus returns a consolidated status snapshot without authentication.
// GET /api/public/status
func (a *APIServer) getPublicStatus(c *gin.Context) {
	var (
		stats    interface{}
		statsErr error
	)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if a.monitor == nil {
			return
		}
		stats, statsErr = a.monitor.GetSystemStats()
	}()

	servers := a.proxyController.GetAllServerStatuses()

	// Build active sessions snapshot
	sessions := a.sessionMgr.GetAllSessions()
	sessionDTOs := make([]session.SessionDTO, 0, len(sessions))
	activeSessions := make(map[string][]session.SessionDTO)
	for _, sess := range sessions {
		dto := sess.ToDTO()
		sessionDTOs = append(sessionDTOs, dto)
		activeSessions[dto.ServerID] = append(activeSessions[dto.ServerID], dto)
	}

	// Fetch all server pings concurrently and wait for completion
	type pingResult struct {
		id   string
		info map[string]interface{}
	}
	results := make(chan pingResult, len(servers))
	var pingWG sync.WaitGroup
	for _, srv := range servers {
		s := srv
		pingWG.Add(1)
		go func(server config.ServerConfigDTO) {
			defer pingWG.Done()
			info := a.buildServerPingFromConfig(server)
			results <- pingResult{id: server.ID, info: info}
		}(s)
	}
	go func() {
		pingWG.Wait()
		close(results)
	}()

	pings := make(map[string]map[string]interface{}, len(servers))
	for res := range results {
		pings[res.id] = res.info
	}

	wg.Wait()

	response := map[string]interface{}{
		"stats":           stats,
		"servers":         servers,
		"sessions":        sessionDTOs,
		"active_sessions": activeSessions,
		"pings":           pings,
		"generated_at":    time.Now(),
	}
	if statsErr != nil {
		response["stats_error"] = statsErr.Error()
	}

	respondSuccess(c, response)
}

// buildServerPingFromConfig builds ping info based on the provided server config.
// It avoids config lookup races and keeps the result tied to the server entry.
func (a *APIServer) buildServerPingFromConfig(server config.ServerConfigDTO) map[string]interface{} {
	serverID := server.ID
	publicPingTimeout := 5 * time.Second
	if a.globalConfig != nil {
		if a.globalConfig.PublicPingTimeoutSeconds == 0 {
			publicPingTimeout = 0
		} else if a.globalConfig.PublicPingTimeoutSeconds > 0 {
			publicPingTimeout = time.Duration(a.globalConfig.PublicPingTimeoutSeconds) * time.Second
		}
	}

	// If server isn't running, avoid direct ping.
	if server.Status != "running" {
		info := map[string]interface{}{
			"server_id": serverID,
			"online":    false,
			"stopped":   true,
			"source":    "stopped",
		}
		if server.CustomMOTD != "" {
			info["motd"] = server.CustomMOTD
			info["parsed_motd"] = parseMOTD(server.CustomMOTD)
		}
		return info
	}

	// Prefer proxy cached latency/MOTD if available.
	if provider, ok := a.proxyController.(LatencyInfoProvider); ok {
		latency, online, motd, found := provider.GetServerLatencyInfoRaw(serverID)
		if found && (latency >= 0 || motd != "") {
			info := map[string]interface{}{
				"server_id": serverID,
				"latency":   latency,
				"online":    online,
				"motd":      motd,
				"source":    "proxy",
			}
			if motd != "" {
				info["parsed_motd"] = parseMOTD(motd)
			}
			return info
		}
	}

	// Fallback: direct ping using the provided config.
	host := strings.TrimSpace(server.Target)
	if host != "" {
		address := host
		if !strings.Contains(host, ":") {
			port := server.Port
			if port <= 0 {
				port = 19132
			}
			address = net.JoinHostPort(host, strconv.Itoa(port))
		}
		ping := a.doPingWithTimeout(address, publicPingTimeout)
		info := map[string]interface{}{
			"server_id": serverID,
			"latency":   ping.Latency,
			"online":    ping.Online,
			"motd":      ping.MOTD,
			"source":    "direct",
		}
		if ping.ParsedMOTD != nil {
			info["parsed_motd"] = ping.ParsedMOTD
		}
		if ping.Error != "" {
			info["error"] = ping.Error
		}
		return info
	}

	return map[string]interface{}{
		"server_id": serverID,
		"latency":   -1,
		"online":    false,
		"not_found": true,
	}
}

// getConfig returns the global configuration (read-only).
// GET /api/config
func (a *APIServer) getConfig(c *gin.Context) {
	if a.globalConfig == nil {
		respondError(c, http.StatusInternalServerError, "Config not available", "")
		return
	}

	// Return a safe subset of config (no sensitive data)
	configDTO := map[string]interface{}{
		"api_port":                    a.globalConfig.APIPort,
		"api_entry_path":              a.globalConfig.APIEntryPath,
		"database_path":               a.globalConfig.DatabasePath,
		"log_dir":                     a.globalConfig.LogDir,
		"log_retention_days":          a.globalConfig.LogRetentionDays,
		"log_max_size_mb":             a.globalConfig.LogMaxSizeMB,
		"debug_mode":                  a.globalConfig.DebugMode,
		"max_session_records":         a.globalConfig.MaxSessionRecords,
		"max_access_log_records":      a.globalConfig.MaxAccessLogRecords,
		"auth_verify_enabled":         a.globalConfig.AuthVerifyEnabled,
		"auth_verify_url":             a.globalConfig.AuthVerifyURL,
		"auth_cache_minutes":          a.globalConfig.AuthCacheMinutes,
		"proxy_ports_enabled":         a.globalConfig.ProxyPortsEnabled,
		"passthrough_idle_timeout":    a.globalConfig.PassthroughIdleTimeout,
		"public_ping_timeout_seconds": a.globalConfig.PublicPingTimeoutSeconds,
	}
	respondSuccess(c, configDTO)
}

// updateConfig updates the global configuration.
// PUT /api/config
func (a *APIServer) updateConfig(c *gin.Context) {
	if a.globalConfig == nil {
		respondError(c, http.StatusInternalServerError, "Config not available", "")
		return
	}

	var req struct {
		APIPort                  int    `json:"api_port"`
		APIEntryPath             string `json:"api_entry_path"`
		LogDir                   string `json:"log_dir"`
		LogRetentionDays         int    `json:"log_retention_days"`
		LogMaxSizeMB             int    `json:"log_max_size_mb"`
		DebugMode                bool   `json:"debug_mode"`
		MaxSessionRecords        int    `json:"max_session_records"`
		MaxAccessLogRecords      int    `json:"max_access_log_records"`
		AuthVerifyEnabled        bool   `json:"auth_verify_enabled"`
		AuthVerifyURL            string `json:"auth_verify_url"`
		AuthCacheMinutes         int    `json:"auth_cache_minutes"`
		ProxyPortsEnabled        *bool  `json:"proxy_ports_enabled"`
		PassthroughIdleTimeout   *int   `json:"passthrough_idle_timeout"`
		PublicPingTimeoutSeconds *int   `json:"public_ping_timeout_seconds"`
		Restart                  bool   `json:"restart"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Update config in memory
	if req.APIPort > 0 {
		a.globalConfig.APIPort = req.APIPort
	}
	if req.APIEntryPath != "" {
		a.globalConfig.APIEntryPath = req.APIEntryPath
	}
	if req.LogDir != "" {
		a.globalConfig.LogDir = req.LogDir
	}
	if req.LogRetentionDays > 0 {
		a.globalConfig.LogRetentionDays = req.LogRetentionDays
	}
	if req.LogMaxSizeMB > 0 {
		a.globalConfig.LogMaxSizeMB = req.LogMaxSizeMB
	}
	a.globalConfig.DebugMode = req.DebugMode
	if req.MaxSessionRecords > 0 {
		a.globalConfig.MaxSessionRecords = req.MaxSessionRecords
	}
	if req.MaxAccessLogRecords > 0 {
		a.globalConfig.MaxAccessLogRecords = req.MaxAccessLogRecords
	}
	a.globalConfig.AuthVerifyEnabled = req.AuthVerifyEnabled
	if req.AuthVerifyURL != "" {
		a.globalConfig.AuthVerifyURL = req.AuthVerifyURL
	}
	if req.AuthCacheMinutes > 0 {
		a.globalConfig.AuthCacheMinutes = req.AuthCacheMinutes
	}
	if req.ProxyPortsEnabled != nil {
		a.globalConfig.ProxyPortsEnabled = *req.ProxyPortsEnabled
		if a.proxyController != nil {
			if err := a.proxyController.ReloadProxyPorts(); err != nil {
				fmt.Printf("Warning: failed to reload proxy ports after config update: %v\n", err)
			}
		}
	}
	if req.PassthroughIdleTimeout != nil {
		if *req.PassthroughIdleTimeout < 0 {
			respondError(c, http.StatusBadRequest, "Invalid passthrough_idle_timeout", "passthrough_idle_timeout cannot be negative")
			return
		}
		a.globalConfig.PassthroughIdleTimeout = *req.PassthroughIdleTimeout
	}
	if req.PublicPingTimeoutSeconds != nil {
		if *req.PublicPingTimeoutSeconds < 0 {
			respondError(c, http.StatusBadRequest, "Invalid public_ping_timeout_seconds", "public_ping_timeout_seconds cannot be negative")
			return
		}
		a.globalConfig.PublicPingTimeoutSeconds = *req.PublicPingTimeoutSeconds
	}

	// Note: Actual restart would require additional implementation
	// For now, just acknowledge the config update
	respondSuccessWithMsg(c, "配置已更新", nil)
}

// updateEntryPath updates the API entry path dynamically.
// PUT /api/config/entry-path
func (a *APIServer) updateEntryPath(c *gin.Context) {
	if a.globalConfig == nil {
		respondError(c, http.StatusInternalServerError, "Config not available", "")
		return
	}

	var req struct {
		EntryPath string `json:"entry_path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate entry path
	if req.EntryPath == "" {
		respondError(c, http.StatusBadRequest, "Entry path cannot be empty", "")
		return
	}
	if !strings.HasPrefix(req.EntryPath, "/") {
		req.EntryPath = "/" + req.EntryPath
	}

	// Update in memory
	a.globalConfig.APIEntryPath = req.EntryPath

	respondSuccessWithMsg(c, "入口路径已更新为: "+req.EntryPath, map[string]string{
		"entry_path": req.EntryPath,
	})
}

// getMetrics returns Prometheus metrics.
// GET /metrics
// Requirements: 6.7
func (a *APIServer) getMetrics(c *gin.Context) {
	// Update metrics before serving
	if a.promMetrics != nil {
		a.promMetrics.Update()
		// Use the custom registry handler
		promhttp.HandlerFor(a.promMetrics.Registry, promhttp.HandlerOpts{}).ServeHTTP(c.Writer, c.Request)
	} else {
		// Fallback to default handler if no metrics configured
		promhttp.Handler().ServeHTTP(c.Writer, c.Request)
	}
}

// GetPrometheusMetrics returns the Prometheus metrics instance for external updates.
func (a *APIServer) GetPrometheusMetrics() *monitor.PrometheusMetrics {
	return a.promMetrics
}

// ACL (Access Control List) Handlers
// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8

// getBlacklist returns the list of all blacklisted players.
// GET /api/acl/blacklist
// Query params: server_id (optional) - filter by server ID
// Requirements: 3.1
func (a *APIServer) getBlacklist(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	serverID := c.Query("server_id")

	var entries []*db.BlacklistEntry
	var err error

	if serverID != "" {
		entries, err = a.aclManager.GetBlacklist(serverID)
	} else {
		entries, err = a.aclManager.GetAllBlacklist()
	}

	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to get blacklist", err.Error())
		return
	}

	dtos := make([]db.BlacklistEntryDTO, 0, len(entries))
	for _, entry := range entries {
		dtos = append(dtos, entry.ToDTO())
	}
	respondSuccess(c, dtos)
}

// addToBlacklist adds a player to the blacklist.
// POST /api/acl/blacklist
// Requirements: 3.2
func (a *APIServer) addToBlacklist(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	var req db.AddBlacklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	playerName := req.GetPlayerName()
	if playerName == "" {
		respondError(c, http.StatusBadRequest, "Invalid request body", "player_name is required")
		return
	}

	entry := &db.BlacklistEntry{
		DisplayName: playerName,
		Reason:      req.Reason,
		ServerID:    req.ServerID,
		AddedAt:     time.Now(),
		ExpiresAt:   req.ExpiresAt,
		AddedBy:     "", // Could be set from API key context if needed
	}

	if err := a.aclManager.AddToBlacklist(entry); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to add to blacklist", err.Error())
		return
	}

	// Kick the player if they are currently online
	kickedCount := 0
	if a.proxyController != nil {
		kickedCount = a.proxyController.KickPlayer(playerName, "已被封禁")
	}

	respondSuccess(c, map[string]interface{}{
		"entry":        entry.ToDTO(),
		"kicked_count": kickedCount,
	})
}

// removeFromBlacklist removes a player from the blacklist.
// DELETE /api/acl/blacklist/:name
// Query params: server_id (optional) - specify server ID for server-specific entry
// Requirements: 3.3
func (a *APIServer) removeFromBlacklist(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	serverID := c.Query("server_id")

	if err := a.aclManager.RemoveFromBlacklist(name, serverID); err != nil {
		if err == sql.ErrNoRows {
			respondError(c, http.StatusNotFound, "Entry not found", "No blacklist entry found with the specified name")
			return
		}
		respondError(c, http.StatusInternalServerError, "Failed to remove from blacklist", err.Error())
		return
	}

	respondSuccessWithMsg(c, "已从黑名单移除", nil)
}

// getWhitelist returns the list of all whitelisted players.
// GET /api/acl/whitelist
// Query params: server_id (optional) - filter by server ID
// Requirements: 3.4
func (a *APIServer) getWhitelist(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	serverID := c.Query("server_id")

	var entries []*db.WhitelistEntry
	var err error

	if serverID != "" {
		entries, err = a.aclManager.GetWhitelist(serverID)
	} else {
		entries, err = a.aclManager.GetAllWhitelist()
	}

	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to get whitelist", err.Error())
		return
	}

	dtos := make([]db.WhitelistEntryDTO, 0, len(entries))
	for _, entry := range entries {
		dtos = append(dtos, entry.ToDTO())
	}
	respondSuccess(c, dtos)
}

// addToWhitelist adds a player to the whitelist.
// POST /api/acl/whitelist
// Requirements: 3.5
func (a *APIServer) addToWhitelist(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	var req db.AddWhitelistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	playerName := req.GetPlayerName()
	if playerName == "" {
		respondError(c, http.StatusBadRequest, "Invalid request body", "player_name is required")
		return
	}

	entry := &db.WhitelistEntry{
		DisplayName: playerName,
		ServerID:    req.ServerID,
		AddedAt:     time.Now(),
		AddedBy:     "", // Could be set from API key context if needed
	}

	if err := a.aclManager.AddToWhitelist(entry); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to add to whitelist", err.Error())
		return
	}

	respondSuccess(c, entry.ToDTO())
}

// removeFromWhitelist removes a player from the whitelist.
// DELETE /api/acl/whitelist/:name
// Query params: server_id (optional) - specify server ID for server-specific entry
// Requirements: 3.6
func (a *APIServer) removeFromWhitelist(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	name := c.Param("name")
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}

	serverID := c.Query("server_id")

	if err := a.aclManager.RemoveFromWhitelist(name, serverID); err != nil {
		if err == sql.ErrNoRows {
			respondError(c, http.StatusNotFound, "Entry not found", "No whitelist entry found with the specified name")
			return
		}
		respondError(c, http.StatusInternalServerError, "Failed to remove from whitelist", err.Error())
		return
	}

	respondSuccessWithMsg(c, "已从白名单移除", nil)
}

// getACLSettings returns the current ACL settings.
// GET /api/acl/settings
// Query params: server_id (optional) - get settings for specific server
// Requirements: 3.7
func (a *APIServer) getACLSettings(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	serverID := c.Query("server_id")

	settings, err := a.aclManager.GetSettings(serverID)
	if err != nil {
		// Return default settings if not found
		settings = db.DefaultACLSettings()
		settings.ServerID = serverID
	}

	respondSuccess(c, settings.ToDTO())
}

// updateACLSettings updates the ACL settings.
// PUT /api/acl/settings
// Requirements: 3.8
func (a *APIServer) updateACLSettings(c *gin.Context) {
	if a.aclManager == nil {
		respondError(c, http.StatusInternalServerError, "ACL manager not initialized", "")
		return
	}

	var settingsDTO db.ACLSettingsDTO
	if err := c.ShouldBindJSON(&settingsDTO); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	settings := &db.ACLSettings{
		ServerID:         settingsDTO.ServerID,
		WhitelistEnabled: settingsDTO.WhitelistEnabled,
		DefaultMessage:   settingsDTO.DefaultMessage,
		WhitelistMessage: settingsDTO.WhitelistMessage,
	}

	if err := a.aclManager.UpdateSettings(settings); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to update ACL settings", err.Error())
		return
	}

	respondSuccess(c, settings.ToDTO())
}

// GetACLManager returns the ACL manager for external use.
func (a *APIServer) GetACLManager() *acl.ACLManager {
	return a.aclManager
}

// Log Handlers

// getLogFiles returns the list of available log files.
// GET /api/logs
func (a *APIServer) getLogFiles(c *gin.Context) {
	logDir := "logs"
	if a.globalConfig != nil && a.globalConfig.LogDir != "" {
		logDir = a.globalConfig.LogDir
	}

	files, err := os.ReadDir(logDir)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to read log directory", err.Error())
		return
	}

	var logFiles []string
	for _, f := range files {
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".log") || strings.HasSuffix(f.Name(), ".txt")) {
			logFiles = append(logFiles, f.Name())
		}
	}

	// Sort by name descending (newest first)
	sort.Sort(sort.Reverse(sort.StringSlice(logFiles)))
	respondSuccess(c, logFiles)
}

// getLogContent returns the content of a specific log file.
// GET /api/logs/:filename
func (a *APIServer) getLogContent(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		respondError(c, http.StatusBadRequest, "Filename is required", "")
		return
	}

	// Prevent directory traversal
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		respondError(c, http.StatusBadRequest, "Invalid filename", "")
		return
	}

	logDir := "logs"
	if a.globalConfig != nil && a.globalConfig.LogDir != "" {
		logDir = a.globalConfig.LogDir
	}

	filepath := logDir + "/" + filename

	// Get lines parameter
	const maxLines = 2000
	lines := 500
	if linesStr := c.Query("lines"); linesStr != "" {
		if l, err := strconv.Atoi(linesStr); err == nil && l > 0 {
			if l > maxLines {
				lines = maxLines
			} else {
				lines = l
			}
		}
	}

	content, err := readLastLines(filepath, lines)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to read log file", err.Error())
		return
	}

	respondSuccess(c, content)
}

// readLastLines reads the last n lines from a file
func readLastLines(filepath string, n int) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return "", err
	}

	// For small files, read everything
	if stat.Size() < 1024*1024 { // Less than 1MB
		content, err := os.ReadFile(filepath)
		if err != nil {
			return "", err
		}
		lines := strings.Split(string(content), "\n")
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		return strings.Join(lines, "\n"), nil
	}

	// For large files, read from end
	bufSize := int64(n * 200) // Estimate 200 bytes per line
	if bufSize > stat.Size() {
		bufSize = stat.Size()
	}

	buf := make([]byte, bufSize)
	_, err = file.ReadAt(buf, stat.Size()-bufSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	lines := strings.Split(string(buf), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}

// Session History Handlers

// clearSessionHistory clears all session history records.
// DELETE /api/sessions/history
func (a *APIServer) clearSessionHistory(c *gin.Context) {
	if a.sessionRepo == nil {
		respondError(c, http.StatusInternalServerError, "Session repository not initialized", "")
		return
	}

	if err := a.sessionRepo.ClearHistory(); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to clear session history", err.Error())
		return
	}

	respondSuccess(c, gin.H{"message": "Session history cleared"})
}

// deleteSessionHistory deletes a specific session history record.
// DELETE /api/sessions/history/:id
func (a *APIServer) deleteSessionHistory(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		respondError(c, http.StatusBadRequest, "Session ID is required", "")
		return
	}

	if a.sessionRepo == nil {
		respondError(c, http.StatusInternalServerError, "Session repository not initialized", "")
		return
	}

	if err := a.sessionRepo.DeleteHistory(id); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to delete session", err.Error())
		return
	}

	respondSuccess(c, gin.H{"message": "Session deleted"})
}

// deleteLogFile deletes a specific log file.
// DELETE /api/logs/:filename
func (a *APIServer) deleteLogFile(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		respondError(c, http.StatusBadRequest, "Filename is required", "")
		return
	}

	// Prevent directory traversal
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		respondError(c, http.StatusBadRequest, "Invalid filename", "")
		return
	}

	logDir := "logs"
	if a.globalConfig != nil && a.globalConfig.LogDir != "" {
		logDir = a.globalConfig.LogDir
	}

	filepath := logDir + "/" + filename
	if err := os.Remove(filepath); err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to delete log file", err.Error())
		return
	}

	respondSuccess(c, gin.H{"message": "Log file deleted"})
}

// clearAllLogs deletes all log files.
// DELETE /api/logs
func (a *APIServer) clearAllLogs(c *gin.Context) {
	logDir := "logs"
	if a.globalConfig != nil && a.globalConfig.LogDir != "" {
		logDir = a.globalConfig.LogDir
	}

	files, err := os.ReadDir(logDir)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "Failed to read log directory", err.Error())
		return
	}

	deleted := 0
	for _, f := range files {
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".log") || strings.HasSuffix(f.Name(), ".txt")) {
			if err := os.Remove(logDir + "/" + f.Name()); err == nil {
				deleted++
			}
		}
	}

	respondSuccess(c, gin.H{"message": fmt.Sprintf("Deleted %d log files", deleted)})
}

// PingResponse represents the response from a ping request.
type PingResponse struct {
	Address    string      `json:"address"`
	Latency    int64       `json:"latency"`               // Latency in milliseconds
	Online     bool        `json:"online"`                // Whether the server is online
	MOTD       string      `json:"motd"`                  // Raw MOTD string
	ParsedMOTD *ParsedMOTD `json:"parsed_motd,omitempty"` // Parsed MOTD fields
	Error      string      `json:"error,omitempty"`
}

// ParsedMOTD represents parsed MCPE MOTD fields.
type ParsedMOTD struct {
	Edition         string `json:"edition"`          // MCPE or MCEE
	ServerName      string `json:"server_name"`      // Server name/description
	ProtocolVersion string `json:"protocol_version"` // Protocol version number
	GameVersion     string `json:"game_version"`     // Game version string
	PlayerCount     string `json:"player_count"`     // Current player count
	MaxPlayers      string `json:"max_players"`      // Maximum players
	ServerUID       string `json:"server_uid"`       // Server unique ID
	WorldName       string `json:"world_name"`       // World/level name
	GameMode        string `json:"game_mode"`        // Game mode (Survival, Creative, etc.)
	Port            string `json:"port"`             // IPv4 port
	PortV6          string `json:"port_v6"`          // IPv6 port
}

// parseMOTD parses an MCPE MOTD string into structured fields.
func parseMOTD(motd string) *ParsedMOTD {
	parts := strings.Split(motd, ";")
	if len(parts) < 6 {
		return nil
	}

	parsed := &ParsedMOTD{
		Edition: parts[0],
	}

	if len(parts) > 1 {
		parsed.ServerName = parts[1]
	}
	if len(parts) > 2 {
		parsed.ProtocolVersion = parts[2]
	}
	if len(parts) > 3 {
		parsed.GameVersion = parts[3]
	}
	if len(parts) > 4 {
		parsed.PlayerCount = parts[4]
	}
	if len(parts) > 5 {
		parsed.MaxPlayers = parts[5]
	}
	if len(parts) > 6 {
		parsed.ServerUID = parts[6]
	}
	if len(parts) > 7 {
		parsed.WorldName = parts[7]
	}
	if len(parts) > 8 {
		parsed.GameMode = parts[8]
	}
	if len(parts) > 10 {
		parsed.Port = parts[10]
	}
	if len(parts) > 11 {
		parsed.PortV6 = parts[11]
	}

	return parsed
}

// pingServer pings a Minecraft Bedrock server and returns status info.
// GET /api/ping/:address
// The address should be in format "host:port" or just "host" (default port 19132)
func (a *APIServer) pingServer(c *gin.Context) {
	address := ensurePingAddress(c.Param("address"))
	if address == "" {
		respondError(c, http.StatusBadRequest, "Address is required", "")
		return
	}
	resolvedAddress, err := resolvePingAddressForRequest(address, allowPrivateTargets(c))
	if err != nil {
		respondError(c, http.StatusBadRequest, "目标地址不可用", err.Error())
		return
	}

	response := a.doPing(resolvedAddress)
	respondSuccess(c, response)
}

// PingRequest represents the request body for POST ping.
type PingRequest struct {
	Address string `json:"address" binding:"required"`
}

// pingServerPost pings a Minecraft Bedrock server using POST request.
// POST /api/ping
// Body: {"address": "host:port"}
func (a *APIServer) pingServerPost(c *gin.Context) {
	var req PingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	address := ensurePingAddress(req.Address)
	if address == "" {
		respondError(c, http.StatusBadRequest, "Address is required", "")
		return
	}
	resolvedAddress, err := resolvePingAddressForRequest(address, allowPrivateTargets(c))
	if err != nil {
		respondError(c, http.StatusBadRequest, "目标地址不可用", err.Error())
		return
	}

	response := a.doPing(resolvedAddress)
	respondSuccess(c, response)
}

func ensurePingAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}

	if host, port, err := net.SplitHostPort(address); err == nil {
		if port == "" {
			port = "19132"
		}
		return net.JoinHostPort(host, port)
	}

	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
	}

	return net.JoinHostPort(address, "19132")
}

// doPing performs the actual ping operation.
func (a *APIServer) doPing(address string) *PingResponse {
	response := &PingResponse{
		Address: address,
		Online:  false,
	}

	start := time.Now()
	pong, err := raknet.Ping(address)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		response.Error = err.Error()
		response.Latency = -1
		return response
	}

	response.Online = true
	response.Latency = latency
	response.MOTD = string(pong)
	response.ParsedMOTD = parseMOTD(string(pong))

	return response
}

// doPingWithTimeout performs ping with an upper time limit to avoid blocking long.
func (a *APIServer) doPingWithTimeout(address string, timeout time.Duration) *PingResponse {
	if timeout <= 0 {
		return a.doPing(address)
	}
	resultCh := make(chan *PingResponse, 1)
	go func() {
		resultCh <- a.doPing(address)
	}()
	select {
	case res := <-resultCh:
		return res
	case <-time.After(timeout):
		return &PingResponse{
			Address: address,
			Online:  false,
			Latency: -1,
			Error:   "timeout",
		}
	}
}

// Goroutine Management Handlers

// getGoroutines returns all tracked goroutines.
// GET /api/debug/goroutines
func (a *APIServer) getGoroutines(c *gin.Context) {
	gm := monitor.GetGoroutineManager()
	goroutines := gm.GetTrackedGoroutines()
	respondSuccess(c, map[string]interface{}{
		"total_runtime": runtime.NumGoroutine(),
		"tracked":       len(goroutines),
		"goroutines":    goroutines,
	})
}

// getGoroutineStats returns comprehensive goroutine statistics.
// GET /api/debug/goroutines/stats
// Query params: stacks=true to include runtime stacks
func (a *APIServer) getGoroutineStats(c *gin.Context) {
	includeStacks := c.Query("stacks") == "true"
	gm := monitor.GetGoroutineManager()
	stats := gm.GetStats(includeStacks)

	// Build response with process info
	response := map[string]interface{}{
		"total_count":     stats.TotalCount,
		"tracked_count":   stats.TrackedCount,
		"by_component":    stats.ByComponent,
		"by_state":        stats.ByState,
		"long_running":    stats.LongRunning,
		"potential_leaks": stats.PotentialLeaks,
		"runtime_stacks":  stats.RuntimeStacks,
	}

	// Add process CPU/memory info if monitor is available
	if a.monitor != nil {
		if procInfo, err := a.monitor.GetProcessInfo(); err == nil {
			response["process_cpu_percent"] = procInfo.CPUPercent
			response["process_memory_bytes"] = procInfo.MemoryBytes
		}
	}

	// Add runtime memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	response["memory"] = map[string]interface{}{
		"alloc":           memStats.Alloc,         // 当前分配的内存
		"total_alloc":     memStats.TotalAlloc,    // 累计分配的内存
		"sys":             memStats.Sys,           // 从系统获取的内存
		"heap_alloc":      memStats.HeapAlloc,     // 堆分配的内存
		"heap_sys":        memStats.HeapSys,       // 堆从系统获取的内存
		"heap_idle":       memStats.HeapIdle,      // 堆空闲内存
		"heap_inuse":      memStats.HeapInuse,     // 堆使用中的内存
		"heap_released":   memStats.HeapReleased,  // 释放给系统的内存
		"heap_objects":    memStats.HeapObjects,   // 堆对象数量
		"stack_inuse":     memStats.StackInuse,    // 栈使用中的内存
		"stack_sys":       memStats.StackSys,      // 栈从系统获取的内存
		"gc_cpu_fraction": memStats.GCCPUFraction, // GC CPU 占用比例
		"num_gc":          memStats.NumGC,         // GC 次数
		"last_gc":         memStats.LastGC,        // 上次 GC 时间 (纳秒)
		"pause_total_ns":  memStats.PauseTotalNs,  // GC 暂停总时间
		"num_forced_gc":   memStats.NumForcedGC,   // 强制 GC 次数
	}

	// Add server stats if proxy controller is available
	if a.proxyController != nil {
		serverStats := a.proxyController.GetAllServerStatuses()
		response["servers"] = serverStats
	}

	// Add session stats if session manager is available
	if a.sessionMgr != nil {
		sessions := a.sessionMgr.GetAllSessions()
		activeSessions := 0
		totalBytesUp := int64(0)
		totalBytesDown := int64(0)
		for _, sess := range sessions {
			activeSessions++
			snap := sess.Snapshot()
			totalBytesUp += snap.BytesUp
			totalBytesDown += snap.BytesDown
		}
		response["sessions"] = map[string]interface{}{
			"active":           activeSessions,
			"total_bytes_up":   totalBytesUp,
			"total_bytes_down": totalBytesDown,
		}
	}

	// Add outbound stats if proxy outbound handler is available
	if a.proxyOutboundHandler != nil && a.proxyOutboundHandler.outboundMgr != nil {
		outbounds := a.proxyOutboundHandler.outboundMgr.ListOutbounds()
		healthyCount := 0
		unhealthyCount := 0
		udpAvailable := 0
		for _, ob := range outbounds {
			if ob.Enabled {
				if ob.GetHealthy() {
					healthyCount++
				} else {
					unhealthyCount++
				}
				if ob.UDPAvailable != nil && *ob.UDPAvailable {
					udpAvailable++
				}
			}
		}
		response["outbounds"] = map[string]interface{}{
			"total":         len(outbounds),
			"healthy":       healthyCount,
			"unhealthy":     unhealthyCount,
			"udp_available": udpAvailable,
		}
	}

	respondSuccess(c, response)
}

// getGoroutinePprof returns pprof goroutine profile data.
// GET /api/debug/goroutines/pprof
func (a *APIServer) getGoroutinePprof(c *gin.Context) {
	gm := monitor.GetGoroutineManager()
	pprofData := gm.GetPprofGoroutines()
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, pprofData)
}

// handlePprof exposes net/http/pprof under authenticated routes.
// GET|POST /api/debug/pprof/*action
func (a *APIServer) handlePprof(c *gin.Context) {
	action := strings.TrimPrefix(c.Param("action"), "/")

	// Special handling for profile with debug=1 to return text format
	if action == "profile" && c.Query("debug") == "1" {
		a.handleCPUProfileText(c)
		return
	}

	switch action {
	case "", "/":
		pprof.Index(c.Writer, c.Request)
	case "cmdline":
		pprof.Cmdline(c.Writer, c.Request)
	case "profile":
		pprof.Profile(c.Writer, c.Request)
	case "symbol":
		pprof.Symbol(c.Writer, c.Request)
	case "trace":
		pprof.Trace(c.Writer, c.Request)
	default:
		pprof.Handler(action).ServeHTTP(c.Writer, c.Request)
	}
}

// handleCPUProfileText captures CPU profile and returns a text summary
func (a *APIServer) handleCPUProfileText(c *gin.Context) {
	seconds := 5
	if s := c.Query("seconds"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= 120 {
			seconds = v
		}
	}

	// Capture CPU profile to buffer
	var buf bytes.Buffer
	if err := runtimePprof.StartCPUProfile(&buf); err != nil {
		c.String(http.StatusInternalServerError, "Failed to start CPU profile: %v", err)
		return
	}

	time.Sleep(time.Duration(seconds) * time.Second)
	runtimePprof.StopCPUProfile()

	// Parse the profile and generate text output
	profile, err := profile.Parse(&buf)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to parse CPU profile: %v", err)
		return
	}

	// Generate text report
	var result strings.Builder
	result.WriteString(fmt.Sprintf("CPU Profile (%d seconds)\n", seconds))
	result.WriteString(fmt.Sprintf("Duration: %v\n", profile.DurationNanos/1e9))
	result.WriteString(fmt.Sprintf("Samples: %d\n", len(profile.Sample)))
	result.WriteString("=" + strings.Repeat("=", 79) + "\n\n")

	// Calculate total samples
	var totalSamples int64
	for _, sample := range profile.Sample {
		if len(sample.Value) > 0 {
			totalSamples += sample.Value[0]
		}
	}

	// Aggregate by function
	funcSamples := make(map[string]int64)
	for _, sample := range profile.Sample {
		if len(sample.Location) > 0 && len(sample.Value) > 0 {
			loc := sample.Location[0]
			if len(loc.Line) > 0 && loc.Line[0].Function != nil {
				funcName := loc.Line[0].Function.Name
				funcSamples[funcName] += sample.Value[0]
			}
		}
	}

	// Sort by samples
	type funcStat struct {
		name    string
		samples int64
	}
	var stats []funcStat
	for name, samples := range funcSamples {
		stats = append(stats, funcStat{name, samples})
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].samples > stats[j].samples
	})

	// Output top functions
	result.WriteString("Top Functions by CPU Time:\n")
	result.WriteString(fmt.Sprintf("%-60s %10s %8s\n", "Function", "Samples", "Percent"))
	result.WriteString(strings.Repeat("-", 80) + "\n")

	maxShow := 50
	if len(stats) < maxShow {
		maxShow = len(stats)
	}
	for i := 0; i < maxShow; i++ {
		stat := stats[i]
		percent := float64(stat.samples) / float64(totalSamples) * 100
		funcName := stat.name
		if len(funcName) > 58 {
			funcName = "..." + funcName[len(funcName)-55:]
		}
		result.WriteString(fmt.Sprintf("%-60s %10d %7.2f%%\n", funcName, stat.samples, percent))
	}

	if len(stats) > maxShow {
		result.WriteString(fmt.Sprintf("\n... and %d more functions\n", len(stats)-maxShow))
	}

	result.WriteString(fmt.Sprintf("\nTotal Samples: %d\n", totalSamples))

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, result.String())
}

// cancelGoroutine attempts to cancel a specific tracked goroutine.
// POST /api/debug/goroutines/cancel/:id
func (a *APIServer) cancelGoroutine(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Invalid goroutine ID", err.Error())
		return
	}

	gm := monitor.GetGoroutineManager()
	if gm.Cancel(id) {
		respondSuccessWithMsg(c, "协程已取消", map[string]int64{"id": id})
	} else {
		respondError(c, http.StatusNotFound, "协程未找到或无法取消", "")
	}
}

// cancelAllGoroutines attempts to cancel all tracked goroutines.
// POST /api/debug/goroutines/cancel-all
func (a *APIServer) cancelAllGoroutines(c *gin.Context) {
	gm := monitor.GetGoroutineManager()
	cancelled := gm.CancelAll()
	respondSuccessWithMsg(c, fmt.Sprintf("已取消 %d 个协程", cancelled), map[string]int{"cancelled": cancelled})
}

// cancelGoroutinesByComponent cancels all goroutines of a specific component.
// POST /api/debug/goroutines/cancel-component/:component
func (a *APIServer) cancelGoroutinesByComponent(c *gin.Context) {
	component := c.Param("component")
	if component == "" {
		respondError(c, http.StatusBadRequest, "Component name is required", "")
		return
	}

	gm := monitor.GetGoroutineManager()
	cancelled := gm.CancelByComponent(component)
	respondSuccessWithMsg(c, fmt.Sprintf("已取消 %s 组件的 %d 个协程", component, cancelled), map[string]interface{}{
		"component": component,
		"cancelled": cancelled,
	})
}

// forceGC forces a garbage collection.
// POST /api/debug/gc
func (a *APIServer) forceGC(c *gin.Context) {
	before := runtime.NumGoroutine()
	runtime.GC()
	after := runtime.NumGoroutine()
	respondSuccessWithMsg(c, "GC completed", map[string]interface{}{
		"goroutines_before": before,
		"goroutines_after":  after,
	})
}
