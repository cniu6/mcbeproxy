// Package api provides REST API functionality using Gin framework.
package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

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
) *APIServer {
	// Set Gin to release mode for production
	gin.SetMode(gin.ReleaseMode)

	// Create Prometheus metrics if monitor is available
	var promMetrics *monitor.PrometheusMetrics
	if mon != nil {
		promMetrics = monitor.NewPrometheusMetrics(mon)
	}

	api := &APIServer{
		router:          gin.New(),
		globalConfig:    globalConfig,
		configMgr:       configMgr,
		sessionMgr:      sessionMgr,
		db:              database,
		keyRepo:         keyRepo,
		playerRepo:      playerRepo,
		sessionRepo:     sessionRepo,
		monitor:         mon,
		promMetrics:     promMetrics,
		proxyController: proxyController,
		aclManager:      aclManager,
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

		// API key management endpoints
		api.POST("/keys", a.createAPIKey)
		api.DELETE("/keys/:key", a.deleteAPIKey)

		// System stats endpoints
		api.GET("/stats/system", a.getSystemStats)
		api.GET("/config", a.getConfig)
		api.PUT("/config/entry-path", a.updateEntryPath)

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

		// Check config.json api_key first
		if a.globalConfig != nil && a.globalConfig.APIKey != "" {
			if apiKey == a.globalConfig.APIKey {
				c.Next()
				return
			}
		}

		// Check if any API keys exist in database
		keys, err := a.keyRepo.List()
		if err != nil {
			respondError(c, http.StatusInternalServerError, "Failed to check API keys", err.Error())
			c.Abort()
			return
		}

		// If no API keys configured (neither in config nor database), skip authentication
		configKeySet := a.globalConfig != nil && a.globalConfig.APIKey != ""
		if len(keys) == 0 && !configKeySet {
			c.Next()
			return
		}

		// API key is required at this point
		if apiKey == "" {
			respondError(c, http.StatusUnauthorized, "API key required", "X-API-Key header is missing")
			c.Abort()
			return
		}

		// Validate API key from database
		key, err := a.keyRepo.GetByKey(apiKey)
		if err != nil {
			if err == sql.ErrNoRows {
				respondError(c, http.StatusUnauthorized, "Invalid API key", "The provided API key is not valid")
				c.Abort()
				return
			}
			respondError(c, http.StatusInternalServerError, "Failed to validate API key", err.Error())
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
		c.Next()
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

// getConfig returns the global configuration (read-only).
// GET /api/config
func (a *APIServer) getConfig(c *gin.Context) {
	if a.globalConfig == nil {
		respondError(c, http.StatusInternalServerError, "Config not available", "")
		return
	}

	// Return a safe subset of config (no sensitive data)
	configDTO := map[string]interface{}{
		"api_port":            a.globalConfig.APIPort,
		"api_entry_path":      a.globalConfig.APIEntryPath,
		"database_path":       a.globalConfig.DatabasePath,
		"log_dir":             a.globalConfig.LogDir,
		"log_retention_days":  a.globalConfig.LogRetentionDays,
		"auth_verify_enabled": a.globalConfig.AuthVerifyEnabled,
		"auth_verify_url":     a.globalConfig.AuthVerifyURL,
		"auth_cache_minutes":  a.globalConfig.AuthCacheMinutes,
	}
	respondSuccess(c, configDTO)
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
	lines := 500
	if linesStr := c.Query("lines"); linesStr != "" {
		if l, err := strconv.Atoi(linesStr); err == nil && l > 0 {
			lines = l
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
	if err != nil && err.Error() != "EOF" {
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
