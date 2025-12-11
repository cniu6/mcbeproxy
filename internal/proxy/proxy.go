// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/auth"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	proxyerrors "mcpeserverproxy/internal/errors"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/protocol"
	"mcpeserverproxy/internal/session"
)

// Listener is an interface for proxy listeners (both transparent and RakNet).
type Listener interface {
	Start() error
	Listen(ctx context.Context) error
	Stop() error
}

// ProxyServer is the main entry point that integrates all proxy components.
// It manages UDP listeners, session management, configuration, and database persistence.
type ProxyServer struct {
	config           *config.GlobalConfig
	configMgr        *config.ConfigManager
	sessionMgr       *session.SessionManager
	db               *db.Database
	sessionRepo      *db.SessionRepository
	playerRepo       *db.PlayerRepository
	bufferPool       *BufferPool
	forwarder        *Forwarder
	errorHandler     *proxyerrors.ErrorHandler
	aclManager       *acl.ACLManager        // ACL manager for access control
	externalVerifier *auth.ExternalVerifier // External auth verifier
	listeners        map[string]Listener    // serverID -> listener (can be UDPListener or RakNetProxy)
	listenersMu      sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	running          bool
	runningMu        sync.RWMutex
}

// NewProxyServer creates a new ProxyServer with all components initialized.
func NewProxyServer(
	globalConfig *config.GlobalConfig,
	configMgr *config.ConfigManager,
	database *db.Database,
) (*ProxyServer, error) {
	// Create buffer pool for efficient memory usage
	bufferPool := NewBufferPool(DefaultBufferSize)

	// Create protocol handler
	protocolHandler := protocol.NewProtocolHandler()

	// Create forwarder
	forwarder := NewForwarder(protocolHandler, bufferPool)

	// Create session manager with default idle timeout (5 minutes)
	sessionMgr := session.NewSessionManager(5 * time.Minute)

	// Create repositories
	sessionRepo := db.NewSessionRepository(database, globalConfig.MaxSessionRecords)
	playerRepo := db.NewPlayerRepository(database)

	// Create error handler
	errorHandler := proxyerrors.NewErrorHandler()

	// Create external verifier if configured
	var externalVerifier *auth.ExternalVerifier
	if globalConfig.AuthVerifyEnabled && globalConfig.AuthVerifyURL != "" {
		externalVerifier = auth.NewExternalVerifier(globalConfig.AuthVerifyEnabled, globalConfig.AuthVerifyURL, globalConfig.AuthCacheMinutes)
		logger.Info("External auth verification enabled: %s", globalConfig.AuthVerifyURL)
	}

	// Set up session end callback for persistence
	sessionMgr.OnSessionEnd = func(sess *session.Session) {
		persistSession(sess, sessionRepo, playerRepo, errorHandler)
	}

	return &ProxyServer{
		config:           globalConfig,
		configMgr:        configMgr,
		sessionMgr:       sessionMgr,
		db:               database,
		sessionRepo:      sessionRepo,
		playerRepo:       playerRepo,
		bufferPool:       bufferPool,
		forwarder:        forwarder,
		errorHandler:     errorHandler,
		externalVerifier: externalVerifier,
		listeners:        make(map[string]Listener),
	}, nil
}

// SetACLManager sets the ACL manager for access control.
// This must be called before Start() to enable access control in proxy listeners.
// Requirements: 5.1
func (p *ProxyServer) SetACLManager(aclMgr *acl.ACLManager) {
	p.aclManager = aclMgr
}

// GetACLManager returns the ACL manager (may be nil if not set).
func (p *ProxyServer) GetACLManager() *acl.ACLManager {
	return p.aclManager
}

// GetExternalVerifier returns the external verifier (may be nil if not configured).
func (p *ProxyServer) GetExternalVerifier() *auth.ExternalVerifier {
	return p.externalVerifier
}

// persistSession saves session data to the database when a session ends.
// Uses retry logic for database operations per requirement 9.3.
func persistSession(sess *session.Session, sessionRepo *db.SessionRepository, playerRepo *db.PlayerRepository, errorHandler *proxyerrors.ErrorHandler) {
	// Create session record
	endTime := time.Now()
	duration := endTime.Sub(sess.StartTime)
	record := &session.SessionRecord{
		ID:          sess.ID,
		ClientAddr:  sess.ClientAddr,
		ServerID:    sess.ServerID,
		UUID:        sess.UUID,
		DisplayName: sess.DisplayName,
		BytesUp:     sess.BytesUp,
		BytesDown:   sess.BytesDown,
		StartTime:   sess.StartTime,
		EndTime:     endTime,
	}

	// Log player disconnect event (requirement 9.5)
	if sess.UUID != "" {
		logger.LogPlayerDisconnect(sess.UUID, sess.DisplayName, sess.ServerID, sess.ClientAddr, duration, sess.BytesUp, sess.BytesDown)
	}
	logger.LogSessionEnded(sess.ClientAddr, sess.ServerID, duration)

	// Save session record with retry (requirement 9.3)
	err := errorHandler.RetryOperation("persist session", func() error {
		return sessionRepo.Create(record)
	})
	if err != nil {
		logger.LogDatabaseError("persist session", err)
	}

	// Cleanup old records if needed with retry
	err = errorHandler.RetryOperation("cleanup session records", func() error {
		return sessionRepo.Cleanup()
	})
	if err != nil {
		logger.LogDatabaseError("cleanup session records", err)
	}

	// Update player stats if we have player info (use DisplayName as primary key)
	if sess.DisplayName != "" {
		totalBytes := sess.BytesUp + sess.BytesDown

		// Try to get existing player by display name
		player, err := playerRepo.GetByDisplayName(sess.DisplayName)
		if err != nil {
			// Create new player record with retry
			player = &db.PlayerRecord{
				DisplayName:   sess.DisplayName,
				UUID:          sess.UUID,
				XUID:          sess.XUID,
				FirstSeen:     sess.StartTime,
				LastSeen:      endTime,
				TotalBytes:    totalBytes,
				TotalPlaytime: int64(duration.Seconds()),
			}
			err = errorHandler.RetryOperation("create player record", func() error {
				return playerRepo.Create(player)
			})
			if err != nil {
				logger.LogDatabaseError("create player record", err)
			}
		} else {
			// Update existing player stats with retry
			err = errorHandler.RetryOperation("update player stats", func() error {
				return playerRepo.UpdateStats(sess.DisplayName, totalBytes, duration)
			})
			if err != nil {
				logger.LogDatabaseError("update player stats", err)
			}
		}
	}
}

// Start starts the proxy server and all configured listeners.
func (p *ProxyServer) Start() error {
	p.runningMu.Lock()
	if p.running {
		p.runningMu.Unlock()
		return fmt.Errorf("proxy server is already running")
	}

	// Create context for graceful shutdown
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.running = true
	p.runningMu.Unlock()

	// Start garbage collection for idle sessions
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.sessionMgr.GarbageCollect(p.ctx)
	}()

	// Start DNS refresh
	p.configMgr.StartDNSRefresh(p.ctx, 60*time.Second)

	// Start config file watcher
	if err := p.configMgr.Watch(p.ctx); err != nil {
		log.Printf("Warning: failed to start config watcher: %v", err)
	}

	// Set up config change callback
	p.configMgr.SetOnChange(func() {
		if err := p.Reload(); err != nil {
			logger.Error("Failed to reload after config change: %v", err)
		}
	})

	// Start listeners for all enabled servers
	servers := p.configMgr.GetAllServers()
	for _, serverCfg := range servers {
		if serverCfg.Enabled {
			if err := p.startListener(serverCfg); err != nil {
				logger.Error("Failed to start listener for server %s: %v", serverCfg.ID, err)
			}
		}
	}

	logger.Info("Proxy server started with %d listeners", p.listenerCount())
	return nil
}

// startListener creates and starts a listener for a server configuration.
// It chooses between transparent UDP proxy and full RakNet proxy based on config.
func (p *ProxyServer) startListener(serverCfg *config.ServerConfig) error {
	p.listenersMu.Lock()
	defer p.listenersMu.Unlock()

	// Check if listener already exists
	if _, exists := p.listeners[serverCfg.ID]; exists {
		return fmt.Errorf("listener for server %s already exists", serverCfg.ID)
	}

	var listener Listener
	proxyMode := serverCfg.GetProxyMode()

	switch proxyMode {
	case "mitm":
		// Use MITM proxy with gophertunnel (full protocol access, requires proxy Xbox auth for auth servers)
		mitmProxy := NewMITMProxy(
			serverCfg.ID,
			serverCfg,
			p.configMgr,
			p.sessionMgr,
		)
		// Inject ACL manager for access control (Requirement 5.1)
		if p.aclManager != nil {
			mitmProxy.SetACLManager(p.aclManager)
		}
		listener = mitmProxy
		logger.Info("Using MITM proxy mode for server %s", serverCfg.ID)
	case "raknet":
		// Use full RakNet proxy (can extract player info)
		raknetProxy := NewRakNetProxy(
			serverCfg.ID,
			serverCfg,
			p.configMgr,
			p.sessionMgr,
		)
		// Inject ACL manager for access control (Requirement 5.1)
		if p.aclManager != nil {
			raknetProxy.SetACLManager(p.aclManager)
		}
		listener = raknetProxy
		logger.Info("Using RakNet proxy mode for server %s", serverCfg.ID)
	case "passthrough":
		// Use passthrough proxy (like gamma - forwards auth, extracts player info)
		passthroughProxy := NewPassthroughProxy(
			serverCfg.ID,
			serverCfg,
			p.configMgr,
			p.sessionMgr,
		)
		// Inject ACL manager for access control (Requirement 5.1)
		if p.aclManager != nil {
			passthroughProxy.SetACLManager(p.aclManager)
		}
		// Inject external verifier for auth verification
		if p.externalVerifier != nil {
			passthroughProxy.SetExternalVerifier(p.externalVerifier)
		}
		listener = passthroughProxy
		logger.Info("Using passthrough proxy mode for server %s (auth forwarded)", serverCfg.ID)
	default:
		// Use transparent UDP proxy (default)
		udpListener := NewUDPListener(
			serverCfg.ID,
			serverCfg,
			p.bufferPool,
			p.sessionMgr,
			p.forwarder,
			p.configMgr,
		)
		listener = udpListener
		logger.Debug("Using transparent proxy mode for server %s", serverCfg.ID)
	}

	// Start the listener
	if err := listener.Start(); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	// Store listener
	p.listeners[serverCfg.ID] = listener

	// Start listening in a goroutine
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := listener.Listen(p.ctx); err != nil && err != context.Canceled {
			logger.Error("Listener for server %s stopped with error: %v", serverCfg.ID, err)
		}
	}()

	logger.LogServerStarted(serverCfg.ID, serverCfg.ListenAddr)
	return nil
}

// stopListener stops a specific listener.
func (p *ProxyServer) stopListener(serverID string) error {
	p.listenersMu.Lock()
	defer p.listenersMu.Unlock()

	listener, exists := p.listeners[serverID]
	if !exists {
		return fmt.Errorf("listener for server %s not found", serverID)
	}

	if err := listener.Stop(); err != nil {
		return fmt.Errorf("failed to stop listener: %w", err)
	}

	delete(p.listeners, serverID)
	logger.LogServerStopped(serverID)
	return nil
}

// Stop gracefully stops the proxy server and all listeners.
func (p *ProxyServer) Stop() error {
	p.runningMu.Lock()
	if !p.running {
		p.runningMu.Unlock()
		return fmt.Errorf("proxy server is not running")
	}
	p.running = false
	p.runningMu.Unlock()

	// Cancel context to signal all goroutines to stop
	if p.cancel != nil {
		p.cancel()
	}

	// Stop config watcher
	p.configMgr.StopWatch()

	// Stop all listeners
	p.listenersMu.Lock()
	for serverID, listener := range p.listeners {
		if err := listener.Stop(); err != nil {
			logger.Error("Error stopping listener %s: %v", serverID, err)
		}
	}
	p.listeners = make(map[string]Listener)
	p.listenersMu.Unlock()

	// Clean up all sessions (persist to database)
	sessions := p.sessionMgr.GetAllSessions()
	for _, sess := range sessions {
		p.sessionMgr.Remove(sess.ClientAddr)
	}

	// Wait for all goroutines to finish
	p.wg.Wait()

	logger.Info("Proxy server stopped")
	return nil
}

// Reload reloads the configuration and updates listeners accordingly.
func (p *ProxyServer) Reload() error {
	p.runningMu.RLock()
	if !p.running {
		p.runningMu.RUnlock()
		return fmt.Errorf("proxy server is not running")
	}
	p.runningMu.RUnlock()

	servers := p.configMgr.GetAllServers()
	serverMap := make(map[string]*config.ServerConfig)
	for _, s := range servers {
		serverMap[s.ID] = s
	}

	// Get current listeners
	p.listenersMu.RLock()
	currentListeners := make(map[string]bool)
	for id := range p.listeners {
		currentListeners[id] = true
	}
	p.listenersMu.RUnlock()

	// Stop listeners for removed or disabled servers
	for serverID := range currentListeners {
		serverCfg, exists := serverMap[serverID]
		if !exists || !serverCfg.Enabled {
			if err := p.stopListener(serverID); err != nil {
				logger.Error("Failed to stop listener for removed/disabled server %s: %v", serverID, err)
			}
		}
	}

	// Start listeners for new or re-enabled servers
	for _, serverCfg := range servers {
		if serverCfg.Enabled {
			if _, exists := currentListeners[serverCfg.ID]; !exists {
				if err := p.startListener(serverCfg); err != nil {
					logger.Error("Failed to start listener for server %s: %v", serverCfg.ID, err)
				}
			}
		}
	}

	logger.LogConfigReloaded(p.listenerCount())
	return nil
}

// ReloadServer reloads a specific server configuration without affecting others.
// This provides atomic restart for individual servers.
func (p *ProxyServer) ReloadServer(serverID string) error {
	p.runningMu.RLock()
	if !p.running {
		p.runningMu.RUnlock()
		return fmt.Errorf("proxy server is not running")
	}
	p.runningMu.RUnlock()

	// Get the latest config for this server
	serverCfg, exists := p.configMgr.GetServer(serverID)
	if !exists {
		// Server was removed, stop it if running
		p.listenersMu.RLock()
		_, running := p.listeners[serverID]
		p.listenersMu.RUnlock()

		if running {
			return p.stopListener(serverID)
		}
		return fmt.Errorf("server %s not found", serverID)
	}

	// Check if listener is currently running
	p.listenersMu.RLock()
	_, running := p.listeners[serverID]
	p.listenersMu.RUnlock()

	if running {
		// Stop the existing listener
		if err := p.stopListener(serverID); err != nil {
			return fmt.Errorf("failed to stop server %s: %w", serverID, err)
		}
	}

	// Start with new config if enabled
	if serverCfg.Enabled {
		if err := p.startListener(serverCfg); err != nil {
			return fmt.Errorf("failed to start server %s: %w", serverID, err)
		}
	}

	logger.Info("Server %s reloaded successfully", serverID)
	return nil
}

// StartServer starts the proxy for a specific server configuration.
func (p *ProxyServer) StartServer(serverID string) error {
	p.runningMu.RLock()
	if !p.running {
		p.runningMu.RUnlock()
		return fmt.Errorf("proxy server is not running")
	}
	p.runningMu.RUnlock()

	serverCfg, exists := p.configMgr.GetServer(serverID)
	if !exists {
		return fmt.Errorf("server %s not found", serverID)
	}

	// Check if already running
	p.listenersMu.RLock()
	_, running := p.listeners[serverID]
	p.listenersMu.RUnlock()

	if running {
		return fmt.Errorf("server %s is already running", serverID)
	}

	return p.startListener(serverCfg)
}

// StopServer stops the proxy for a specific server configuration.
func (p *ProxyServer) StopServer(serverID string) error {
	p.runningMu.RLock()
	if !p.running {
		p.runningMu.RUnlock()
		return fmt.Errorf("proxy server is not running")
	}
	p.runningMu.RUnlock()

	return p.stopListener(serverID)
}

// IsServerRunning checks if a specific server's listener is running.
func (p *ProxyServer) IsServerRunning(serverID string) bool {
	p.listenersMu.RLock()
	defer p.listenersMu.RUnlock()
	_, exists := p.listeners[serverID]
	return exists
}

// listenerCount returns the number of active listeners.
func (p *ProxyServer) listenerCount() int {
	p.listenersMu.RLock()
	defer p.listenersMu.RUnlock()
	return len(p.listeners)
}

// IsRunning returns whether the proxy server is running.
func (p *ProxyServer) IsRunning() bool {
	p.runningMu.RLock()
	defer p.runningMu.RUnlock()
	return p.running
}

// GetSessionManager returns the session manager.
func (p *ProxyServer) GetSessionManager() *session.SessionManager {
	return p.sessionMgr
}

// GetConfigManager returns the configuration manager.
func (p *ProxyServer) GetConfigManager() *config.ConfigManager {
	return p.configMgr
}

// GetDatabase returns the database instance.
func (p *ProxyServer) GetDatabase() *db.Database {
	return p.db
}

// GetSessionRepository returns the session repository.
func (p *ProxyServer) GetSessionRepository() *db.SessionRepository {
	return p.sessionRepo
}

// GetPlayerRepository returns the player repository.
func (p *ProxyServer) GetPlayerRepository() *db.PlayerRepository {
	return p.playerRepo
}

// GetActiveSessionCount returns the number of active sessions.
func (p *ProxyServer) GetActiveSessionCount() int {
	return p.sessionMgr.Count()
}

// GetActiveSessionsForServer returns the number of active sessions for a specific server.
func (p *ProxyServer) GetActiveSessionsForServer(serverID string) int {
	sessions := p.sessionMgr.GetAllSessions()
	count := 0
	for _, sess := range sessions {
		if sess.ServerID == serverID {
			count++
		}
	}
	return count
}

// GetServerStatus returns the status of a server (running/stopped).
func (p *ProxyServer) GetServerStatus(serverID string) string {
	if p.IsServerRunning(serverID) {
		return "running"
	}
	return "stopped"
}

// GetAllServerStatuses returns status information for all configured servers.
func (p *ProxyServer) GetAllServerStatuses() []config.ServerConfigDTO {
	servers := p.configMgr.GetAllServers()
	result := make([]config.ServerConfigDTO, 0, len(servers))

	for _, server := range servers {
		status := p.GetServerStatus(server.ID)
		activeSessions := p.GetActiveSessionsForServer(server.ID)
		result = append(result, server.ToDTO(status, activeSessions))
	}

	return result
}

// PlayerKicker interface for listeners that support kicking players
type PlayerKicker interface {
	KickPlayer(playerName, reason string) int
}

// KickPlayer kicks a player by display name from all sessions.
// Sends disconnect packet before closing connection.
// Returns the number of sessions that were kicked.
func (p *ProxyServer) KickPlayer(playerName string, reason string) int {
	logger.Info("ProxyServer.KickPlayer called: playerName=%s, reason=%s", playerName, reason)
	kickedCount := 0

	// Kick from all listeners that support it
	p.listenersMu.RLock()
	listenerCount := len(p.listeners)
	logger.Info("Checking %d listeners for PlayerKicker interface", listenerCount)
	for serverID, listener := range p.listeners {
		if kicker, ok := listener.(PlayerKicker); ok {
			logger.Info("Listener %s supports PlayerKicker, calling KickPlayer", serverID)
			count := kicker.KickPlayer(playerName, reason)
			kickedCount += count
			logger.Info("Listener %s kicked %d connections", serverID, count)
		} else {
			logger.Info("Listener %s does not support PlayerKicker", serverID)
		}
	}
	p.listenersMu.RUnlock()

	// Also remove from session manager
	sessions := p.sessionMgr.GetAllSessions()
	for _, sess := range sessions {
		if sess.DisplayName != "" && strings.EqualFold(sess.DisplayName, playerName) {
			p.sessionMgr.Remove(sess.ClientAddr)
			logger.Info("Removed session for kicked player %s", playerName)
		}
	}

	logger.Info("ProxyServer.KickPlayer finished: total kickedCount=%d", kickedCount)
	return kickedCount
}
