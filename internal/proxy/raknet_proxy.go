// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/session"

	"github.com/sandertv/go-raknet"
)

// RakNetProxy implements a hybrid proxy that uses go-raknet for both
// client and server connections, enabling full protocol access.
type RakNetProxy struct {
	serverID    string
	config      *config.ServerConfig
	configMgr   *config.ConfigManager
	sessionMgr  *session.SessionManager
	listener    *raknet.Listener
	aclManager  *acl.ACLManager // ACL manager for access control
	outboundMgr OutboundManager // Outbound manager for proxy routing
	closed      atomic.Bool
	wg          sync.WaitGroup
	// Cached pong data with real latency
	cachedPong      []byte
	cachedPongMu    sync.RWMutex
	lastPongLatency int64 // milliseconds
	// Context for background goroutines
	ctx    context.Context
	cancel context.CancelFunc
}

// NewRakNetProxy creates a new RakNet proxy for the specified server configuration.
func NewRakNetProxy(
	serverID string,
	cfg *config.ServerConfig,
	configMgr *config.ConfigManager,
	sessionMgr *session.SessionManager,
) *RakNetProxy {
	return &RakNetProxy{
		serverID:   serverID,
		config:     cfg,
		configMgr:  configMgr,
		sessionMgr: sessionMgr,
	}
}

// SetACLManager sets the ACL manager for access control.
func (p *RakNetProxy) SetACLManager(aclMgr *acl.ACLManager) {
	p.aclManager = aclMgr
}

// GetACLManager returns the ACL manager (may be nil if not set).
func (p *RakNetProxy) GetACLManager() *acl.ACLManager {
	return p.aclManager
}

// SetOutboundManager sets the outbound manager for proxy routing.
// Requirements: 2.1
func (p *RakNetProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

// GetOutboundManager returns the outbound manager (may be nil if not set).
func (p *RakNetProxy) GetOutboundManager() OutboundManager {
	return p.outboundMgr
}

// UpdateConfig updates the server configuration.
// This is called when the config file changes to update proxy_outbound and other settings.
func (p *RakNetProxy) UpdateConfig(cfg *config.ServerConfig) {
	p.config = cfg
	logger.Debug("RakNetProxy config updated for server %s, proxy_outbound=%s", p.serverID, cfg.GetProxyOutbound())
}

// Start begins listening for RakNet connections.
func (p *RakNetProxy) Start() error {
	// Create RakNet listener
	listener, err := raknet.Listen(p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start RakNet listener: %w", err)
	}

	p.listener = listener
	p.closed.Store(false)

	// Create cancellable context for background goroutines
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Set pong data for server list
	p.updatePongData()

	logger.Info("RakNet proxy started: id=%s, listen=%s", p.serverID, p.config.ListenAddr)
	return nil
}

// updatePongData sets the pong data for server list queries.
func (p *RakNetProxy) updatePongData() {
	// If show_real_latency is enabled, start periodic refresh with latency
	if p.config.IsShowRealLatency() {
		// Set initial pong data
		customMOTD := p.config.GetCustomMOTD()
		if customMOTD != "" {
			p.listener.PongData([]byte(customMOTD))
		}
		// Immediately fetch once to initialize cache, then start periodic refresh
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			// Track this goroutine as a background task (expected to run for server lifetime)
			gm := monitor.GetGoroutineManager()
			gid := gm.TrackBackground("pong-refresh", "raknet-proxy", "Server: "+p.serverID, p.cancel)
			defer gm.Untrack(gid)

			p.fetchRemotePongWithLatency()
			// Then start periodic refresh with cancellable context
			p.startPongRefresh(p.ctx)
		}()
		return
	}

	// Normal mode: use custom MOTD or fetch from remote
	customMOTD := p.config.GetCustomMOTD()
	if customMOTD != "" {
		p.listener.PongData([]byte(customMOTD))
	} else {
		// Fetch pong from remote server (one-time, no need to track)
		go p.fetchRemotePong()
	}
}

// startPongRefresh periodically refreshes pong data with real latency.
// It requires a context to be cancellable when the proxy is stopped or when connections close.
func (p *RakNetProxy) startPongRefresh(ctx context.Context) {
	// Use longer interval (30s) to reduce memory usage from connection creation
	// Each ping creates a new UDP connection through the proxy which consumes resources
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Context cancelled, exit goroutine
			return
		case <-ticker.C:
			if p.closed.Load() {
				return
			}
			p.fetchRemotePongWithLatency()
		}
	}
}

// fetchRemotePong fetches pong data from the remote server.
func (p *RakNetProxy) fetchRemotePong() {
	serverCfg, exists := p.configMgr.GetServer(p.serverID)
	if !exists {
		return
	}

	// If show_real_latency is enabled, use the latency-aware version
	if serverCfg.IsShowRealLatency() {
		p.fetchRemotePongWithLatency()
		return
	}

	targetAddr := serverCfg.GetTargetAddr()
	pong, err := raknet.Ping(targetAddr)
	if err != nil {
		logger.Debug("Failed to ping remote server %s: %v", targetAddr, err)
		return
	}

	p.listener.PongData(pong)
}

// fetchRemotePongWithLatency fetches pong data through proxy and embeds real latency.
func (p *RakNetProxy) fetchRemotePongWithLatency() {
	serverCfg, exists := p.configMgr.GetServer(p.serverID)
	if !exists {
		return
	}

	targetAddr := serverCfg.GetTargetAddr()
	var pong []byte
	var latency time.Duration
	var err error

	// If using proxy outbound, ping through proxy
	if p.outboundMgr != nil && !serverCfg.IsDirectConnection() {
		pong, latency, err = p.pingThroughProxy(targetAddr, serverCfg.GetProxyOutbound())
	} else {
		// Direct ping
		start := time.Now()
		pong, err = raknet.Ping(targetAddr)
		latency = time.Since(start)
	}

	if err != nil {
		logger.Debug("Failed to ping remote server %s: %v", targetAddr, err)
		// If ping fails but we have custom MOTD, use it with error indicator
		customMOTD := serverCfg.GetCustomMOTD()
		if customMOTD != "" {
			pongToSend := p.embedLatencyInMOTD([]byte(customMOTD), -1)
			p.listener.PongData(pongToSend)
		}
		// Cache the failed state
		p.cachedPongMu.Lock()
		p.lastPongLatency = -1
		p.cachedPongMu.Unlock()
		return
	}

	// Cache the latency and original pong data (contains player count from remote)
	p.cachedPongMu.Lock()
	p.lastPongLatency = latency.Milliseconds()
	p.cachedPong = pong // Store original pong from remote server
	p.cachedPongMu.Unlock()

	// Prepare pong to send to client
	pongToSend := pong
	// Use custom MOTD if set, otherwise use remote pong
	customMOTD := serverCfg.GetCustomMOTD()
	if customMOTD != "" {
		pongToSend = []byte(customMOTD)
	}

	// Embed latency into MOTD
	if len(pongToSend) > 0 {
		pongToSend = p.embedLatencyInMOTD(pongToSend, latency)
	}

	p.listener.PongData(pongToSend)
}

// GetCachedLatency returns the cached latency in milliseconds.
// Returns -1 if not available or offline.
func (p *RakNetProxy) GetCachedLatency() int64 {
	p.cachedPongMu.RLock()
	defer p.cachedPongMu.RUnlock()
	return p.lastPongLatency
}

// GetCachedPong returns the cached pong data.
func (p *RakNetProxy) GetCachedPong() []byte {
	p.cachedPongMu.RLock()
	defer p.cachedPongMu.RUnlock()
	return p.cachedPong
}

// pingThroughProxy pings the target server through the proxy outbound.
func (p *RakNetProxy) pingThroughProxy(targetAddr, proxyName string) ([]byte, time.Duration, error) {
	// Create a proxy dialer for UDP
	// Use a longer timeout (15s) for proxy connections since they have additional latency
	// from QUIC handshake + proxy relay
	proxyDialer := NewProxyDialer(p.outboundMgr, p.config, 15*time.Second)

	start := time.Now()

	// Use raknet.Dialer with the proxy dialer to ping
	dialer := raknet.Dialer{
		UpstreamDialer: proxyDialer,
	}

	// Ping through the proxy with a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a channel for the ping result
	type pingResult struct {
		pong []byte
		err  error
	}
	resultCh := make(chan pingResult, 1)

	go func() {
		pong, err := dialer.Ping(targetAddr)
		select {
		case resultCh <- pingResult{pong, err}:
		default:
			// Nobody listening, just return
		}
	}()

	select {
	case <-ctx.Done():
		latency := time.Since(start)
		logger.Debug("RakNet pingThroughProxy timeout: server=%s target=%s node=%s latency=%s err=%v",
			p.serverID, targetAddr, proxyDialer.GetSelectedNode(), latency, ctx.Err())
		return nil, latency, ctx.Err()
	case result := <-resultCh:
		latency := time.Since(start)
		if result.err != nil {
			logger.Debug("RakNet pingThroughProxy failed: server=%s target=%s node=%s latency=%s err=%v",
				p.serverID, targetAddr, proxyDialer.GetSelectedNode(), latency, result.err)
		} else {
			logger.Debug("RakNet pingThroughProxy ok: server=%s target=%s node=%s latency=%s",
				p.serverID, targetAddr, proxyDialer.GetSelectedNode(), latency)
		}
		return result.pong, latency, result.err
	}
}

// embedLatencyInMOTD embeds the latency value into the MOTD string.
// MCPE MOTD format: MCPE;ServerName;Protocol;Version;Players;MaxPlayers;ServerUID;WorldName;GameMode;...
// We append the latency to the server name.
// If latency is negative, shows "离线" instead.
func (p *RakNetProxy) embedLatencyInMOTD(pong []byte, latency time.Duration) []byte {
	motd := string(pong)
	parts := strings.Split(motd, ";")

	if len(parts) < 2 {
		return pong
	}

	// Add latency to server name (parts[1])
	if latency < 0 {
		parts[1] = fmt.Sprintf("%s §c[离线]", parts[1])
	} else {
		latencyMs := latency.Milliseconds()
		// Color code based on latency
		var color string
		if latencyMs < 50 {
			color = "§a" // Green
		} else if latencyMs < 100 {
			color = "§e" // Yellow
		} else if latencyMs < 200 {
			color = "§6" // Orange
		} else {
			color = "§c" // Red
		}
		parts[1] = fmt.Sprintf("%s %s[%dms]", parts[1], color, latencyMs)
	}

	return []byte(strings.Join(parts, ";"))
}

// Listen starts accepting RakNet connections. It blocks until the context is cancelled.
func (p *RakNetProxy) Listen(ctx context.Context) error {
	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	// Use a channel to receive connections with context cancellation support
	connChan := make(chan *raknet.Conn)
	errChan := make(chan error)

	// Start a goroutine to accept connections
	go func() {
		for {
			if p.closed.Load() {
				return
			}
			conn, err := p.listener.Accept()
			if err != nil {
				if p.closed.Load() {
					return
				}
				// Send error but don't block if channel is full
				select {
				case errChan <- err:
				default:
				}
				continue
			}
			select {
			case connChan <- conn.(*raknet.Conn):
			case <-ctx.Done():
				conn.Close()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case conn := <-connChan:
			p.wg.Add(1)
			go p.handleConnection(ctx, conn)
		case err := <-errChan:
			if !strings.Contains(err.Error(), "use of closed") {
				logger.Debug("RakNet accept error: %v", err)
			}
		}
	}
}

// handleConnection handles a single RakNet connection.
func (p *RakNetProxy) handleConnection(ctx context.Context, clientConn *raknet.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()

	// Check if server is enabled
	serverCfg, exists := p.configMgr.GetServer(p.serverID)
	if !exists || !serverCfg.Enabled {
		logger.Warn("Connection rejected: server %s is disabled", p.serverID)
		return
	}

	// Create session
	sess, _ := p.sessionMgr.GetOrCreate(clientAddr, p.serverID)
	logger.Info("RakNet connection: client=%s, server=%s", clientAddr, p.serverID)

	// Connect to remote server using RakNet
	targetAddr := serverCfg.GetTargetAddr()

	// Use a longer timeout and retry
	var remoteConn *raknet.Conn
	var err error

	// Check if we should use proxy outbound
	// Requirements: 2.1, 2.2, 2.3, 2.4
	useProxy := p.outboundMgr != nil && !serverCfg.IsDirectConnection()

	var lastProxyDialer *ProxyDialer
	for i := 0; i < 3; i++ {
		logger.Debug("Attempting RakNet connection to %s (attempt %d/3)", targetAddr, i+1)

		if useProxy {
			// Use proxy dialer for outbound connection
			proxyDialer := NewProxyDialer(p.outboundMgr, serverCfg, 15*time.Second)
			lastProxyDialer = proxyDialer
			dialer := raknet.Dialer{
				UpstreamDialer: proxyDialer,
			}
			if i == 0 {
				proxyConfig := serverCfg.GetProxyOutbound()
				if strings.Contains(proxyConfig, ",") {
					nodeCount := len(strings.Split(proxyConfig, ","))
					logger.Info("Connecting to remote %s via node-list (%d nodes)", targetAddr, nodeCount)
				} else if strings.HasPrefix(proxyConfig, "@") {
					logger.Info("Connecting to remote %s via group %s", targetAddr, proxyConfig)
				} else {
					logger.Info("Connecting to remote %s via node '%s'", targetAddr, proxyConfig)
				}
			}
			remoteConn, err = dialer.DialTimeout(targetAddr, 15*time.Second)
		} else {
			// Use direct connection
			// Requirements: 2.2
			remoteConn, err = raknet.DialTimeout(targetAddr, 15*time.Second)
		}

		if err == nil {
			break
		}
		logger.Debug("RakNet dial attempt %d failed: %v", i+1, err)
		time.Sleep(time.Second)
	}

	if err != nil {
		// Requirements: 2.4 - Log warning for proxy failures
		if useProxy {
			proxyConfig := serverCfg.GetProxyOutbound()
			if strings.Contains(proxyConfig, ",") {
				logger.Warn("Failed to connect to remote %s via node-list after 3 attempts: %v", targetAddr, err)
			} else {
				logger.Warn("Failed to connect to remote %s via proxy '%s' after 3 attempts: %v", targetAddr, proxyConfig, err)
			}
		} else {
			logger.Error("Failed to connect to remote %s after 3 attempts: %v", targetAddr, err)
		}
		return
	}
	defer remoteConn.Close()

	// Log the actual selected node for proxy connections
	if useProxy && lastProxyDialer != nil {
		selectedNode := lastProxyDialer.GetSelectedNode()
		if selectedNode != "" {
			logger.Info("Connected to remote %s via proxy '%s'", targetAddr, selectedNode)
		} else {
			logger.Info("Connected to remote: %s -> %s", clientAddr, targetAddr)
		}
	} else {
		logger.Info("Connected to remote: %s -> %s", clientAddr, targetAddr)
	}

	// Create context for this connection
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	gm := monitor.GetGoroutineManager()

	// Start bidirectional forwarding
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		defer cancel()
		gid := gm.Track("forward-client-to-remote", "raknet-proxy", "Client: "+clientAddr, cancel)
		defer gm.Untrack(gid)
		p.forwardPacketsTracked(connCtx, clientConn, remoteConn, sess, true, gid)
	}()

	// Remote -> Client
	go func() {
		defer wg.Done()
		defer cancel()
		gid := gm.Track("forward-remote-to-client", "raknet-proxy", "Client: "+clientAddr, cancel)
		defer gm.Untrack(gid)
		p.forwardPacketsTracked(connCtx, remoteConn, clientConn, sess, false, gid)
	}()

	wg.Wait()

	// Log session end and remove session from manager
	duration := time.Since(sess.StartTime)
	displayName := sess.GetDisplayName()
	if displayName != "" {
		logger.Info("Session ended: player=%s, client=%s, duration=%v", displayName, clientAddr, duration)
	} else {
		logger.Info("Session ended: client=%s, duration=%v", clientAddr, duration)
	}

	// Remove session from manager to prevent stale sessions
	if err := p.sessionMgr.Remove(clientAddr); err != nil {
		logger.Debug("Failed to remove session for %s: %v", clientAddr, err)
	}
}

// forwardPackets forwards packets between two RakNet connections.
func (p *RakNetProxy) forwardPackets(ctx context.Context, src, dst *raknet.Conn, sess *session.Session, isClientToRemote bool) {
	p.forwardPacketsTracked(ctx, src, dst, sess, isClientToRemote, 0)
}

// forwardPacketsTracked forwards packets between two RakNet connections with goroutine tracking.
func (p *RakNetProxy) forwardPacketsTracked(ctx context.Context, src, dst *raknet.Conn, sess *session.Session, isClientToRemote bool, gid int64) {
	// Use buffer pool to reduce GC pressure
	bufPtr := GetRakNetBuffer()
	buf := *bufPtr
	defer PutRakNetBuffer(bufPtr)

	gm := monitor.GetGoroutineManager()
	// Use longer timeout to reduce CPU usage from frequent deadline checks
	const readTimeout = 500 * time.Millisecond
	activityUpdateCounter := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
			src.SetReadDeadline(time.Now().Add(readTimeout))
			n, err := src.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Update activity less frequently (every 5 timeouts = 2.5 seconds)
					activityUpdateCounter++
					if gid != 0 && activityUpdateCounter >= 5 {
						gm.UpdateActivity(gid)
						activityUpdateCounter = 0
					}
					continue
				}
				return
			}

			if n == 0 {
				continue
			}

			data := buf[:n]
			activityUpdateCounter = 0

			// Update session stats and keep session alive
			sess.UpdateLastSeen()
			if gid != 0 {
				gm.UpdateActivity(gid)
			}
			if isClientToRemote {
				sess.AddBytesUp(int64(n))
				p.tryExtractPlayerInfo(sess, data)
			} else {
				sess.AddBytesDown(int64(n))
				p.tryExtractPlayerInfoFromServer(sess, data)
				// Try to detect and log disconnect packets from remote server
				if disconnectMsg := p.tryParseDisconnectPacket(data); disconnectMsg != "" {
					logger.Info("Remote server disconnect for %s: %s", sess.ClientAddr, disconnectMsg)
				}
			}

			// Forward packet
			_, err = dst.Write(data)
			if err != nil {
				return
			}
		}
	}
}

// tryExtractPlayerInfo attempts to extract player information from packets.
func (p *RakNetProxy) tryExtractPlayerInfo(sess *session.Session, data []byte) {
	if sess.IsLoginExtracted() || len(data) < 10 {
		return
	}
	p.searchForPlayerInfo(sess, data)
}

// tryExtractPlayerInfoFromServer attempts to extract player info from server packets.
func (p *RakNetProxy) tryExtractPlayerInfoFromServer(sess *session.Session, data []byte) {
	if sess.IsLoginExtracted() || len(data) < 10 {
		return
	}
	p.searchForPlayerInfo(sess, data)
}

// searchForPlayerInfo searches for player information patterns in packet data.
func (p *RakNetProxy) searchForPlayerInfo(sess *session.Session, data []byte) {
	dataStr := string(data)

	// Pattern 1: Look for "displayName" in JSON
	if idx := findPattern(dataStr, `"displayName"`); idx >= 0 {
		name := extractJSONString(dataStr, idx, "displayName")
		if name != "" && len(name) > 0 && len(name) < 50 {
			logger.Info("Player identified: name=%s, client=%s", name, sess.ClientAddr)
			sess.SetPlayerInfo("", name)

			// Check ACL access control after player name is extracted
			// Note: RakNet proxy cannot send disconnect packets directly,
			// so we just log the denial. The MITM proxy should be used for
			// proper access control with disconnect capability.
			if p.aclManager != nil {
				allowed, reason := p.checkACLAccess(name, p.serverID, sess.ClientAddr)
				if !allowed {
					logger.Warn("RakNet proxy: ACL denied but cannot disconnect: player=%s, reason=%s", name, reason)
				}
			}
			return
		}
	}

	// Pattern 2: Look for "identity" (UUID) in JSON
	if idx := findPattern(dataStr, `"identity"`); idx >= 0 {
		uuid := extractJSONString(dataStr, idx, "identity")
		if uuid != "" && len(uuid) == 36 {
			logger.Info("Player UUID found: uuid=%s, client=%s", uuid, sess.ClientAddr)
			sess.SetPlayerInfo(uuid, sess.GetDisplayName())
			return
		}
	}

	// Pattern 3: Look for XUID
	if idx := findPattern(dataStr, `"XUID"`); idx >= 0 {
		xuid := extractJSONString(dataStr, idx, "XUID")
		if xuid != "" && len(xuid) > 0 {
			logger.Info("Player XUID found: xuid=%s, client=%s", xuid, sess.ClientAddr)
			if sess.GetDisplayName() == "" {
				sess.SetPlayerInfo(xuid, "")
			}
		}
	}
}

// findPattern finds a pattern in a string and returns its index.
func findPattern(s, pattern string) int {
	for i := 0; i <= len(s)-len(pattern); i++ {
		if s[i:i+len(pattern)] == pattern {
			return i
		}
	}
	return -1
}

// extractJSONString extracts a JSON string value after a key.
func extractJSONString(s string, startIdx int, key string) string {
	keyPattern := `"` + key + `"`
	idx := findPattern(s[startIdx:], keyPattern)
	if idx < 0 {
		return ""
	}

	pos := startIdx + idx + len(keyPattern)
	for pos < len(s) && (s[pos] == ' ' || s[pos] == ':' || s[pos] == '\t') {
		pos++
	}

	if pos >= len(s) || s[pos] != '"' {
		return ""
	}
	pos++

	start := pos
	for pos < len(s) && s[pos] != '"' {
		if s[pos] == '\\' && pos+1 < len(s) {
			pos += 2
		} else {
			pos++
		}
	}

	if pos >= len(s) {
		return ""
	}

	return s[start:pos]
}

// checkACLAccess checks if a player is allowed to access the server.
// It implements fail-open behavior: if database errors occur, access is allowed.
// Requirements: 5.1, 5.3, 5.4
func (p *RakNetProxy) checkACLAccess(playerName, serverID, clientAddr string) (allowed bool, reason string) {
	// Use defer/recover to handle any panics from ACL manager
	defer func() {
		if r := recover(); r != nil {
			// Requirement 5.4: Database error - default allow and log warning
			logger.LogACLCheckError(playerName, serverID, r)
			allowed = true
			reason = ""
		}
	}()

	// Call ACL manager to check access with error reporting
	var dbErr error
	allowed, reason, dbErr = p.aclManager.CheckAccessWithError(playerName, serverID)

	// Requirement 5.4: Log warning if database error occurred
	if dbErr != nil {
		logger.LogACLCheckError(playerName, serverID, dbErr)
	}

	if !allowed {
		// Requirement 5.3: Log the denial event with player info and reason
		logger.LogAccessDenied(playerName, serverID, clientAddr, reason)
	}

	return allowed, reason
}

// Stop closes the RakNet proxy.
func (p *RakNetProxy) Stop() error {
	p.closed.Store(true)

	// Cancel background goroutines (pong refresh, etc.)
	if p.cancel != nil {
		p.cancel()
	}

	if p.listener != nil {
		err := p.listener.Close()
		p.wg.Wait()
		return err
	}

	p.wg.Wait()
	return nil
}

// tryParseDisconnectPacket attempts to parse a packet as a Disconnect packet.
// Returns the disconnect message if it's a disconnect packet, empty string otherwise.
// This is used to log the reason when the remote server disconnects the player.
func (p *RakNetProxy) tryParseDisconnectPacket(data []byte) string {
	if len(data) < 3 {
		return ""
	}

	// Check for packet header (0xfe)
	if data[0] != 0xfe {
		return ""
	}

	// Get compression algorithm ID (second byte)
	compressionID := data[1]
	compressedData := data[2:]

	var decompressed []byte
	var err error

	switch compressionID {
	case 0x00: // Flate compression
		decompressed, err = p.decompressFlate(compressedData)
	case 0x01: // Snappy compression
		decompressed, err = p.decompressSnappy(compressedData)
	default:
		return ""
	}

	if err != nil {
		return ""
	}

	// Parse the decompressed data to find disconnect packet
	return p.parseDisconnectData(decompressed)
}

// decompressFlate decompresses flate-compressed packet data.
func (p *RakNetProxy) decompressFlate(data []byte) ([]byte, error) {
	return decompressFlateLimited(data)
}

// decompressSnappy decompresses snappy-compressed packet data.
func (p *RakNetProxy) decompressSnappy(data []byte) ([]byte, error) {
	return decompressSnappyLimited(data)
}

// parseDisconnectData parses decompressed packet data to extract disconnect message.
func (p *RakNetProxy) parseDisconnectData(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	buf := bytes.NewBuffer(data)

	// Read packet length (varuint32)
	var packetLen uint32
	if err := readVaruint32(buf, &packetLen); err != nil {
		return ""
	}

	// Read packet ID (varuint32)
	var packetID uint32
	if err := readVaruint32(buf, &packetID); err != nil {
		return ""
	}

	// Disconnect packet ID is 0x05
	if packetID&0x3FF != 0x05 {
		return ""
	}

	// Read disconnect reason (varint32)
	var reason int32
	if err := readVarint32(buf, &reason); err != nil {
		return ""
	}

	// Read hide disconnect screen (bool)
	hideScreen, err := buf.ReadByte()
	if err != nil {
		return ""
	}

	// If hide screen is true, there's no message
	if hideScreen != 0 {
		return fmt.Sprintf("(reason code: %d, no message)", reason)
	}

	// Read message length (varuint32)
	var msgLen uint32
	if err := readVaruint32(buf, &msgLen); err != nil {
		return fmt.Sprintf("(reason code: %d)", reason)
	}

	if msgLen == 0 || msgLen > uint32(buf.Len()) {
		return fmt.Sprintf("(reason code: %d)", reason)
	}

	// Read message
	msgBytes := buf.Next(int(msgLen))
	message := string(msgBytes)

	if message == "" {
		return fmt.Sprintf("(reason code: %d)", reason)
	}

	return message
}
