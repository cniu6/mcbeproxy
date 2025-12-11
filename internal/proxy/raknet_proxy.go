// Package proxy provides the core UDP proxy functionality.
package proxy

import (
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
	"mcpeserverproxy/internal/session"

	"github.com/sandertv/go-raknet"
)

// RakNetProxy implements a hybrid proxy that uses go-raknet for both
// client and server connections, enabling full protocol access.
type RakNetProxy struct {
	serverID   string
	config     *config.ServerConfig
	configMgr  *config.ConfigManager
	sessionMgr *session.SessionManager
	listener   *raknet.Listener
	aclManager *acl.ACLManager // ACL manager for access control
	closed     atomic.Bool
	wg         sync.WaitGroup
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

// Start begins listening for RakNet connections.
func (p *RakNetProxy) Start() error {
	// Create custom MOTD for the listener
	motd := p.config.GetCustomMOTD()
	if motd == "" {
		motd = fmt.Sprintf("MCPE;%s;712;1.21.50;0;100;0;%s;Survival;1;19132;19132;0;", p.config.Name, p.config.Name)
	}

	// Create RakNet listener
	listener, err := raknet.Listen(p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start RakNet listener: %w", err)
	}

	// Set the pong data (MOTD)
	listener.PongData([]byte(motd))

	p.listener = listener
	p.closed.Store(false)

	logger.Info("RakNet proxy started: id=%s, listen=%s", p.serverID, p.config.ListenAddr)
	return nil
}

// Listen starts accepting RakNet connections. It blocks until the context is cancelled.
func (p *RakNetProxy) Listen(ctx context.Context) error {
	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if p.closed.Load() {
				return nil
			}

			// Accept new connection
			conn, err := p.listener.Accept()
			if err != nil {
				if p.closed.Load() {
					return nil
				}
				if !strings.Contains(err.Error(), "use of closed") {
					logger.Debug("RakNet accept error: %v", err)
				}
				continue
			}

			// Handle connection in a goroutine
			p.wg.Add(1)
			go p.handleConnection(ctx, conn.(*raknet.Conn))
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
	for i := 0; i < 3; i++ {
		logger.Debug("Attempting RakNet connection to %s (attempt %d/3)", targetAddr, i+1)
		remoteConn, err = raknet.DialTimeout(targetAddr, 15*time.Second)
		if err == nil {
			break
		}
		logger.Debug("RakNet dial attempt %d failed: %v", i+1, err)
		time.Sleep(time.Second)
	}

	if err != nil {
		logger.Error("Failed to connect to remote %s after 3 attempts: %v", targetAddr, err)
		return
	}
	defer remoteConn.Close()

	logger.Info("Connected to remote: %s -> %s", clientAddr, targetAddr)

	// Create context for this connection
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start bidirectional forwarding
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardPackets(connCtx, clientConn, remoteConn, sess, true)
	}()

	// Remote -> Client
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardPackets(connCtx, remoteConn, clientConn, sess, false)
	}()

	wg.Wait()

	// Log session end
	duration := time.Since(sess.StartTime)
	if sess.DisplayName != "" {
		logger.Info("Session ended: player=%s, client=%s, duration=%v", sess.DisplayName, clientAddr, duration)
	} else {
		logger.Info("Session ended: client=%s, duration=%v", clientAddr, duration)
	}
}

// forwardPackets forwards packets between two RakNet connections.
func (p *RakNetProxy) forwardPackets(ctx context.Context, src, dst *raknet.Conn, sess *session.Session, isClientToRemote bool) {
	buf := make([]byte, 65536)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			src.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := src.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			if n == 0 {
				continue
			}

			data := buf[:n]

			// Update session stats
			if isClientToRemote {
				sess.AddBytesUp(int64(n))
				p.tryExtractPlayerInfo(sess, data)
			} else {
				sess.AddBytesDown(int64(n))
				p.tryExtractPlayerInfoFromServer(sess, data)
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
			sess.SetPlayerInfo(uuid, sess.DisplayName)
			return
		}
	}

	// Pattern 3: Look for XUID
	if idx := findPattern(dataStr, `"XUID"`); idx >= 0 {
		xuid := extractJSONString(dataStr, idx, "XUID")
		if xuid != "" && len(xuid) > 0 {
			logger.Info("Player XUID found: xuid=%s, client=%s", xuid, sess.ClientAddr)
			if sess.DisplayName == "" {
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
	if p.listener != nil {
		err := p.listener.Close()
		p.wg.Wait()
		return err
	}
	return nil
}
