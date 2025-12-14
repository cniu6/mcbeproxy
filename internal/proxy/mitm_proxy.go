// Package proxy provides the core UDP proxy functionality.
// This implements a MITM proxy similar to github.com/lhridder/gamma
package proxy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/auth"
	"mcpeserverproxy/internal/config"
	proxyerrors "mcpeserverproxy/internal/errors"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/session"

	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// mitmConnInfo stores connection info for kick functionality
type mitmConnInfo struct {
	conn       *minecraft.Conn
	playerName string
}

// MITMProxy implements a Man-In-The-Middle proxy using gophertunnel.
// Similar to github.com/lhridder/gamma, it acts as a full Minecraft server
// to the client and a full Minecraft client to the remote server.
type MITMProxy struct {
	serverID      string
	config        *config.ServerConfig
	configMgr     *config.ConfigManager
	sessionMgr    *session.SessionManager
	listener      *minecraft.Listener
	authManager   *auth.XboxAuthManager // Xbox Live auth manager for authentication
	aclManager    *acl.ACLManager       // ACL manager for access control
	closed        atomic.Bool
	wg            sync.WaitGroup
	activeConns   map[*minecraft.Conn]*mitmConnInfo // Track active client connections with player info
	activeConnsMu sync.Mutex
}

// NewMITMProxy creates a new MITM proxy for the specified server configuration.
func NewMITMProxy(
	serverID string,
	cfg *config.ServerConfig,
	configMgr *config.ConfigManager,
	sessionMgr *session.SessionManager,
) *MITMProxy {
	return &MITMProxy{
		serverID:    serverID,
		config:      cfg,
		configMgr:   configMgr,
		sessionMgr:  sessionMgr,
		activeConns: make(map[*minecraft.Conn]*mitmConnInfo),
	}
}

// Start begins listening for Minecraft connections.
// If xbox_auth_enabled is true, it initializes the XboxAuthManager and performs authentication.
// Requirements: 1.1, 5.3, 5.4
func (p *MITMProxy) Start() error {
	// Initialize Xbox Live authentication if enabled (Requirements 5.3, 5.4)
	if p.config.IsXboxAuthEnabled() {
		tokenPath := p.config.GetXboxTokenPath()
		p.authManager = auth.NewXboxAuthManager(tokenPath)

		// Perform authentication (Requirement 1.1)
		ctx := context.Background()
		if err := p.authManager.Authenticate(ctx); err != nil {
			return fmt.Errorf("Xbox Live authentication failed: %w", err)
		}
		logger.Info("Xbox Live authentication enabled for server: %s", p.serverID)
	} else {
		logger.Info("Xbox Live authentication disabled for server: %s", p.serverID)
	}

	// Create listener config
	// AuthenticationDisabled=true means we accept connections without validating Xbox Live
	// The client still sends their identity data which we can read
	listenerCfg := minecraft.ListenConfig{
		StatusProvider:         minecraft.NewStatusProvider(p.config.Name, "Survival"),
		AuthenticationDisabled: true,
	}

	listener, err := listenerCfg.Listen("raknet", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start MITM listener: %w", err)
	}

	p.listener = listener
	p.closed.Store(false)

	logger.Info("MITM proxy started: id=%s, listen=%s", p.serverID, p.config.ListenAddr)
	return nil
}

// GetAuthManager returns the Xbox Live auth manager (may be nil if auth is disabled).
func (p *MITMProxy) GetAuthManager() *auth.XboxAuthManager {
	return p.authManager
}

// IsXboxAuthEnabled returns whether Xbox Live authentication is enabled for this proxy.
func (p *MITMProxy) IsXboxAuthEnabled() bool {
	return p.authManager != nil && p.authManager.IsAuthenticated()
}

// SetACLManager sets the ACL manager for access control.
// Requirements: 5.1
func (p *MITMProxy) SetACLManager(aclMgr *acl.ACLManager) {
	p.aclManager = aclMgr
}

// GetACLManager returns the ACL manager (may be nil if not set).
func (p *MITMProxy) GetACLManager() *acl.ACLManager {
	return p.aclManager
}

// Listen starts accepting Minecraft connections.
func (p *MITMProxy) Listen(ctx context.Context) error {
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

			conn, err := p.listener.Accept()
			if err != nil {
				if p.closed.Load() {
					return nil
				}
				if !strings.Contains(err.Error(), "use of closed") {
					logger.Debug("MITM accept error: %v", err)
				}
				continue
			}

			p.wg.Add(1)
			go p.handleConnection(ctx, conn.(*minecraft.Conn))
		}
	}
}

// handleConnection handles a single Minecraft connection.
func (p *MITMProxy) handleConnection(ctx context.Context, clientConn *minecraft.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	// Track active connection (player name will be set after identity extraction)
	connInf := &mitmConnInfo{conn: clientConn, playerName: ""}
	p.activeConnsMu.Lock()
	p.activeConns[clientConn] = connInf
	p.activeConnsMu.Unlock()
	defer func() {
		p.activeConnsMu.Lock()
		delete(p.activeConns, clientConn)
		p.activeConnsMu.Unlock()
	}()

	clientAddr := clientConn.RemoteAddr().String()

	// Check if server is enabled
	serverCfg, exists := p.configMgr.GetServer(p.serverID)
	if !exists || !serverCfg.Enabled {
		logger.Warn("Connection rejected: server %s is disabled", p.serverID)
		return
	}

	// Get player identity data from the client connection
	identityData := clientConn.IdentityData()
	clientData := clientConn.ClientData()

	// Extract player information
	playerName := identityData.DisplayName
	playerUUID := identityData.Identity
	playerXUID := identityData.XUID

	// Update connInfo with player name for kick functionality
	connInf.playerName = playerName

	// Log player connection with full identity info (Requirement 2.4)
	logger.Info("Player connected: name=%s, uuid=%s, xuid=%s, client=%s",
		playerName, playerUUID, playerXUID, clientAddr)

	// Check ACL access control (Requirements 5.1, 5.2, 5.3, 5.4)
	if p.aclManager != nil {
		allowed, reason := p.checkACLAccess(playerName, p.serverID, clientAddr)
		if !allowed {
			// Send disconnect packet with denial reason (Requirement 5.2)
			_ = clientConn.WritePacket(&packet.Disconnect{
				Message:                 reason,
				HideDisconnectionScreen: false,
			})
			return
		}
	}

	// Create session with player info including XUID (Requirements 2.1, 2.2, 2.3, 2.5)
	sess, _ := p.sessionMgr.GetOrCreate(clientAddr, p.serverID)
	sess.SetPlayerInfoWithXUID(playerUUID, playerName, playerXUID)

	// Connect to remote server
	targetAddr := serverCfg.GetTargetAddr()

	// Create dialer with appropriate authentication
	// Requirements: 3.1, 3.2, 3.5
	dialer := minecraft.Dialer{
		ClientData: clientData,
	}

	// If Xbox Live authentication is enabled, use the proxy's token source
	// Otherwise, pass the client's identity data (for servers that don't require auth)
	if p.IsXboxAuthEnabled() {
		// Use proxy's Xbox Live credentials for authentication (Requirement 3.1, 3.2)
		dialer.TokenSource = p.authManager.GetTokenSource()
		logger.Info("Connecting to remote server with Xbox auth: %s (player: %s)", targetAddr, playerName)
	} else {
		// Pass client's identity data for servers without Xbox auth requirement
		dialer.IdentityData = identityData
		logger.Info("Connecting to remote server without Xbox auth: %s (player: %s)", targetAddr, playerName)
	}

	// Try to connect with a longer timeout
	remoteConn, err := dialer.DialTimeout("raknet", targetAddr, 60*time.Second)
	if err != nil {
		// Handle connection failure with appropriate error message
		// Requirements: 3.5, 6.4, 6.5
		p.handleConnectionError(clientConn, playerName, targetAddr, err)
		return
	}
	defer remoteConn.Close()

	logger.Info("Connected to remote: player=%s, %s -> %s", playerName, clientAddr, targetAddr)

	// Spawn the player on the client using the remote server's game data
	gameData := remoteConn.GameData()
	if err := clientConn.StartGame(gameData); err != nil {
		logger.Error("Failed to start game for client: %v", err)
		return
	}

	// Create context for this connection
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start bidirectional packet forwarding
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Remote
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardPackets(connCtx, clientConn, remoteConn, sess, true, playerName)
	}()

	// Remote -> Client
	go func() {
		defer wg.Done()
		defer cancel()
		p.forwardPackets(connCtx, remoteConn, clientConn, sess, false, playerName)
	}()

	wg.Wait()

	// Log session end
	duration := time.Since(sess.StartTime)
	logger.Info("Session ended: player=%s, client=%s, duration=%v, up=%d, down=%d",
		playerName, clientAddr, duration, sess.BytesUp, sess.BytesDown)
}

// forwardPackets forwards packets between two Minecraft connections.
func (p *MITMProxy) forwardPackets(ctx context.Context, src, dst *minecraft.Conn, sess *session.Session, isClientToRemote bool, playerName string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			pk, err := src.ReadPacket()
			if err != nil {
				return
			}

			// Update stats (approximate packet size) and keep session alive
			sess.UpdateLastSeen()
			if isClientToRemote {
				sess.AddBytesUp(100) // Approximate
			} else {
				sess.AddBytesDown(100) // Approximate
			}

			// Log interesting packets
			if isClientToRemote {
				switch pkt := pk.(type) {
				case *packet.Text:
					if pkt.Message != "" {
						logger.Info("Chat [%s]: %s", playerName, pkt.Message)
					}
				case *packet.CommandRequest:
					logger.Info("Command [%s]: %s", playerName, pkt.CommandLine)
				}
			}

			// Forward packet
			if err := dst.WritePacket(pk); err != nil {
				return
			}
		}
	}
}

// handleConnectionError handles connection errors and sends appropriate disconnect messages to the client.
// Requirements: 3.5, 6.4, 6.5
func (p *MITMProxy) handleConnectionError(clientConn *minecraft.Conn, playerName, targetAddr string, err error) {
	// Requirement 6.5: Log the rejection reason when remote server rejects connection
	logger.Error("Failed to connect to remote %s: %v", targetAddr, err)

	var errMsg string

	// Check if this is an authentication-related error
	if p.IsXboxAuthEnabled() {
		// Check if the error indicates authentication failure
		errStr := err.Error()
		isAuthError := strings.Contains(errStr, "authentication") ||
			strings.Contains(errStr, "token") ||
			strings.Contains(errStr, "unauthorized") ||
			strings.Contains(errStr, "403") ||
			strings.Contains(errStr, "401")

		if isAuthError {
			// Requirement 6.4: Log warning when token refresh fails
			logger.Warn("Authentication error detected, may need to re-authenticate: %v", err)

			// Try to validate/refresh the token
			ctx := context.Background()
			if refreshErr := p.authManager.ValidateAndRefreshToken(ctx); refreshErr != nil {
				// Token refresh failed - trigger re-authentication in background
				logger.Warn("Token validation failed, initiating re-authentication")
				go p.triggerReauthentication()
				errMsg = proxyerrors.ErrMsgTokenRefreshFailed
			} else {
				// Token is valid, server rejected for other reasons
				errMsg = fmt.Sprintf(proxyerrors.ErrMsgServerRejected, err)
			}
		} else {
			// Non-auth error with Xbox auth enabled
			logger.Error("Remote server rejected connection for player %s", playerName)
			errMsg = fmt.Sprintf(proxyerrors.ErrMsgServerRejected, err)
		}
	} else {
		// No Xbox auth - generic connection error
		errMsg = fmt.Sprintf("§cUnable to connect to server\n§7%v", err)
	}

	// Requirement 3.5: Send disconnect packet to client with appropriate error message
	_ = clientConn.WritePacket(&packet.Disconnect{
		Message:                 errMsg,
		HideDisconnectionScreen: false,
	})
}

// checkACLAccess checks if a player is allowed to access the server.
// It implements fail-open behavior: if database errors occur, access is allowed.
// Requirements: 5.1, 5.2, 5.3, 5.4
func (p *MITMProxy) checkACLAccess(playerName, serverID, clientAddr string) (allowed bool, reason string) {
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

		// Format the reason with Minecraft color codes for better display
		if reason == "" {
			reason = "§cAccess denied"
		} else {
			reason = "§c" + reason
		}
	}

	return allowed, reason
}

// triggerReauthentication initiates re-authentication in the background.
// This is called when token refresh fails during a connection attempt.
// Requirements: 1.7, 3.5, 6.4
func (p *MITMProxy) triggerReauthentication() {
	if p.authManager == nil {
		return
	}

	ctx := context.Background()
	if err := p.authManager.ReauthenticateOnFailure(ctx); err != nil {
		logger.Error("Re-authentication failed: %v", err)
		logger.Error("Please restart the proxy and complete Xbox Live authentication")
	} else {
		logger.Info("Re-authentication successful, new connections will use updated credentials")
	}
}

// KickPlayer kicks a player by name, sending disconnect packet before closing connection.
// Returns the number of connections kicked.
func (p *MITMProxy) KickPlayer(playerName, reason string) int {
	// First, collect connections to kick while holding the lock
	p.activeConnsMu.Lock()
	logger.Info("MITMProxy KickPlayer called: playerName=%s, reason=%s, activeConns=%d", playerName, reason, len(p.activeConns))

	var connsToKick []*minecraft.Conn
	for conn, info := range p.activeConns {
		logger.Debug("Checking connection: stored playerName=%s, target=%s", info.playerName, playerName)
		if info.playerName != "" && strings.EqualFold(info.playerName, playerName) {
			connsToKick = append(connsToKick, conn)
		}
	}
	p.activeConnsMu.Unlock()

	// Now kick the connections without holding the lock (to avoid deadlock)
	kickedCount := 0
	for _, conn := range connsToKick {
		// Send disconnect packet with reason
		kickMsg := "被管理员踢出"
		if reason != "" {
			kickMsg = reason
		}
		logger.Info("Sending disconnect to player %s: %s", playerName, kickMsg)
		_ = conn.WritePacket(&packet.Disconnect{
			Message:                 "§c" + kickMsg,
			HideDisconnectionScreen: false,
		})
		// Close connection after sending disconnect
		conn.Close()
		kickedCount++
		logger.Info("Kicked player %s from MITM proxy (reason: %s)", playerName, reason)
	}
	logger.Info("MITMProxy KickPlayer finished: kickedCount=%d", kickedCount)
	return kickedCount
}

// Stop closes the MITM proxy.
func (p *MITMProxy) Stop() error {
	p.closed.Store(true)

	// Close all active connections to unblock ReadPacket calls
	p.activeConnsMu.Lock()
	for conn := range p.activeConns {
		conn.Close()
	}
	p.activeConns = make(map[*minecraft.Conn]*mitmConnInfo)
	p.activeConnsMu.Unlock()

	if p.listener != nil {
		err := p.listener.Close()
		p.wg.Wait()
		return err
	}
	return nil
}
