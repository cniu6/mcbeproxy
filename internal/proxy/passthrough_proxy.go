// Package proxy provides the core UDP proxy functionality.
// This implements a passthrough proxy similar to github.com/lhridder/gamma
// that accepts RakNet connections, extracts player info from login packets,
// then forwards the raw bytes to the remote server (preserving client auth).
package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/session"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/flate"
	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// RakNet packet IDs for unconnected messages
const (
	raknetIDUnconnectedPing         byte = 0x01
	raknetIDUnconnectedPingOpenConn byte = 0x02
	raknetIDUnconnectedPong         byte = 0x1c
	packetHeader                    byte = 0xfe
)

// RakNet magic bytes
var raknetMagic = []byte{
	0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
}

// ExternalVerifier interface for external auth verification.
type ExternalVerifier interface {
	IsEnabled() bool
	Verify(xuid, uuid, gamertag, serverID, clientIP string) (bool, string)
}

// connInfo stores connection info for kick functionality
type connInfo struct {
	conn          *raknet.Conn
	playerName    string
	kickRequested atomic.Bool
	kickReason    string
	kickMu        sync.Mutex
}

// PassthroughProxy implements a passthrough proxy using go-raknet.
// It accepts RakNet connections, extracts player info from login packets,
// then forwards the raw bytes to the remote server (preserving client auth).
type PassthroughProxy struct {
	serverID         string
	config           *config.ServerConfig
	configMgr        *config.ConfigManager
	sessionMgr       *session.SessionManager
	listener         *raknet.Listener
	aclManager       *acl.ACLManager  // ACL manager for access control
	externalVerifier ExternalVerifier // External auth verifier
	outboundMgr      OutboundManager  // Outbound manager for proxy routing
	closed           atomic.Bool
	wg               sync.WaitGroup
	activeConns      map[*raknet.Conn]*connInfo // Track active connections with player info
	activeConnsMu    sync.Mutex
	// Cached pong data with real latency
	cachedPong      []byte
	cachedPongMu    sync.RWMutex
	lastPongLatency int64 // milliseconds
	// Context for background goroutines
	ctx    context.Context
	cancel context.CancelFunc
}

// NewPassthroughProxy creates a new passthrough proxy.
func NewPassthroughProxy(
	serverID string,
	cfg *config.ServerConfig,
	configMgr *config.ConfigManager,
	sessionMgr *session.SessionManager,
) *PassthroughProxy {
	return &PassthroughProxy{
		serverID:    serverID,
		config:      cfg,
		configMgr:   configMgr,
		sessionMgr:  sessionMgr,
		activeConns: make(map[*raknet.Conn]*connInfo),
	}
}

// SetACLManager sets the ACL manager for access control.
func (p *PassthroughProxy) SetACLManager(aclMgr *acl.ACLManager) {
	p.aclManager = aclMgr
}

// GetACLManager returns the ACL manager (may be nil if not set).
func (p *PassthroughProxy) GetACLManager() *acl.ACLManager {
	return p.aclManager
}

// SetExternalVerifier sets the external verifier for auth verification.
func (p *PassthroughProxy) SetExternalVerifier(verifier ExternalVerifier) {
	p.externalVerifier = verifier
}

// GetExternalVerifier returns the external verifier (may be nil if not set).
func (p *PassthroughProxy) GetExternalVerifier() ExternalVerifier {
	return p.externalVerifier
}

// SetOutboundManager sets the outbound manager for proxy routing.
// Requirements: 2.1
func (p *PassthroughProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

// GetOutboundManager returns the outbound manager (may be nil if not set).
func (p *PassthroughProxy) GetOutboundManager() OutboundManager {
	return p.outboundMgr
}

// UpdateConfig updates the server configuration.
// This is called when the config file changes to update proxy_outbound and other settings.
func (p *PassthroughProxy) UpdateConfig(cfg *config.ServerConfig) {
	p.config = cfg
	logger.Debug("PassthroughProxy config updated for server %s, proxy_outbound=%s", p.serverID, cfg.GetProxyOutbound())
}

// Start begins listening for RakNet connections.
func (p *PassthroughProxy) Start() error {
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

	logger.Info("Passthrough proxy started: id=%s, listen=%s", p.serverID, p.config.ListenAddr)
	return nil
}

// updatePongData sets the pong data for server list queries.
func (p *PassthroughProxy) updatePongData() {
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
			gid := gm.TrackBackground("pong-refresh", "passthrough-proxy", "Server: "+p.serverID, p.cancel)
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
func (p *PassthroughProxy) startPongRefresh(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
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
func (p *PassthroughProxy) fetchRemotePong() {
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
func (p *PassthroughProxy) fetchRemotePongWithLatency() {
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
func (p *PassthroughProxy) GetCachedLatency() int64 {
	p.cachedPongMu.RLock()
	defer p.cachedPongMu.RUnlock()
	return p.lastPongLatency
}

// GetCachedPong returns the cached pong data.
func (p *PassthroughProxy) GetCachedPong() []byte {
	p.cachedPongMu.RLock()
	defer p.cachedPongMu.RUnlock()
	return p.cachedPong
}

// pingThroughProxy pings the target server through the proxy outbound.
func (p *PassthroughProxy) pingThroughProxy(targetAddr, proxyName string) ([]byte, time.Duration, error) {
	// Create a proxy dialer for UDP
	// Use a longer timeout (15s) for proxy connections since they have additional latency
	// from QUIC handshake + proxy relay
	proxyDialer := NewProxyDialer(p.outboundMgr, p.config, 15*time.Second)

	start := time.Now()

	// Use raknet.Dialer with the proxy dialer to ping
	dialer := raknet.Dialer{
		UpstreamDialer: proxyDialer,
	}

	// Ping through the proxy
	pong, err := dialer.Ping(targetAddr)
	latency := time.Since(start)

	if err != nil {
		return nil, latency, err
	}

	return pong, latency, nil
}

// embedLatencyInMOTD embeds the latency value into the MOTD string.
// MCPE MOTD format: MCPE;ServerName;Protocol;Version;Players;MaxPlayers;ServerUID;WorldName;GameMode;...
// We append the latency to the server name.
// If latency is negative, shows "离线" instead.
func (p *PassthroughProxy) embedLatencyInMOTD(pong []byte, latency time.Duration) []byte {
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

// Listen starts accepting and handling RakNet connections.
func (p *PassthroughProxy) Listen(ctx context.Context) error {
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
			logger.Debug("Accept error: %v", err)
		}
	}
}

// handleConnection handles a single RakNet connection.
func (p *PassthroughProxy) handleConnection(ctx context.Context, clientConn *raknet.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	// Track active connection (player name will be set later after login)
	connInf := &connInfo{conn: clientConn, playerName: ""}
	p.activeConnsMu.Lock()
	p.activeConns[clientConn] = connInf
	p.activeConnsMu.Unlock()
	defer func() {
		p.activeConnsMu.Lock()
		delete(p.activeConns, clientConn)
		p.activeConnsMu.Unlock()
	}()

	clientAddr := clientConn.RemoteAddr().String()

	serverCfg, exists := p.configMgr.GetServer(p.serverID)
	if !exists || !serverCfg.Enabled {
		return
	}

	// Check if server is disabled (reject new connections)
	if serverCfg.Disabled {
		// We need to complete the handshake before sending disconnect
		// Set deadline for initial handshake
		clientConn.SetDeadline(time.Now().Add(10 * time.Second))

		// Read NetworkSettings request
		if _, err := clientConn.ReadPacket(); err != nil {
			return
		}

		// Send NetworkSettings response
		netSettingsPk := &packet.NetworkSettings{
			CompressionThreshold: 512,
			CompressionAlgorithm: packet.CompressionAlgorithmFlate,
		}
		if err := p.sendPacketUncompressed(clientConn, netSettingsPk); err != nil {
			return
		}

		// Read Login packet
		if _, err := clientConn.ReadPacket(); err != nil {
			return
		}

		// Send disconnect with custom message
		disabledMsg := serverCfg.DisabledMessage
		if disabledMsg == "" {
			disabledMsg = "服务器暂时关闭，请稍后再试"
		}
		p.sendDisconnect(clientConn, "§c"+disabledMsg)
		logger.Info("Connection rejected (server disabled): client=%s, server=%s", clientAddr, p.serverID)
		return
	}

	// Set deadline for initial handshake
	clientConn.SetDeadline(time.Now().Add(10 * time.Second))

	// Step 1: Read NetworkSettings request packet
	networkBytes, err := clientConn.ReadPacket()
	if err != nil {
		logger.Debug("Failed to read network settings from %s: %v", clientAddr, err)
		return
	}

	// Step 2: Send NetworkSettings response using gophertunnel's packet structure
	// CompressionAlgorithm: 0 = Flate (default), 1 = Snappy
	netSettingsPk := &packet.NetworkSettings{
		CompressionThreshold: 512,
		CompressionAlgorithm: packet.CompressionAlgorithmFlate, // 0 = Flate
	}
	if err := p.sendPacketUncompressed(clientConn, netSettingsPk); err != nil {
		logger.Debug("Failed to send network settings to %s: %v", clientAddr, err)
		return
	}

	// Step 3: Read Login packet
	loginBytes, err := clientConn.ReadPacket()
	if err != nil {
		logger.Debug("Failed to read login packet from %s: %v", clientAddr, err)
		return
	}

	// Step 4: Parse login packet to extract player info
	playerName, playerUUID, playerXUID := p.parseLoginPacket(loginBytes)

	// Clean up any existing sessions for this player before creating a new one
	// This prevents "already logged in elsewhere" errors when players reconnect
	if playerXUID != "" {
		removed := p.sessionMgr.RemoveByXUID(playerXUID)
		if removed > 0 {
			logger.Debug("Cleaned up %d stale session(s) for XUID %s", removed, playerXUID)
		}
	} else if playerName != "" {
		removed := p.sessionMgr.RemoveByPlayerName(playerName)
		if removed > 0 {
			logger.Debug("Cleaned up %d stale session(s) for player %s", removed, playerName)
		}
	}

	// Create session
	sess, _ := p.sessionMgr.GetOrCreate(clientAddr, p.serverID)
	if playerName != "" {
		sess.SetPlayerInfoWithXUID(playerUUID, playerName, playerXUID)
		// Update connInfo with player name for kick functionality
		connInf.playerName = playerName
		logger.Info("Player connected: name=%s, uuid=%s, xuid=%s, client=%s",
			playerName, playerUUID, playerXUID, clientAddr)

		// Check ACL access control (Requirements 5.1, 5.2, 5.3, 5.4)
		if p.aclManager != nil {
			allowed, reason := p.checkACLAccess(playerName, p.serverID, clientAddr)
			if !allowed {
				// Send disconnect packet with denial reason (Requirement 5.2)
				p.sendDisconnect(clientConn, reason)
				return
			}
		}

		// Check external auth verification
		if p.externalVerifier != nil && p.externalVerifier.IsEnabled() {
			allowed, reason := p.externalVerifier.Verify(playerXUID, playerUUID, playerName, p.serverID, clientAddr)
			if !allowed {
				logger.LogAccessDenied(playerName, p.serverID, clientAddr, "external auth: "+reason)
				// Use reason directly - external verifier now always provides meaningful messages
				if reason == "" {
					reason = "验证失败，请稍后再试"
				}
				p.sendDisconnect(clientConn, "§c"+reason)
				return
			}
		}
	} else {
		logger.Info("New connection: client=%s -> remote=%s", clientAddr, serverCfg.GetTargetAddr())
	}

	// Clear deadline for normal operation
	clientConn.SetDeadline(time.Time{})

	// Step 5: Connect to remote server
	targetAddr := serverCfg.GetTargetAddr()
	var remoteConn *raknet.Conn

	// Check if we should use proxy outbound
	// Requirements: 2.1, 2.2, 2.3, 2.4
	if p.outboundMgr != nil && !serverCfg.IsDirectConnection() {
		// Use proxy dialer for outbound connection
		proxyDialer := NewProxyDialer(p.outboundMgr, serverCfg, 15*time.Second)
		dialer := raknet.Dialer{
			UpstreamDialer: proxyDialer,
		}
		proxyConfig := serverCfg.GetProxyOutbound()
		// Log proxy config type
		if strings.Contains(proxyConfig, ",") {
			nodeCount := len(strings.Split(proxyConfig, ","))
			logger.Info("Connecting to remote %s via node-list (%d nodes)", targetAddr, nodeCount)
		} else if strings.HasPrefix(proxyConfig, "@") {
			logger.Info("Connecting to remote %s via group %s", targetAddr, proxyConfig)
		} else {
			logger.Info("Connecting to remote %s via node '%s'", targetAddr, proxyConfig)
		}
		logger.Debug("ProxyDialer created, attempting RakNet dial to %s", targetAddr)
		remoteConn, err = dialer.Dial(targetAddr)
		if err != nil {
			logger.Error("RakNet dial via proxy failed: %v", err)
		} else {
			selectedNode := proxyDialer.GetSelectedNode()
			if selectedNode != "" {
				logger.Info("RakNet connection established via proxy '%s' to %s", selectedNode, targetAddr)
			} else {
				logger.Info("RakNet connection established via proxy to %s", targetAddr)
			}
		}
	} else {
		// Use direct connection
		// Requirements: 2.2
		logger.Debug("Using direct connection to %s", targetAddr)
		remoteConn, err = raknet.Dial(targetAddr)
	}

	if err != nil {
		// Requirements: 2.4 - Log warning and handle connection failure
		if !serverCfg.IsDirectConnection() {
			logger.Warn("Failed to connect to remote %s via proxy %s: %v", targetAddr, serverCfg.GetProxyOutbound(), err)
		} else {
			logger.Error("Failed to connect to remote %s: %v", targetAddr, err)
		}
		p.sendDisconnect(clientConn, "§cFailed to connect to server")
		return
	}
	defer remoteConn.Close()

	// Step 6: Forward the NetworkSettings request to remote
	logger.Debug("Forwarding NetworkSettings to remote (%d bytes)", len(networkBytes))
	if _, err := remoteConn.Write(networkBytes); err != nil {
		logger.Error("Failed to forward network settings to remote: %v", err)
		return
	}

	// Read and discard remote's NetworkSettings response
	logger.Debug("Waiting for NetworkSettings response from remote...")
	netResp, err := remoteConn.ReadPacket()
	if err != nil {
		logger.Error("Failed to read network settings from remote: %v", err)
		return
	}
	logger.Debug("Received NetworkSettings response from remote (%d bytes)", len(netResp))

	// Step 7: Forward the Login packet to remote (this contains client's auth JWT)
	logger.Debug("Forwarding Login packet to remote (%d bytes)", len(loginBytes))
	if _, err := remoteConn.Write(loginBytes); err != nil {
		logger.Error("Failed to forward login to remote: %v", err)
		return
	}
	logger.Debug("Login packet forwarded, starting bidirectional forwarding")

	// Step 8: Start bidirectional forwarding
	// Create a connection-level context that will be cancelled when this function returns
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	var wg sync.WaitGroup
	wg.Add(2)

	gm := monitor.GetGoroutineManager()

	// Forward from remote to client
	go func() {
		defer wg.Done()
		defer connCancel() // Cancel context when this goroutine exits to notify the other
		gid := gm.Track("forward-remote-to-client", "passthrough-proxy", "Player: "+playerName, connCancel)
		defer gm.Untrack(gid)

		consecutiveTimeouts := 0
		const maxConsecutiveTimeouts = 300 // 30 seconds of no data (100ms * 300)

		for {
			select {
			case <-connCtx.Done():
				logger.Debug("Context cancelled, stopping remote->client forwarding for %s", clientAddr)
				return
			default:
				// Set read deadline to allow periodic context checking
				remoteConn.SetDeadline(time.Now().Add(100 * time.Millisecond))
				pk, err := remoteConn.ReadPacket()
				if err != nil {
					// Check if it's a timeout error
					if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
						consecutiveTimeouts++
						// Check if we've exceeded max consecutive timeouts (connection likely dead)
						if consecutiveTimeouts >= maxConsecutiveTimeouts {
							logger.Debug("Connection timeout (remote->client) for %s: no data for 30s", clientAddr)
							return
						}
						// Timeout is expected, continue to check context
						gm.UpdateActivity(gid)
						continue
					}
					logger.Debug("Connection closed (remote->client) for %s: %v", clientAddr, err)
					return
				}
				// Reset timeout counter on successful read
				consecutiveTimeouts = 0
				// Clear deadline for write operation
				remoteConn.SetDeadline(time.Time{})

				sess.AddBytesDown(int64(len(pk)))
				sess.UpdateLastSeen() // Keep session alive while data is flowing
				gm.UpdateActivity(gid)
				if _, err := clientConn.Write(pk); err != nil {
					logger.Debug("Connection closed (write to client) for %s: %v", clientAddr, err)
					return
				}
			}
		}
	}()

	// Forward from client to remote
	go func() {
		defer wg.Done()
		defer connCancel() // Cancel context when this goroutine exits to notify the other
		gid := gm.Track("forward-client-to-remote", "passthrough-proxy", "Player: "+playerName, connCancel)
		defer gm.Untrack(gid)

		consecutiveTimeouts := 0
		const maxConsecutiveTimeouts = 300 // 30 seconds of no data (100ms * 300)

		for {
			select {
			case <-connCtx.Done():
				logger.Debug("Context cancelled, stopping client->remote forwarding for %s", clientAddr)
				return
			default:
				// Set read deadline to allow periodic context checking
				clientConn.SetDeadline(time.Now().Add(100 * time.Millisecond))
				pk, err := clientConn.ReadPacket()
				if err != nil {
					// Check if it's a timeout error
					if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
						consecutiveTimeouts++
						// Check if we've exceeded max consecutive timeouts (connection likely dead)
						if consecutiveTimeouts >= maxConsecutiveTimeouts {
							logger.Debug("Connection timeout (client->remote) for %s: no data for 30s", clientAddr)
							return
						}
						// Timeout is expected, continue to check context
						gm.UpdateActivity(gid)
						continue
					}
					logger.Debug("Connection closed (client->remote) for %s: %v", clientAddr, err)
					return
				}
				// Reset timeout counter on successful read
				consecutiveTimeouts = 0
				// Clear deadline for write operation
				clientConn.SetDeadline(time.Time{})

				sess.AddBytesUp(int64(len(pk)))
				sess.UpdateLastSeen() // Keep session alive while data is flowing
				gm.UpdateActivity(gid)
				if _, err := remoteConn.Write(pk); err != nil {
					logger.Debug("Connection closed (write to remote) for %s: %v", clientAddr, err)
					return
				}
			}
		}
	}()

	wg.Wait()

	// Log session end and remove session from manager
	duration := time.Since(sess.StartTime)
	if playerName != "" {
		logger.Info("Session ended: player=%s, client=%s, duration=%v, up=%d, down=%d",
			playerName, clientAddr, duration, sess.BytesUp, sess.BytesDown)
	} else {
		logger.Info("Session ended: client=%s, duration=%v", clientAddr, duration)
	}

	// Remove session from manager to prevent "already logged in" errors on reconnect
	if err := p.sessionMgr.Remove(clientAddr); err != nil {
		logger.Debug("Failed to remove session for %s: %v", clientAddr, err)
	}
}

// parseLoginPacket parses a login packet to extract player information.
// The login packet is compressed and contains JWT tokens with player identity.
// Format: 0xfe + compression_id(1 byte) + compressed_data
// compression_id: 0x00 = Flate, 0x01 = Snappy
func (p *PassthroughProxy) parseLoginPacket(data []byte) (displayName, uuid, xuid string) {
	if len(data) < 3 {
		logger.Debug("Login packet too short: %d bytes", len(data))
		return
	}

	// Check for packet header (0xfe)
	if data[0] != packetHeader {
		logger.Debug("Login packet missing header, first byte: 0x%x", data[0])
		return
	}

	// Log first few bytes for debugging
	if len(data) > 20 {
		logger.Debug("Login packet first 20 bytes: %x", data[:20])
	}

	// Get compression algorithm ID (second byte)
	compressionID := data[1]
	compressedData := data[2:]

	logger.Debug("Compression ID: 0x%x, compressed data length: %d", compressionID, len(compressedData))

	var decompressed []byte
	var err error

	switch compressionID {
	case 0x00: // Flate compression
		logger.Debug("Using Flate decompression")
		decompressed, err = p.decompressFlate(compressedData)
	case 0x01: // Snappy compression
		logger.Debug("Using Snappy decompression")
		decompressed, err = p.decompressSnappy(compressedData)
	default:
		logger.Debug("Unknown compression ID: 0x%x", compressionID)
		return
	}

	if err != nil {
		logger.Debug("Failed to decompress login packet: %v", err)
		return
	}

	logger.Debug("Decompressed data length: %d", len(decompressed))
	if len(decompressed) > 50 {
		logger.Debug("Decompressed first 50 bytes: %x", decompressed[:50])
	}

	// Parse the decompressed data
	return p.parseLoginData(decompressed)
}

// decompressSnappy decompresses snappy-compressed packet data.
func (p *PassthroughProxy) decompressSnappy(data []byte) ([]byte, error) {
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("decompress snappy: %w", err)
	}
	return decompressed, nil
}

// decompressFlate decompresses flate-compressed packet data.
func (p *PassthroughProxy) decompressFlate(data []byte) ([]byte, error) {
	buf := bytes.NewReader(data)
	reader := flate.NewReader(buf)
	defer reader.Close()

	// Reset the reader with the data
	if err := reader.(flate.Resetter).Reset(buf, nil); err != nil {
		return nil, fmt.Errorf("reset flate: %w", err)
	}

	// Guess an uncompressed size of 2*len(data)
	decompressed := bytes.NewBuffer(make([]byte, 0, len(data)*2))
	if _, err := io.Copy(decompressed, reader); err != nil {
		return nil, fmt.Errorf("decompress flate: %v", err)
	}
	return decompressed.Bytes(), nil
}

// parseLoginData parses the decompressed login packet data.
func (p *PassthroughProxy) parseLoginData(data []byte) (displayName, uuid, xuid string) {
	if len(data) < 4 {
		logger.Debug("Decompressed data too short: %d bytes", len(data))
		return
	}

	// Read packet length (varuint32)
	buf := bytes.NewBuffer(data)
	var packetLen uint32
	if err := readVaruint32(buf, &packetLen); err != nil {
		logger.Debug("Failed to read packet length: %v", err)
		return
	}
	logger.Debug("Packet length: %d", packetLen)

	// Read packet ID (varuint32)
	var packetID uint32
	if err := readVaruint32(buf, &packetID); err != nil {
		logger.Debug("Failed to read packet ID: %v", err)
		return
	}
	logger.Debug("Packet ID: 0x%x (masked: 0x%x)", packetID, packetID&0x3FF)

	// Login packet ID is 0x01
	if packetID&0x3FF != 0x01 {
		logger.Debug("Not a login packet, ID: 0x%x", packetID)
		return
	}

	// Read protocol version (int32 big endian)
	var protocolVersion int32
	if err := binary.Read(buf, binary.BigEndian, &protocolVersion); err != nil {
		logger.Debug("Failed to read protocol version: %v", err)
		return
	}
	logger.Debug("Protocol version: %d", protocolVersion)

	// Read connection request length (varuint32)
	var connReqLen uint32
	if err := readVaruint32(buf, &connReqLen); err != nil {
		logger.Debug("Failed to read connection request length: %v", err)
		return
	}
	logger.Debug("Connection request length: %d, remaining: %d", connReqLen, buf.Len())

	if connReqLen <= 0 || connReqLen > uint32(buf.Len()) {
		logger.Debug("Invalid connection request length: %d (remaining: %d)", connReqLen, buf.Len())
		return
	}

	// Read connection request data
	connReqData := buf.Next(int(connReqLen))
	logger.Debug("Connection request data length: %d", len(connReqData))

	return p.parseConnectionRequest(connReqData)
}

// parseConnectionRequest parses the connection request to extract identity data.
func (p *PassthroughProxy) parseConnectionRequest(data []byte) (displayName, uuid, xuid string) {
	if len(data) < 4 {
		logger.Debug("Connection request data too short: %d bytes", len(data))
		return
	}

	buf := bytes.NewBuffer(data)

	// Read chain length (int32 little endian)
	var chainLen int32
	if err := binary.Read(buf, binary.LittleEndian, &chainLen); err != nil {
		logger.Debug("Failed to read chain length: %v", err)
		return
	}
	logger.Debug("Chain length: %d, remaining: %d", chainLen, buf.Len())

	if chainLen <= 0 || chainLen > int32(buf.Len()) {
		logger.Debug("Invalid chain length: %d (remaining: %d)", chainLen, buf.Len())
		return
	}

	// Read chain JSON
	chainData := buf.Next(int(chainLen))
	logger.Debug("Chain data (first 200 chars): %s", string(chainData[:min(200, len(chainData))]))

	// Parse the outer JSON structure
	// Format: {"AuthenticationType":0,"Certificate":"{\"chain\":[...]}"}
	var outerWrapper struct {
		AuthenticationType int    `json:"AuthenticationType"`
		Certificate        string `json:"Certificate"`
	}
	if err := json.Unmarshal(chainData, &outerWrapper); err != nil {
		logger.Debug("Failed to parse outer JSON: %v", err)
		// Try direct chain format as fallback
		return p.parseChainDirect(chainData)
	}

	logger.Debug("AuthenticationType: %d, Certificate length: %d", outerWrapper.AuthenticationType, len(outerWrapper.Certificate))

	// Parse the inner Certificate JSON (which contains the chain)
	var chainWrapper struct {
		Chain []string `json:"chain"`
	}
	if err := json.Unmarshal([]byte(outerWrapper.Certificate), &chainWrapper); err != nil {
		logger.Debug("Failed to parse certificate JSON: %v", err)
		return
	}

	logger.Debug("Found %d JWT tokens in chain", len(chainWrapper.Chain))

	return p.extractIdentityFromChain(chainWrapper.Chain)
}

// parseChainDirect tries to parse chain data in direct format {"chain":[...]}
func (p *PassthroughProxy) parseChainDirect(data []byte) (displayName, uuid, xuid string) {
	var chainWrapper struct {
		Chain []string `json:"chain"`
	}
	if err := json.Unmarshal(data, &chainWrapper); err != nil {
		logger.Debug("Failed to parse direct chain JSON: %v", err)
		return
	}

	logger.Debug("Found %d JWT tokens in direct chain", len(chainWrapper.Chain))
	return p.extractIdentityFromChain(chainWrapper.Chain)
}

// extractIdentityFromChain extracts player identity from JWT chain
func (p *PassthroughProxy) extractIdentityFromChain(chain []string) (displayName, uuid, xuid string) {
	jwtParser := jwt.Parser{}
	for i, token := range chain {
		var claims identityClaims
		_, _, err := jwtParser.ParseUnverified(token, &claims)
		if err != nil {
			logger.Debug("Failed to parse JWT token %d: %v", i, err)
			continue
		}

		logger.Debug("Token %d: DisplayName=%s, Identity=%s, XUID=%s",
			i, claims.ExtraData.DisplayName, claims.ExtraData.Identity, claims.ExtraData.XUID)

		if claims.ExtraData.DisplayName != "" {
			displayName = claims.ExtraData.DisplayName
			uuid = claims.ExtraData.Identity
			xuid = claims.ExtraData.XUID
			return
		}
	}

	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// identityClaims holds JWT claims for player identity.
type identityClaims struct {
	jwt.RegisteredClaims
	ExtraData struct {
		DisplayName string `json:"displayName"`
		Identity    string `json:"identity"`
		XUID        string `json:"XUID"`
	} `json:"extraData"`
}

// readVaruint32 reads a variable-length uint32.
func readVaruint32(r io.ByteReader, x *uint32) error {
	var v uint32
	for i := uint(0); i < 35; i += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		v |= uint32(b&0x7f) << i
		if b&0x80 == 0 {
			*x = v
			return nil
		}
	}
	return fmt.Errorf("varuint32 did not terminate after 5 bytes")
}

// checkACLAccess checks if a player is allowed to access the server.
// It implements fail-open behavior: if database errors occur, access is allowed.
// Requirements: 5.1, 5.2, 5.3, 5.4
func (p *PassthroughProxy) checkACLAccess(playerName, serverID, clientAddr string) (allowed bool, reason string) {
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

// sendDisconnect sends a disconnect packet to the client.
// In passthrough mode, we don't have access to the encryption keys,
// so we need to send the packet in a way the client can understand.
//
// The disconnect packet format for Bedrock Edition:
// - Packet ID: 0x05 (Disconnect)
// - Reason: int32 (disconnect reason code)
// - Hide disconnect screen: bool
// - Kick message: string (if hide is false)
func (p *PassthroughProxy) sendDisconnect(conn *raknet.Conn, message string) {
	logger.Debug("Sending disconnect packet with message: %s", message)

	// In passthrough mode, the client has established an encrypted session with the remote server.
	// We cannot send Minecraft-level disconnect packets because we don't have the encryption keys.
	// The best we can do is close the RakNet connection, which will show "Disconnected from server"
	// or similar message on the client.

	// However, we can try to send the disconnect packet anyway - if the client hasn't
	// fully established encryption yet, it might work.

	// Create disconnect packet using gophertunnel's packet structure
	pk := &packet.Disconnect{
		Reason:                  packet.DisconnectReasonKicked,
		HideDisconnectionScreen: false,
		Message:                 message,
		FilteredMessage:         message,
	}

	// Try compressed packet first
	if err := p.sendPacket(conn, pk); err != nil {
		logger.Debug("Failed to send compressed disconnect packet: %v", err)
	}

	// Also try uncompressed
	if err := p.sendPacketUncompressed(conn, pk); err != nil {
		logger.Debug("Failed to send uncompressed disconnect packet: %v", err)
	}

	// Try direct raw packet
	if err := p.sendDisconnectDirect(conn, message); err != nil {
		logger.Debug("Failed to send direct disconnect packet: %v", err)
	}

	logger.Info("Sent disconnect packet to client with message: %s", message)
}

// sendDisconnectDirect sends a disconnect packet using raw bytes for maximum compatibility.
func (p *PassthroughProxy) sendDisconnectDirect(conn *raknet.Conn, message string) error {
	// Build disconnect packet manually
	// Packet ID: 0x05 (Disconnect)
	var packetBuf bytes.Buffer

	// Write packet ID
	protocol.WriteVaruint32(&packetBuf, 0x05)

	// Write disconnect reason (varint32) - DisconnectReasonKicked = 2
	protocol.WriteVarint32(&packetBuf, 2)

	// Write hide disconnect screen (bool) - false to show message
	packetBuf.WriteByte(0x00)

	// Write message (string) - length prefixed with varuint32
	msgBytes := []byte(message)
	protocol.WriteVaruint32(&packetBuf, uint32(len(msgBytes)))
	packetBuf.Write(msgBytes)

	// Write filtered message (string) - length prefixed with varuint32
	protocol.WriteVaruint32(&packetBuf, uint32(len(msgBytes)))
	packetBuf.Write(msgBytes)

	// Build batch with length prefix
	var batchBuf bytes.Buffer
	protocol.WriteVaruint32(&batchBuf, uint32(packetBuf.Len()))
	batchBuf.Write(packetBuf.Bytes())

	// Compress with flate
	compressed, err := p.compressFlate(batchBuf.Bytes())
	if err != nil {
		return fmt.Errorf("compress packet: %w", err)
	}

	// Build final packet: 0xfe + 0x00 (flate) + compressed_data
	var finalBuf bytes.Buffer
	finalBuf.WriteByte(packetHeader) // 0xfe
	finalBuf.WriteByte(0x00)         // Flate compression
	finalBuf.Write(compressed)

	_, err = conn.Write(finalBuf.Bytes())
	return err
}

// sendPlayStatus sends a PlayStatus packet to the client.
func (p *PassthroughProxy) sendPlayStatus(conn *raknet.Conn, status int32) {
	pk := &packet.PlayStatus{
		Status: status,
	}
	if err := p.sendPacket(conn, pk); err != nil {
		logger.Debug("Failed to send play status packet: %v", err)
	}
}

// sendPacketUncompressed sends a packet without compression (used before compression is enabled).
func (p *PassthroughProxy) sendPacketUncompressed(conn *raknet.Conn, pk packet.Packet) error {
	// Step 1: Encode the packet using gophertunnel's protocol writer
	var packetBuf bytes.Buffer
	packetWriter := protocol.NewWriter(&packetBuf, 0) // shieldID = 0

	// Write packet ID as varuint32
	header := pk.ID()
	protocol.WriteVaruint32(&packetBuf, header)

	// Marshal the packet content
	pk.Marshal(packetWriter)

	// Step 2: Build the batch packet (length prefix + packet data)
	var batchBuf bytes.Buffer
	protocol.WriteVaruint32(&batchBuf, uint32(packetBuf.Len()))
	batchBuf.Write(packetBuf.Bytes())

	// Step 3: Build final packet: 0xfe + uncompressed_data (no compression before NetworkSettings)
	var finalBuf bytes.Buffer
	finalBuf.WriteByte(packetHeader) // 0xfe
	finalBuf.Write(batchBuf.Bytes())

	_, err := conn.Write(finalBuf.Bytes())
	return err
}

// sendPacket encodes and sends a packet to the client using gophertunnel's Encoder.
func (p *PassthroughProxy) sendPacket(conn *raknet.Conn, pk packet.Packet) error {
	// Step 1: Encode the packet using gophertunnel's protocol writer
	var packetBuf bytes.Buffer
	packetWriter := protocol.NewWriter(&packetBuf, 0) // shieldID = 0

	// Write packet ID as varuint32
	header := pk.ID()
	protocol.WriteVaruint32(&packetBuf, header)

	// Marshal the packet content
	pk.Marshal(packetWriter)

	// Step 2: Use gophertunnel's Encoder to properly encode the packet batch
	var outputBuf bytes.Buffer
	encoder := packet.NewEncoder(&outputBuf)
	encoder.EnableCompression(packet.FlateCompression)

	// Encode the packet (Encoder handles batching, compression, and header)
	if err := encoder.Encode([][]byte{packetBuf.Bytes()}); err != nil {
		return fmt.Errorf("encode packet: %w", err)
	}

	_, err := conn.Write(outputBuf.Bytes())
	return err
}

// compressFlate compresses data using flate/zlib compression.
func (p *PassthroughProxy) compressFlate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, 6)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeVaruint32 writes a variable-length uint32.
func writeVaruint32(w io.Writer, x uint32) {
	for x >= 0x80 {
		w.Write([]byte{byte(x) | 0x80})
		x >>= 7
	}
	w.Write([]byte{byte(x)})
}

// KickPlayer kicks a player by name, sending disconnect packet before closing connection.
// Returns the number of connections kicked.
//
// NOTE: In passthrough mode, we don't have access to the encryption keys used between
// the client and the remote server. This means we cannot send Minecraft-level disconnect
// packets that the client will understand. The client will see "Disconnected from server"
// instead of a custom kick message. This is a fundamental limitation of passthrough mode.
// For custom kick messages, use MITM mode instead.
func (p *PassthroughProxy) KickPlayer(playerName, reason string) int {
	// First, collect connections to kick while holding the lock
	p.activeConnsMu.Lock()
	logger.Info("KickPlayer called: playerName=%s, reason=%s, activeConns=%d", playerName, reason, len(p.activeConns))

	var infosToKick []*connInfo
	for _, info := range p.activeConns {
		logger.Debug("Checking connection: stored playerName=%s, target=%s", info.playerName, playerName)
		if info.playerName != "" && strings.EqualFold(info.playerName, playerName) {
			infosToKick = append(infosToKick, info)
		}
	}
	p.activeConnsMu.Unlock()

	// Now kick the connections without holding the lock (to avoid deadlock)
	kickedCount := 0
	for _, info := range infosToKick {
		// Set kick reason
		info.kickMu.Lock()
		kickMsg := "§c被管理员踢出"
		if reason != "" {
			kickMsg = "§c" + reason
		}
		info.kickReason = kickMsg
		info.kickMu.Unlock()

		// Mark as kick requested
		info.kickRequested.Store(true)

		logger.Info("Sending disconnect to player %s: %s", playerName, kickMsg)

		// Try to send disconnect packet (may not work due to encryption)
		// We try multiple methods for best compatibility
		p.sendDisconnect(info.conn, kickMsg)

		// Wait a bit for the packet to be sent
		time.Sleep(100 * time.Millisecond)

		// Close the RakNet connection - this will cause the client to disconnect
		// In passthrough mode, this is the only reliable way to kick a player
		info.conn.Close()
		kickedCount++
		logger.Info("Kicked player %s from passthrough proxy (reason: %s)", playerName, reason)
		logger.Warn("Note: In passthrough mode, custom kick messages are not supported due to encryption. Client will see 'Disconnected from server'.")
	}
	logger.Info("KickPlayer finished: kickedCount=%d", kickedCount)
	return kickedCount
}

// Stop closes the passthrough proxy.
func (p *PassthroughProxy) Stop() error {
	p.closed.Store(true)

	// Cancel background goroutines (pong refresh, etc.)
	if p.cancel != nil {
		p.cancel()
	}

	// Close all active connections to unblock ReadPacket calls
	p.activeConnsMu.Lock()
	for conn := range p.activeConns {
		conn.Close()
	}
	p.activeConns = make(map[*raknet.Conn]*connInfo)
	p.activeConnsMu.Unlock()

	if p.listener != nil {
		err := p.listener.Close()
		p.wg.Wait()
		return err
	}

	p.wg.Wait()
	return nil
}
