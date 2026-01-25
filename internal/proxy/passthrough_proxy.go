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
	compression   packet.Compression
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
	rawCompat        *RawUDPProxy
	useRawCompat     bool
	passthroughIdleTimeoutOverride time.Duration
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
		lastPongLatency: -1,
	}
}

// SetACLManager sets the ACL manager for access control.
func (p *PassthroughProxy) SetACLManager(aclMgr *acl.ACLManager) {
	p.aclManager = aclMgr
	if p.rawCompat != nil {
		p.rawCompat.SetACLManager(aclMgr)
	}
}

// GetACLManager returns the ACL manager (may be nil if not set).
func (p *PassthroughProxy) GetACLManager() *acl.ACLManager {
	return p.aclManager
}

// SetExternalVerifier sets the external verifier for auth verification.
func (p *PassthroughProxy) SetExternalVerifier(verifier ExternalVerifier) {
	p.externalVerifier = verifier
	if p.rawCompat != nil {
		p.rawCompat.SetExternalVerifier(verifier)
	}
}

// GetExternalVerifier returns the external verifier (may be nil if not set).
func (p *PassthroughProxy) GetExternalVerifier() ExternalVerifier {
	return p.externalVerifier
}

// SetOutboundManager sets the outbound manager for proxy routing.
// Requirements: 2.1
func (p *PassthroughProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
	if p.rawCompat != nil {
		p.rawCompat.SetOutboundManager(outboundMgr)
	}
}

// SetPassthroughIdleTimeoutOverride sets a global override for passthrough idle timeout.
func (p *PassthroughProxy) SetPassthroughIdleTimeoutOverride(timeout time.Duration) {
	p.passthroughIdleTimeoutOverride = timeout
	if p.rawCompat != nil {
		p.rawCompat.SetPassthroughIdleTimeoutOverride(timeout)
	}
}

// GetOutboundManager returns the outbound manager (may be nil if not set).
func (p *PassthroughProxy) GetOutboundManager() OutboundManager {
	return p.outboundMgr
}

// UpdateConfig updates the server configuration.
// This is called when the config file changes to update proxy_outbound and other settings.
func (p *PassthroughProxy) UpdateConfig(cfg *config.ServerConfig) {
	p.config = cfg
	if p.rawCompat != nil {
		p.rawCompat.UpdateConfig(cfg)
	}
	logger.Debug("PassthroughProxy config updated for server %s, proxy_outbound=%s", p.serverID, cfg.GetProxyOutbound())
}

// Start begins listening for RakNet connections.
func (p *PassthroughProxy) Start() error {
	useRawCompat := p.outboundMgr != nil && p.config != nil && !p.config.IsDirectConnection()
	p.useRawCompat = useRawCompat
	if useRawCompat {
		if p.rawCompat == nil {
			p.rawCompat = NewRawUDPProxy(p.serverID, p.config, p.configMgr, p.sessionMgr)
			if p.aclManager != nil {
				p.rawCompat.SetACLManager(p.aclManager)
			}
			if p.externalVerifier != nil {
				p.rawCompat.SetExternalVerifier(p.externalVerifier)
			}
			p.rawCompat.SetOutboundManager(p.outboundMgr)
			if p.passthroughIdleTimeoutOverride > 0 {
				p.rawCompat.SetPassthroughIdleTimeoutOverride(p.passthroughIdleTimeoutOverride)
			}
		} else {
			p.rawCompat.UpdateConfig(p.config)
			if p.aclManager != nil {
				p.rawCompat.SetACLManager(p.aclManager)
			}
			if p.externalVerifier != nil {
				p.rawCompat.SetExternalVerifier(p.externalVerifier)
			}
			p.rawCompat.SetOutboundManager(p.outboundMgr)
			if p.passthroughIdleTimeoutOverride > 0 {
				p.rawCompat.SetPassthroughIdleTimeoutOverride(p.passthroughIdleTimeoutOverride)
			}
		}
		logger.Info("Passthrough proxy using raw UDP compatible forwarding for server %s", p.serverID)
		return p.rawCompat.Start()
	}

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
	// Use longer interval (60s) to reduce CPU usage from QUIC connection creation
	// Each ping creates a new UDP connection through the proxy which consumes resources
	// Especially for Hysteria2, QUIC handshakes are CPU-intensive
	// Track consecutive failures to implement exponential backoff
	consecutiveFailures := 0
	maxBackoffInterval := 5 * time.Minute

	for {
		// Calculate actual wait time based on failures (exponential backoff)
		waitTime := 60 * time.Second
		if consecutiveFailures > 0 {
			// Double the wait time for each failure, up to maxBackoffInterval
			backoff := time.Duration(1<<uint(consecutiveFailures)) * 30 * time.Second
			if backoff > maxBackoffInterval {
				backoff = maxBackoffInterval
			}
			waitTime = backoff
		}

		select {
		case <-ctx.Done():
			// Context cancelled, exit goroutine
			return
		case <-time.After(waitTime):
			if p.closed.Load() {
				return
			}
			// Check if ping was successful
			success := p.fetchRemotePongWithLatencyWithResult()
			if success {
				consecutiveFailures = 0
			} else {
				consecutiveFailures++
				if consecutiveFailures > 5 {
					consecutiveFailures = 5 // Cap at 5 to limit max backoff
				}
				logger.Debug("Pong refresh failed for %s, consecutive failures: %d, next retry in %v",
					p.serverID, consecutiveFailures, waitTime*2)
			}
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
	p.fetchRemotePongWithLatencyWithResult()
}

// fetchRemotePongWithLatencyWithResult fetches pong data through proxy and embeds real latency.
// Returns true if ping was successful, false otherwise.
func (p *PassthroughProxy) fetchRemotePongWithLatencyWithResult() bool {
	serverCfg, exists := p.configMgr.GetServer(p.serverID)
	if !exists {
		return false
	}

	targetAddr := serverCfg.GetTargetAddr()
	var pong []byte
	var latency time.Duration
	var err error

	// If using proxy outbound, ping through proxy with a shorter timeout
	// to avoid blocking for too long on unhealthy nodes
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
		return false
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
	return true
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
	// Use a shorter timeout (8s) to avoid blocking for too long on unhealthy nodes
	// This reduces CPU usage when many nodes are unhealthy
	proxyDialer := NewProxyDialer(p.outboundMgr, p.config, 8*time.Second)

	start := time.Now()

	// Use raknet.Dialer with the proxy dialer to ping
	dialer := raknet.Dialer{
		UpstreamDialer: proxyDialer,
	}

	// Ping through the proxy - simple and direct, no goroutine leak
	pong, err := dialer.Ping(targetAddr)
	latency := time.Since(start)

	if err != nil {
		logger.Debug("PingThroughProxy failed: server=%s target=%s node=%s latency=%v err=%v",
			p.serverID, targetAddr, proxyDialer.GetSelectedNode(), latency, err)
		return nil, latency, err
	}

	logger.Debug("PingThroughProxy ok: server=%s target=%s node=%s latency=%v",
		p.serverID, targetAddr, proxyDialer.GetSelectedNode(), latency)
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
	if p.useRawCompat {
		if p.rawCompat == nil {
			return fmt.Errorf("listener not started")
		}
		return p.rawCompat.Listen(ctx)
	}

	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	// Use a channel to receive connections with context cancellation support
	connChan := make(chan *raknet.Conn, 16)
	errChan := make(chan error, 16)

	// Start a goroutine to accept connections
	go func() {
		backoff := 10 * time.Millisecond
		const maxBackoff = 1 * time.Second

		for {
			if p.closed.Load() {
				return
			}
			conn, err := p.listener.Accept()
			if err != nil {
				if p.closed.Load() {
					return
				}
				if ctx.Err() != nil {
					return
				}

				// Avoid tight looping on repeated accept errors (observed to cause CPU spikes).
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}

				// Don't spam logs: forward to main loop and sleep a bit.
				// Send error but don't block if channel is full
				select {
				case errChan <- err:
				default:
				}
				// If it's a timeout/temporary error, just retry with backoff.
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					time.Sleep(backoff)
					continue
				}
				time.Sleep(backoff)
				continue
			}

			// Reset backoff after a successful accept.
			backoff = 10 * time.Millisecond

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
		loginBytes, err := clientConn.ReadPacket()
		if err != nil {
			return
		}
		compression := compressionFromGamePacket(loginBytes)
		connInf.kickMu.Lock()
		connInf.compression = compression
		connInf.kickMu.Unlock()

		// Send disconnect with custom message
		disabledMsg := serverCfg.DisabledMessage
		if disabledMsg == "" {
			disabledMsg = "服务器暂时关闭，请稍后再试"
		}
		p.sendDisconnect(clientConn, "§c"+disabledMsg, compression)
		logger.Info("Connection rejected (server disabled): client=%s, server=%s", clientAddr, p.serverID)
		return
	}

	// Set deadline for initial handshake
	clientConn.SetDeadline(time.Now().Add(10 * time.Second))

	// Step 1: Read NetworkSettings request packet from client
	networkBytes, err := clientConn.ReadPacket()
	if err != nil {
		logger.Debug("Failed to read network settings from %s: %v", clientAddr, err)
		return
	}
	logger.Debug("Received NetworkSettings request from client (%d bytes)", len(networkBytes))

	// Step 2: Connect to remote server FIRST (before sending NetworkSettings response)
	// This allows us to get the remote server's actual NetworkSettings and forward them
	// to the client, ensuring consistency for anti-cheat systems.
	targetAddr := serverCfg.GetTargetAddr()
	var remoteConn *raknet.Conn

	// Check if we should use proxy outbound
	if p.outboundMgr != nil && !serverCfg.IsDirectConnection() {
		proxyDialer := NewProxyDialer(p.outboundMgr, serverCfg, 15*time.Second)
		dialer := raknet.Dialer{
			UpstreamDialer: proxyDialer,
		}
		proxyConfig := serverCfg.GetProxyOutbound()
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
		logger.Debug("Using direct connection to %s", targetAddr)
		remoteConn, err = raknet.Dial(targetAddr)
	}

	if err != nil {
		if !serverCfg.IsDirectConnection() {
			logger.Warn("Failed to connect to remote %s via proxy %s: %v", targetAddr, serverCfg.GetProxyOutbound(), err)
		} else {
			logger.Error("Failed to connect to remote %s: %v", targetAddr, err)
		}
		// Send a simple disconnect - we can't use sendDisconnect here as compression isn't set up yet
		// Just close the connection, client will see "Unable to connect to world"
		return
	}
	defer remoteConn.Close()

	// Step 3: Forward NetworkSettings request to remote server
	logger.Debug("Forwarding NetworkSettings to remote (%d bytes)", len(networkBytes))
	if _, err := remoteConn.Write(networkBytes); err != nil {
		logger.Error("Failed to forward network settings to remote: %v", err)
		return
	}

	// Step 4: Read NetworkSettings response from remote server
	logger.Debug("Waiting for NetworkSettings response from remote...")
	netResp, err := remoteConn.ReadPacket()
	if err != nil {
		logger.Error("Failed to read network settings from remote: %v", err)
		return
	}
	logger.Debug("Received NetworkSettings response from remote (%d bytes)", len(netResp))

	// Log remote NetworkSettings for debugging
	p.logRemoteNetworkSettings(netResp, clientAddr)

	// Step 5: Forward the EXACT NetworkSettings response from remote to client
	// This ensures client uses the same compression settings as the remote server
	// which is critical for anti-cheat compatibility
	if _, err := clientConn.Write(netResp); err != nil {
		logger.Error("Failed to forward network settings to client: %v", err)
		return
	}
	logger.Debug("Forwarded remote NetworkSettings to client (%d bytes)", len(netResp))

	// Step 6: Read Login packet from client (now using remote server's compression settings)
	loginBytes, err := clientConn.ReadPacket()
	if err != nil {
		logger.Debug("Failed to read login packet from %s: %v", clientAddr, err)
		return
	}

	compression := compressionFromGamePacket(loginBytes)
	connInf.kickMu.Lock()
	connInf.compression = compression
	connInf.kickMu.Unlock()

	// Step 7: Parse login packet to extract player info
	playerName, playerUUID, playerXUID := p.parseLoginPacket(loginBytes)

	// Clean up any existing sessions for this player before creating a new one
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
				p.sendDisconnect(clientConn, reason, compression)
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
				p.sendDisconnect(clientConn, "§c"+reason, compression)
				return
			}
		}
	} else {
		logger.Info("New connection: client=%s -> remote=%s", clientAddr, serverCfg.GetTargetAddr())
	}

	// Clear deadline for normal operation
	clientConn.SetDeadline(time.Time{})

	// Step 8: Forward the Login packet to remote (this contains client's auth JWT)
	loginToSend := loginBytes

	logger.Debug("Forwarding Login packet to remote (%d bytes)", len(loginToSend))
	if _, err := remoteConn.Write(loginToSend); err != nil {
		logger.Error("Failed to forward login to remote: %v", err)
		return
	}
	logger.Debug("Login packet forwarded, starting bidirectional forwarding")

	// Step 9: Start bidirectional forwarding
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
		var lastParseableRemotePacket []byte
		// Use longer timeout to reduce CPU usage from frequent deadline checks
		const readTimeout = 2 * time.Second
		const maxConsecutiveTimeouts = 15 // 30 seconds of no data (2s * 15)
		activityUpdateCounter := 0

		for {
			select {
			case <-connCtx.Done():
				logger.Debug("Context cancelled, stopping remote->client forwarding for %s", clientAddr)
				return
			default:
				// Set read deadline to allow periodic context checking
				remoteConn.SetReadDeadline(time.Now().Add(readTimeout))
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
						// Update activity less frequently (every 5 timeouts = 2.5 seconds)
						activityUpdateCounter++
						if activityUpdateCounter >= 5 {
							gm.UpdateActivity(gid)
							activityUpdateCounter = 0
						}
						continue
					}
					// Log detailed connection close info
					logger.Info("Connection closed (remote->client) for %s: %v", clientAddr, err)
					parsedMsg := ""
					if !logger.IsLevelEnabled(logger.LevelDebug) {
						parsedMsg = p.tryParseDisconnectPacket(lastParseableRemotePacket)
						if parsedMsg != "" {
							logger.Info("[S->C] %s: Disconnect message=%s", clientAddr, parsedMsg)
						}
					}
					if parsedMsg == "" && len(lastParseableRemotePacket) > 0 {
						p.tryParseAndLogPacket(lastParseableRemotePacket, clientAddr, "S->C(last)")
					}
					if parsedMsg == "" {
						connInf.kickMu.Lock()
						compression := connInf.compression
						connInf.kickMu.Unlock()
						p.sendDisconnect(clientConn, "§c连接已断开", compression)
					}
					// Check if it's a RakNet-level disconnect
					errStr := err.Error()
					if strings.Contains(errStr, "closed") {
						logger.Info("RakNet connection was closed by remote server for %s", clientAddr)
					}
					return
				}
				// Reset timeout counter on successful read
				consecutiveTimeouts = 0
				activityUpdateCounter = 0
				// Clear deadline for write operation
				remoteConn.SetReadDeadline(time.Time{})

				if len(pk) >= 3 && pk[0] == packetHeader && (pk[1] == 0x00 || pk[1] == 0x01 || pk[1] == 0xff) {
					lastParseableRemotePacket = append(lastParseableRemotePacket[:0], pk...)
				} else {
					lastParseableRemotePacket = nil
				}

				if logger.IsLevelEnabled(logger.LevelDebug) {
					p.tryParseAndLogPacket(pk, clientAddr, "S->C")
				}

				sess.AddBytesDown(int64(len(pk)))
				sess.UpdateLastSeen() // Keep session alive while data is flowing
				gm.UpdateActivity(gid)
				if _, err := clientConn.Write(pk); err != nil {
					logger.Info("Connection closed (write to client) for %s: %v", clientAddr, err)
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
		// Use longer timeout to reduce CPU usage from frequent deadline checks
		const readTimeout = 2 * time.Second
		const maxConsecutiveTimeouts = 15 // 30 seconds of no data (2s * 15)
		activityUpdateCounter := 0

		for {
			select {
			case <-connCtx.Done():
				logger.Debug("Context cancelled, stopping client->remote forwarding for %s", clientAddr)
				return
			default:
				// Set read deadline to allow periodic context checking
				clientConn.SetReadDeadline(time.Now().Add(readTimeout))
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
						// Update activity less frequently (every 5 timeouts = 2.5 seconds)
						activityUpdateCounter++
						if activityUpdateCounter >= 5 {
							gm.UpdateActivity(gid)
							activityUpdateCounter = 0
						}
						continue
					}
					logger.Info("Connection closed (client->remote) for %s: %v", clientAddr, err)
					return
				}
				// Reset timeout counter on successful read
				consecutiveTimeouts = 0
				activityUpdateCounter = 0
				// Clear deadline for write operation
				clientConn.SetReadDeadline(time.Time{})

				if logger.IsLevelEnabled(logger.LevelDebug) {
					p.tryParseAndLogPacket(pk, clientAddr, "C->S")
				}

				sess.AddBytesUp(int64(len(pk)))
				sess.UpdateLastSeen() // Keep session alive while data is flowing
				gm.UpdateActivity(gid)
				if _, err := remoteConn.Write(pk); err != nil {
					logger.Info("Connection closed (write to remote) for %s: %v", clientAddr, err)
					return
				}
			}
		}
	}()

	// 在线状态保活：每 10 秒检查一次连接是否仍然存活，存活则刷新 LastSeen。
	// 这样即使玩家空闲不发“游戏包”，在线列表也不会在 5 分钟后被 GC 清理。
	if sess != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-connCtx.Done():
					return
				case <-ticker.C:
					sess.UpdateLastSeen()
				}
			}
		}()
	}

	wg.Wait()

	// Log session end and remove session from manager
	snap := sess.Snapshot()
	duration := time.Since(snap.StartTime)
	if playerName != "" {
		logger.Info("Session ended: player=%s, client=%s, duration=%v, up=%d, down=%d",
			playerName, clientAddr, duration, snap.BytesUp, snap.BytesDown)
	} else {
		logger.Info("Session ended: client=%s, duration=%v", clientAddr, duration)
	}

	// Remove session from manager to prevent "already logged in" errors on reconnect
	if err := p.sessionMgr.Remove(clientAddr); err != nil {
		logger.Debug("Failed to remove session for %s: %v", clientAddr, err)
	}
}

// modifyLoginProtocolVersion modifies the protocol version in a Login packet.
// Login packet format: 0xfe + compression_id(1 byte) + compressed_data
// Decompressed format: packet_length(varuint) + packet_id(varuint) + protocol_version(int32 BE) + ...
func (p *PassthroughProxy) modifyLoginProtocolVersion(data []byte, newVersion int32) ([]byte, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	// Check for packet header (0xfe)
	if data[0] != packetHeader {
		return nil, fmt.Errorf("missing packet header")
	}

	compressionID := data[1]
	compressedData := data[2:]

	// Decompress
	var decompressed []byte
	var err error
	switch compressionID {
	case 0x00: // Flate
		decompressed, err = p.decompressFlate(compressedData)
	case 0x01: // Snappy
		decompressed, err = p.decompressSnappy(compressedData)
	default:
		return nil, fmt.Errorf("unknown compression: 0x%x", compressionID)
	}
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	// Parse and modify
	buf := bytes.NewBuffer(decompressed)

	// Read packet length
	var packetLen uint32
	if err := readVaruint32(buf, &packetLen); err != nil {
		return nil, fmt.Errorf("read packet length: %w", err)
	}

	// Read packet ID
	var packetID uint32
	if err := readVaruint32(buf, &packetID); err != nil {
		return nil, fmt.Errorf("read packet ID: %w", err)
	}

	// Verify it's a Login packet (0x01)
	if packetID&0x3FF != 0x01 {
		return nil, fmt.Errorf("not a login packet: 0x%x", packetID)
	}

	// Read original protocol version
	var originalVersion int32
	if err := binary.Read(buf, binary.BigEndian, &originalVersion); err != nil {
		return nil, fmt.Errorf("read protocol version: %w", err)
	}

	logger.Info("Modifying protocol version: %d -> %d", originalVersion, newVersion)

	// Rebuild the packet with new version
	// Calculate positions
	headerLen := len(decompressed) - int(packetLen) // varuint length prefix
	packetIDLen := varuintLen(packetID)

	// Find the position of protocol version in decompressed data
	versionOffset := headerLen + packetIDLen

	// Create modified decompressed data
	modifiedDecompressed := make([]byte, len(decompressed))
	copy(modifiedDecompressed, decompressed)

	// Write new version (big endian int32)
	binary.BigEndian.PutUint32(modifiedDecompressed[versionOffset:versionOffset+4], uint32(newVersion))

	// Recompress
	var recompressed []byte
	switch compressionID {
	case 0x00: // Flate
		recompressed, err = p.compressFlate(modifiedDecompressed)
	case 0x01: // Snappy
		recompressed = snappy.Encode(nil, modifiedDecompressed)
	}
	if err != nil {
		return nil, fmt.Errorf("recompress: %w", err)
	}

	// Build final packet
	result := make([]byte, 2+len(recompressed))
	result[0] = packetHeader
	result[1] = compressionID
	copy(result[2:], recompressed)

	return result, nil
}

// varuintLen returns the length of a varuint32 encoding
func varuintLen(x uint32) int {
	n := 1
	for x >= 0x80 {
		x >>= 7
		n++
	}
	return n
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
	decompressed, err := decompressSnappyLimited(data)
	if err != nil {
		return nil, fmt.Errorf("decompress snappy: %w", err)
	}
	return decompressed, nil
}

// decompressFlate decompresses flate-compressed packet data.
func (p *PassthroughProxy) decompressFlate(data []byte) ([]byte, error) {
	decompressed, err := decompressFlateLimited(data)
	if err != nil {
		return nil, fmt.Errorf("decompress flate: %v", err)
	}
	return decompressed, nil
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
func (p *PassthroughProxy) sendDisconnect(conn *raknet.Conn, message string, compression packet.Compression) {
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

	if compression == nil {
		compression = packet.FlateCompression
	}

	// Try compressed packet first
	if err := p.sendPacket(conn, pk, compression); err != nil {
		logger.Debug("Failed to send compressed disconnect packet: %v", err)
	}

	// Also try uncompressed
	if err := p.sendPacketUncompressed(conn, pk); err != nil {
		logger.Debug("Failed to send uncompressed disconnect packet: %v", err)
	}

	// Try direct raw packet
	if err := p.sendDisconnectDirect(conn, message, compression); err != nil {
		logger.Debug("Failed to send direct disconnect packet: %v", err)
	}

	logger.Info("Sent disconnect packet to client with message: %s", message)
}

// sendDisconnectDirect sends a disconnect packet using raw bytes for maximum compatibility.
func (p *PassthroughProxy) sendDisconnectDirect(conn *raknet.Conn, message string, compression packet.Compression) error {
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

	// Use gophertunnel's Encoder to build the final batch packet with the negotiated compression.
	var outputBuf bytes.Buffer
	encoder := packet.NewEncoder(&outputBuf)
	if compression == nil {
		compression = packet.FlateCompression
	}
	encoder.EnableCompression(compression)
	if err := encoder.Encode([][]byte{packetBuf.Bytes()}); err != nil {
		return fmt.Errorf("encode packet: %w", err)
	}

	_, err := conn.Write(outputBuf.Bytes())
	return err
}

// logRemoteNetworkSettings logs the NetworkSettings response from remote server for debugging.
func (p *PassthroughProxy) logRemoteNetworkSettings(data []byte, clientAddr string) {
	if len(data) < 3 {
		logger.Debug("[remote NetworkSettings] %s: packet too short (%d bytes)", clientAddr, len(data))
		return
	}

	// Log raw hex for debugging
	hexData := fmt.Sprintf("%x", data)
	if len(hexData) > 100 {
		hexData = hexData[:100] + "..."
	}
	logger.Debug("[remote NetworkSettings] %s: raw hex=%s", clientAddr, hexData)

	// Check for packet header (0xfe)
	if data[0] != packetHeader {
		logger.Debug("[remote NetworkSettings] %s: no 0xfe header, first_byte=0x%02x", clientAddr, data[0])
		return
	}

	// The packet should be uncompressed at this stage (before compression is enabled)
	// Format: 0xfe + packet_length(varuint) + packet_id(varuint) + packet_data
	buf := bytes.NewBuffer(data[1:])

	// Read packet length
	var packetLen uint32
	if err := readVaruint32(buf, &packetLen); err != nil {
		logger.Debug("[remote NetworkSettings] %s: failed to read packet length: %v", clientAddr, err)
		return
	}

	// Read packet ID
	var packetID uint32
	if err := readVaruint32(buf, &packetID); err != nil {
		logger.Debug("[remote NetworkSettings] %s: failed to read packet ID: %v", clientAddr, err)
		return
	}

	// NetworkSettings packet ID is 0x8f (143)
	logger.Debug("[remote NetworkSettings] %s: packetLen=%d, packetID=0x%02x", clientAddr, packetLen, packetID)

	if packetID&0x3FF != 0x8f {
		logger.Debug("[remote NetworkSettings] %s: not NetworkSettings packet (expected 0x8f)", clientAddr)
		return
	}

	// Parse NetworkSettings fields
	// CompressionThreshold (uint16 little-endian)
	if buf.Len() < 2 {
		return
	}
	thresholdBytes := buf.Next(2)
	compressionThreshold := uint16(thresholdBytes[0]) | uint16(thresholdBytes[1])<<8

	// CompressionAlgorithm (uint16 little-endian)
	if buf.Len() < 2 {
		return
	}
	algoBytes := buf.Next(2)
	compressionAlgo := uint16(algoBytes[0]) | uint16(algoBytes[1])<<8

	algoName := "Unknown"
	switch compressionAlgo {
	case 0:
		algoName = "Flate"
	case 1:
		algoName = "Snappy"
	case 0xffff:
		algoName = "None"
	}

	logger.Info("[remote NetworkSettings] %s: CompressionThreshold=%d, CompressionAlgorithm=%s(%d)",
		clientAddr, compressionThreshold, algoName, compressionAlgo)

	// Log remaining fields if present
	if buf.Len() > 0 {
		// ClientThrottle (bool)
		clientThrottle, _ := buf.ReadByte()
		// ClientThrottleThreshold (uint8)
		clientThrottleThreshold, _ := buf.ReadByte()
		// ClientThrottleScalar (float32)
		var clientThrottleScalar float32
		if buf.Len() >= 4 {
			scalarBytes := buf.Next(4)
			bits := uint32(scalarBytes[0]) | uint32(scalarBytes[1])<<8 | uint32(scalarBytes[2])<<16 | uint32(scalarBytes[3])<<24
			clientThrottleScalar = float32(bits)
		}
		logger.Debug("[remote NetworkSettings] %s: ClientThrottle=%v, ThrottleThreshold=%d, ThrottleScalar=%f",
			clientAddr, clientThrottle != 0, clientThrottleThreshold, clientThrottleScalar)
	}
}

// sendPlayStatus sends a PlayStatus packet to the client.
func (p *PassthroughProxy) sendPlayStatus(conn *raknet.Conn, status int32) {
	pk := &packet.PlayStatus{
		Status: status,
	}
	if err := p.sendPacket(conn, pk, packet.FlateCompression); err != nil {
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
func (p *PassthroughProxy) sendPacket(conn *raknet.Conn, pk packet.Packet, compression packet.Compression) error {
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
	if compression == nil {
		compression = packet.FlateCompression
	}
	encoder.EnableCompression(compression)

	// Encode the packet (Encoder handles batching, compression, and header)
	if err := encoder.Encode([][]byte{packetBuf.Bytes()}); err != nil {
		return fmt.Errorf("encode packet: %w", err)
	}

	_, err := conn.Write(outputBuf.Bytes())
	return err
}

func compressionFromGamePacket(data []byte) packet.Compression {
	if len(data) < 2 || data[0] != packetHeader {
		return packet.FlateCompression
	}
	switch data[1] {
	case 0x00:
		return packet.FlateCompression
	case 0x01:
		return packet.SnappyCompression
	case 0xff:
		return packet.NopCompression
	default:
		return packet.FlateCompression
	}
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
	if p.useRawCompat && p.rawCompat != nil {
		return p.rawCompat.KickPlayer(playerName, reason)
	}

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
		info.kickMu.Lock()
		compression := info.compression
		info.kickMu.Unlock()
		p.sendDisconnect(info.conn, kickMsg, compression)

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
	if p.useRawCompat && p.rawCompat != nil {
		return p.rawCompat.Stop()
	}

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

// Packet IDs for Minecraft Bedrock Edition
const (
	packetIDLogin                   = 0x01
	packetIDPlayStatus              = 0x02
	packetIDServerToClientHandshake = 0x03
	packetIDClientToServerHandshake = 0x04
	packetIDDisconnect              = 0x05
	packetIDResourcePacksInfo       = 0x06
	packetIDResourcePackStack       = 0x07
	packetIDResourcePackResponse    = 0x08
	packetIDText                    = 0x09
	packetIDSetTime                 = 0x0a
	packetIDStartGame               = 0x0b
	packetIDAddPlayer               = 0x0c
	packetIDAddActor                = 0x0d
	packetIDRemoveActor             = 0x0e
	packetIDAddItemActor            = 0x0f
	packetIDTakeItemActor           = 0x11
	packetIDMoveActorAbsolute       = 0x12
	packetIDMovePlayer              = 0x13
	packetIDUpdateBlock             = 0x15
	packetIDLevelEvent              = 0x19
	packetIDBlockEvent              = 0x1a
	packetIDActorEvent              = 0x1b
	packetIDMobEffect               = 0x1c
	packetIDUpdateAttributes        = 0x1d
	packetIDTransfer                = 0x55 // Transfer packet - server tells client to connect elsewhere
	packetIDSetTitle                = 0x58 // Title/subtitle display
	packetIDToastRequest            = 0xba // Toast notification
)

// PlayStatus codes
const (
	playStatusLoginSuccess             = 0
	playStatusLoginFailedClient        = 1
	playStatusLoginFailedServer        = 2
	playStatusPlayerSpawn              = 3
	playStatusLoginFailedInvalidTenant = 4
	playStatusLoginFailedVanillaEdu    = 5
	playStatusLoginFailedEduVanilla    = 6
	playStatusLoginFailedServerFull    = 7
	playStatusLoginFailedEditorVanilla = 8
	playStatusLoginFailedVanillaEditor = 9
)

// tryParseAndLogPacket attempts to parse and log important packets before encryption.
// This helps debug connection issues by showing what the server sends.
func (p *PassthroughProxy) tryParseAndLogPacket(data []byte, clientAddr, direction string) {
	if len(data) < 3 {
		return
	}

	// Check for packet header (0xfe)
	if data[0] != packetHeader {
		logger.Debug("[%s] %s: Packet without 0xfe header, first_byte=0x%02x, len=%d", direction, clientAddr, data[0], len(data))
		return
	}

	// Get compression algorithm ID (second byte)
	compressionID := data[1]
	compressedData := data[2:]

	var decompressed []byte
	var err error

	switch compressionID {
	case 0x00: // Flate compression
		decompressed, err = p.decompressFlate(compressedData)
		if err != nil {
			logger.Debug("[%s] %s: Flate decompression failed: %v", direction, clientAddr, err)
			return
		}
	case 0x01: // Snappy compression
		decompressed, err = p.decompressSnappy(compressedData)
		if err != nil {
			logger.Debug("[%s] %s: Snappy decompression failed: %v", direction, clientAddr, err)
			return
		}
	case 0xff: // No compression
		decompressed = compressedData
	default:
		// Encrypted packet, can't parse - already logged elsewhere
		return
	}

	// Parse batch format
	buf := bytes.NewBuffer(decompressed)
	for buf.Len() > 0 {
		var packetLen uint32
		if err := readVaruint32(buf, &packetLen); err != nil {
			break
		}
		if packetLen == 0 || packetLen > uint32(buf.Len()) {
			break
		}

		packetData := buf.Next(int(packetLen))
		if len(packetData) < 1 {
			continue
		}

		// Parse packet ID
		packetBuf := bytes.NewBuffer(packetData)
		var packetID uint32
		if err := readVaruint32(packetBuf, &packetID); err != nil {
			continue
		}

		// Mask off sender/target sub-client IDs
		packetID = packetID & 0x3FF

		switch packetID {
		case packetIDPlayStatus:
			p.logPlayStatusPacket(packetBuf, clientAddr, direction)
		case packetIDServerToClientHandshake:
			logger.Info("[%s] %s: ServerToClientHandshake (encryption starting)", direction, clientAddr)
			// Log the JWT token for debugging
			if packetBuf.Len() > 0 {
				var tokenLen uint32
				if err := readVaruint32(packetBuf, &tokenLen); err == nil && tokenLen > 0 && tokenLen <= uint32(packetBuf.Len()) {
					token := string(packetBuf.Next(int(tokenLen)))
					if len(token) > 100 {
						token = token[:100] + "..."
					}
					logger.Debug("[%s] %s: ServerToClientHandshake JWT (first 100 chars): %s", direction, clientAddr, token)
				}
			}
		case packetIDClientToServerHandshake:
			logger.Info("[%s] %s: ClientToServerHandshake (client encryption response)", direction, clientAddr)
		case packetIDDisconnect:
			p.logDisconnectPacket(packetBuf, clientAddr, direction)
		case packetIDResourcePacksInfo:
			p.logResourcePacksInfo(packetBuf, clientAddr, direction)
		case packetIDResourcePackStack:
			logger.Info("[%s] %s: ResourcePackStack", direction, clientAddr)
		case packetIDStartGame:
			p.logStartGame(packetBuf, clientAddr, direction)
		case packetIDText:
			p.logTextPacket(packetBuf, clientAddr, direction)
		case packetIDTransfer:
			p.logTransferPacket(packetBuf, clientAddr, direction)
		case packetIDSetTitle:
			p.logSetTitlePacket(packetBuf, clientAddr, direction)
		case packetIDToastRequest:
			p.logToastRequest(packetBuf, clientAddr, direction)
		case packetIDLogin:
			logger.Info("[%s] %s: Login packet", direction, clientAddr)
		case packetIDResourcePackResponse:
			logger.Debug("[%s] %s: ResourcePackResponse", direction, clientAddr)
		default:
			// Log unknown packets with their ID for debugging
			if packetID < 0x100 {
				logger.Debug("[%s] %s: Packet ID=0x%02x, len=%d", direction, clientAddr, packetID, len(packetData))
			}
		}
	}
}

// logPlayStatusPacket logs PlayStatus packet details.
func (p *PassthroughProxy) logPlayStatusPacket(buf *bytes.Buffer, clientAddr, direction string) {
	if buf.Len() < 4 {
		return
	}

	// PlayStatus is a big-endian int32
	statusBytes := buf.Next(4)
	status := int32(statusBytes[0])<<24 | int32(statusBytes[1])<<16 | int32(statusBytes[2])<<8 | int32(statusBytes[3])

	var statusStr string
	switch status {
	case playStatusLoginSuccess:
		statusStr = "LoginSuccess"
	case playStatusLoginFailedClient:
		statusStr = "LoginFailedClient (客户端版本过旧)"
	case playStatusLoginFailedServer:
		statusStr = "LoginFailedServer (服务器版本过旧)"
	case playStatusPlayerSpawn:
		statusStr = "PlayerSpawn"
	case playStatusLoginFailedInvalidTenant:
		statusStr = "LoginFailedInvalidTenant (无效租户)"
	case playStatusLoginFailedVanillaEdu:
		statusStr = "LoginFailedVanillaEdu (教育版不兼容)"
	case playStatusLoginFailedEduVanilla:
		statusStr = "LoginFailedEduVanilla (教育版不兼容)"
	case playStatusLoginFailedServerFull:
		statusStr = "LoginFailedServerFull (服务器已满)"
	case playStatusLoginFailedEditorVanilla:
		statusStr = "LoginFailedEditorVanilla (编辑器不兼容)"
	case playStatusLoginFailedVanillaEditor:
		statusStr = "LoginFailedVanillaEditor (编辑器不兼容)"
	default:
		statusStr = fmt.Sprintf("Unknown(%d)", status)
	}

	logger.Info("[%s] %s: PlayStatus = %s", direction, clientAddr, statusStr)
}

// logDisconnectPacket logs Disconnect packet details.
func (p *PassthroughProxy) logDisconnectPacket(buf *bytes.Buffer, clientAddr, direction string) {
	// Read reason code
	var reason uint32
	if err := readVaruint32(buf, &reason); err != nil {
		logger.Info("[%s] %s: Disconnect (failed to read reason)", direction, clientAddr)
		return
	}

	// Read hide screen flag
	hideScreen, err := buf.ReadByte()
	if err != nil {
		logger.Info("[%s] %s: Disconnect reason=%d", direction, clientAddr, reason)
		return
	}

	if hideScreen != 0 {
		logger.Info("[%s] %s: Disconnect reason=%d (screen hidden)", direction, clientAddr, reason)
		return
	}

	// Read message
	var msgLen uint32
	if err := readVaruint32(buf, &msgLen); err != nil || msgLen == 0 || msgLen > uint32(buf.Len()) {
		logger.Info("[%s] %s: Disconnect reason=%d", direction, clientAddr, reason)
		return
	}

	message := string(buf.Next(int(msgLen)))
	logger.Info("[%s] %s: Disconnect reason=%d, message=%s", direction, clientAddr, reason, message)
}

// logTextPacket logs Text packet details (chat messages, titles, etc).
func (p *PassthroughProxy) logTextPacket(buf *bytes.Buffer, clientAddr, direction string) {
	if buf.Len() < 1 {
		return
	}

	// Read text type
	textType, err := buf.ReadByte()
	if err != nil {
		return
	}

	var typeStr string
	switch textType {
	case 0:
		typeStr = "Raw"
	case 1:
		typeStr = "Chat"
	case 2:
		typeStr = "Translation"
	case 3:
		typeStr = "Popup"
	case 4:
		typeStr = "JukeboxPopup"
	case 5:
		typeStr = "Tip"
	case 6:
		typeStr = "System"
	case 7:
		typeStr = "Whisper"
	case 8:
		typeStr = "Announcement"
	case 9:
		typeStr = "ObjectWhisper"
	case 10:
		typeStr = "Object"
	case 11:
		typeStr = "ObjectAnnouncement"
	default:
		typeStr = fmt.Sprintf("Unknown(%d)", textType)
	}

	// Read needs translation flag
	_, _ = buf.ReadByte()

	// For most types, read source name first
	if textType == 1 || textType == 7 || textType == 8 {
		var sourceLen uint32
		if err := readVaruint32(buf, &sourceLen); err == nil && sourceLen <= uint32(buf.Len()) {
			buf.Next(int(sourceLen)) // skip source name
		}
	}

	// Read message
	var msgLen uint32
	if err := readVaruint32(buf, &msgLen); err != nil || msgLen == 0 || msgLen > uint32(buf.Len()) {
		logger.Debug("[%s] %s: Text type=%s", direction, clientAddr, typeStr)
		return
	}

	message := string(buf.Next(int(msgLen)))
	if len(message) > 100 {
		message = message[:100] + "..."
	}
	logger.Info("[%s] %s: Text type=%s, message=%s", direction, clientAddr, typeStr, message)
}

// logTransferPacket logs Transfer packet details (server telling client to connect elsewhere)
func (p *PassthroughProxy) logTransferPacket(buf *bytes.Buffer, clientAddr, direction string) {
	// Read address
	var addrLen uint32
	if err := readVaruint32(buf, &addrLen); err != nil || addrLen == 0 || addrLen > uint32(buf.Len()) {
		logger.Info("[%s] %s: Transfer (failed to read address)", direction, clientAddr)
		return
	}
	address := string(buf.Next(int(addrLen)))

	// Read port (uint16 LE)
	if buf.Len() < 2 {
		logger.Info("[%s] %s: Transfer to %s (no port)", direction, clientAddr, address)
		return
	}
	portBytes := buf.Next(2)
	port := uint16(portBytes[0]) | uint16(portBytes[1])<<8

	logger.Info("[%s] %s: Transfer to %s:%d", direction, clientAddr, address, port)
}

// logSetTitlePacket logs SetTitle packet details (title/subtitle display)
func (p *PassthroughProxy) logSetTitlePacket(buf *bytes.Buffer, clientAddr, direction string) {
	// Read title type
	var titleType int32
	if err := readVarint32(buf, &titleType); err != nil {
		logger.Info("[%s] %s: SetTitle (failed to read type)", direction, clientAddr)
		return
	}

	typeNames := map[int32]string{
		0: "Clear",
		1: "Reset",
		2: "SetTitle",
		3: "SetSubtitle",
		4: "SetActionBar",
		5: "SetDurations",
		6: "TitleTextObject",
		7: "SubtitleTextObject",
		8: "ActionbarTextObject",
	}

	typeName := typeNames[titleType]
	if typeName == "" {
		typeName = fmt.Sprintf("Unknown(%d)", titleType)
	}

	// Read text
	var textLen uint32
	if err := readVaruint32(buf, &textLen); err != nil || textLen == 0 || textLen > uint32(buf.Len()) {
		logger.Info("[%s] %s: SetTitle type=%s", direction, clientAddr, typeName)
		return
	}
	text := string(buf.Next(int(textLen)))
	if len(text) > 100 {
		text = text[:100] + "..."
	}

	logger.Info("[%s] %s: SetTitle type=%s, text=%s", direction, clientAddr, typeName, text)
}

// logToastRequest logs ToastRequest packet details
func (p *PassthroughProxy) logToastRequest(buf *bytes.Buffer, clientAddr, direction string) {
	// Read title
	var titleLen uint32
	if err := readVaruint32(buf, &titleLen); err != nil || titleLen > uint32(buf.Len()) {
		logger.Info("[%s] %s: ToastRequest (failed to read title)", direction, clientAddr)
		return
	}
	title := string(buf.Next(int(titleLen)))

	// Read content
	var contentLen uint32
	if err := readVaruint32(buf, &contentLen); err != nil || contentLen > uint32(buf.Len()) {
		logger.Info("[%s] %s: ToastRequest title=%s", direction, clientAddr, title)
		return
	}
	content := string(buf.Next(int(contentLen)))

	if len(title) > 50 {
		title = title[:50] + "..."
	}
	if len(content) > 100 {
		content = content[:100] + "..."
	}

	logger.Info("[%s] %s: ToastRequest title=%s, content=%s", direction, clientAddr, title, content)
}

// logResourcePacksInfo logs ResourcePacksInfo packet details
func (p *PassthroughProxy) logResourcePacksInfo(buf *bytes.Buffer, clientAddr, direction string) {
	// Read must accept flag
	mustAccept, err := buf.ReadByte()
	if err != nil {
		logger.Info("[%s] %s: ResourcePacksInfo", direction, clientAddr)
		return
	}

	// Read has addons flag
	hasAddons, _ := buf.ReadByte()

	// Read has scripts flag
	hasScripts, _ := buf.ReadByte()

	// Read behavior pack count
	var behaviorPackCount uint16
	if buf.Len() >= 2 {
		b := buf.Next(2)
		behaviorPackCount = uint16(b[0]) | uint16(b[1])<<8
	}

	// Read resource pack count
	var resourcePackCount uint16
	if buf.Len() >= 2 {
		b := buf.Next(2)
		resourcePackCount = uint16(b[0]) | uint16(b[1])<<8
	}

	logger.Info("[%s] %s: ResourcePacksInfo mustAccept=%v, hasAddons=%v, hasScripts=%v, behaviorPacks=%d, resourcePacks=%d",
		direction, clientAddr, mustAccept != 0, hasAddons != 0, hasScripts != 0, behaviorPackCount, resourcePackCount)
}

// logStartGame logs StartGame packet details
func (p *PassthroughProxy) logStartGame(buf *bytes.Buffer, clientAddr, direction string) {
	// StartGame is a very complex packet, just log basic info
	// Read entity unique ID (varint64)
	var entityUniqueID int64
	if err := readVarint64(buf, &entityUniqueID); err != nil {
		logger.Info("[%s] %s: StartGame (player entering world)", direction, clientAddr)
		return
	}

	// Read entity runtime ID (varuint64)
	var entityRuntimeID uint64
	if err := readVaruint64(buf, &entityRuntimeID); err != nil {
		logger.Info("[%s] %s: StartGame entityUniqueID=%d", direction, clientAddr, entityUniqueID)
		return
	}

	// Read player game mode (varint32)
	var playerGameMode int32
	if err := readVarint32(buf, &playerGameMode); err != nil {
		logger.Info("[%s] %s: StartGame entityUniqueID=%d, runtimeID=%d", direction, clientAddr, entityUniqueID, entityRuntimeID)
		return
	}

	gameModeNames := map[int32]string{
		0: "Survival",
		1: "Creative",
		2: "Adventure",
		3: "Spectator",
	}
	gameModeName := gameModeNames[playerGameMode]
	if gameModeName == "" {
		gameModeName = fmt.Sprintf("Unknown(%d)", playerGameMode)
	}

	logger.Info("[%s] %s: StartGame entityUniqueID=%d, runtimeID=%d, gameMode=%s",
		direction, clientAddr, entityUniqueID, entityRuntimeID, gameModeName)
}

// readVarint32 reads a variable-length signed int32
func readVarint32(r io.ByteReader, x *int32) error {
	var ux uint32
	if err := readVaruint32(r, &ux); err != nil {
		return err
	}
	*x = int32(ux>>1) ^ -int32(ux&1)
	return nil
}

// readVarint64 reads a variable-length signed int64
func readVarint64(r io.ByteReader, x *int64) error {
	var ux uint64
	if err := readVaruint64(r, &ux); err != nil {
		return err
	}
	*x = int64(ux>>1) ^ -int64(ux&1)
	return nil
}

// readVaruint64 reads a variable-length uint64
func readVaruint64(r io.ByteReader, x *uint64) error {
	var v uint64
	for i := uint(0); i < 70; i += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		v |= uint64(b&0x7f) << i
		if b&0x80 == 0 {
			*x = v
			return nil
		}
	}
	return fmt.Errorf("varuint64 overflow")
}

// tryParseDisconnectPacket attempts to parse a packet as a Disconnect packet.
// Returns the disconnect message if it's a disconnect packet, empty string otherwise.
// This is used to log the reason when the remote server disconnects the player.
//
// NOTE: In passthrough mode, packets after the login handshake are encrypted between
// the client and remote server. We cannot decrypt them, so this function will only
// work for unencrypted disconnect packets (rare). The packet is still forwarded to
// the client who can decrypt and display the message.
func (p *PassthroughProxy) tryParseDisconnectPacket(data []byte) string {
	if len(data) < 3 {
		return ""
	}

	// Check for packet header (0xfe)
	if data[0] != packetHeader {
		// Log raw packet info for debugging
		logger.Debug("Packet without 0xfe header, first bytes: %x (len=%d)", data[:min(10, len(data))], len(data))
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
	case 0xff: // No compression (used in some cases)
		decompressed = compressedData
	default:
		// This might be an encrypted packet - log for debugging
		logger.Debug("Unknown compression ID 0x%x, packet may be encrypted (len=%d)", compressionID, len(data))
		return ""
	}

	if err != nil {
		// Decompression failed - packet might be encrypted
		logger.Debug("Decompression failed (packet may be encrypted): %v", err)
		return ""
	}

	// Parse the decompressed data to find disconnect packet
	return p.parseDisconnectData(decompressed)
}

// parseDisconnectData parses decompressed packet data to extract disconnect message.
// Supports both single packet and batch packet formats.
func (p *PassthroughProxy) parseDisconnectData(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	buf := bytes.NewBuffer(data)

	// Try to parse as batch format (length-prefixed packets)
	for buf.Len() > 0 {
		// Read packet length (varuint32)
		var packetLen uint32
		if err := readVaruint32(buf, &packetLen); err != nil {
			break
		}

		if packetLen == 0 || packetLen > uint32(buf.Len()) {
			break
		}

		// Read the packet data
		packetData := buf.Next(int(packetLen))
		if len(packetData) < 1 {
			continue
		}

		// Parse this individual packet
		msg := p.parseSingleDisconnectPacket(packetData)
		if msg != "" {
			return msg
		}
	}

	return ""
}

// parseSingleDisconnectPacket parses a single packet (without length prefix) to extract disconnect message.
func (p *PassthroughProxy) parseSingleDisconnectPacket(data []byte) string {
	if len(data) < 1 {
		return ""
	}

	buf := bytes.NewBuffer(data)

	// Read packet ID (varuint32)
	var packetID uint32
	if err := readVaruint32(buf, &packetID); err != nil {
		return ""
	}

	// Disconnect packet ID is 0x05
	// The packet ID may have sender/target sub-client IDs in upper bits
	if packetID&0x3FF != 0x05 {
		return ""
	}

	logger.Debug("Found disconnect packet, remaining bytes: %d", buf.Len())

	// Read disconnect reason (varint32) - NOT ZigZag encoded in newer versions
	// Try reading as unsigned varuint32 first
	var reasonU uint32
	if err := readVaruint32(buf, &reasonU); err != nil {
		logger.Debug("Failed to read disconnect reason: %v", err)
		return ""
	}
	reason := int32(reasonU)
	logger.Debug("Disconnect reason code: %d", reason)

	// Read hide disconnect screen (bool)
	hideScreen, err := buf.ReadByte()
	if err != nil {
		logger.Debug("Failed to read hide screen flag: %v", err)
		return fmt.Sprintf("(reason code: %d)", reason)
	}
	logger.Debug("Hide disconnect screen: %v", hideScreen != 0)

	// If hide screen is true, there's no message
	if hideScreen != 0 {
		return fmt.Sprintf("(reason code: %d, screen hidden)", reason)
	}

	// Read message length (varuint32)
	var msgLen uint32
	if err := readVaruint32(buf, &msgLen); err != nil {
		logger.Debug("Failed to read message length: %v", err)
		return fmt.Sprintf("(reason code: %d)", reason)
	}
	logger.Debug("Message length: %d, remaining: %d", msgLen, buf.Len())

	if msgLen == 0 {
		return fmt.Sprintf("(reason code: %d, empty message)", reason)
	}

	if msgLen > uint32(buf.Len()) {
		logger.Debug("Message length %d exceeds remaining buffer %d", msgLen, buf.Len())
		return fmt.Sprintf("(reason code: %d)", reason)
	}

	// Read message
	msgBytes := buf.Next(int(msgLen))
	message := string(msgBytes)
	logger.Debug("Disconnect message: %s", message)

	// Also try to read filtered message if present
	if buf.Len() > 0 {
		var filteredLen uint32
		if err := readVaruint32(buf, &filteredLen); err == nil && filteredLen > 0 && filteredLen <= uint32(buf.Len()) {
			filteredBytes := buf.Next(int(filteredLen))
			filteredMsg := string(filteredBytes)
			if filteredMsg != "" && filteredMsg != message {
				logger.Debug("Filtered message: %s", filteredMsg)
			}
		}
	}

	if message == "" {
		return fmt.Sprintf("(reason code: %d)", reason)
	}

	return message
}
