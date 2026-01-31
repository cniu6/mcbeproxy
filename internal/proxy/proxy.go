// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/auth"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	proxyerrors "mcpeserverproxy/internal/errors"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/protocol"
	"mcpeserverproxy/internal/session"
)

// Listener is an interface for proxy listeners (both transparent and RakNet).
type Listener interface {
	Start() error
	Listen(ctx context.Context) error
	Stop() error
}

const defaultAutoPingIntervalMinutes = 10

// ProxyServer is the main entry point that integrates all proxy components.
// It manages UDP listeners, session management, configuration, and database persistence.
type ProxyServer struct {
	config                 *config.GlobalConfig
	configMgr              *config.ConfigManager
	sessionMgr             *session.SessionManager
	db                     *db.Database
	sessionRepo            *db.SessionRepository
	playerRepo             *db.PlayerRepository
	bufferPool             *BufferPool
	forwarder              *Forwarder
	errorHandler           *proxyerrors.ErrorHandler
	aclManager             *acl.ACLManager                    // ACL manager for access control
	externalVerifier       *auth.ExternalVerifier             // External auth verifier
	outboundMgr            OutboundManager                    // Outbound manager for proxy routing
	proxyOutboundConfigMgr *config.ProxyOutboundConfigManager // Proxy outbound config manager
	proxyPortConfigMgr     *config.ProxyPortConfigManager     // Proxy port config manager
	proxyPortManager       *ProxyPortManager                  // Proxy port runtime manager
	listeners              map[string]Listener                // serverID -> listener (can be UDPListener or RakNetProxy)
	listenersMu            sync.RWMutex
	ctx                    context.Context
	cancel                 context.CancelFunc
	wg                     sync.WaitGroup
	running                bool
	runningMu              sync.RWMutex
}

// NewProxyServer creates a new ProxyServer with all components initialized.
// Requirements: 8.1 - Initialize OutboundManager in ProxyServer
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
	// 使用服务器配置的 idle_timeout 覆盖会话空闲超时（可被全局 passthrough 覆盖）
	sessionMgr.SetIdleTimeoutFunc(func(sess *session.Session) time.Duration {
		if sess == nil || configMgr == nil {
			return 0
		}
		serverCfg, ok := configMgr.GetServer(sess.ServerID)
		if ok && strings.EqualFold(serverCfg.GetProxyMode(), "passthrough") {
			if globalConfig != nil && globalConfig.PassthroughIdleTimeout > 0 {
				return time.Duration(globalConfig.PassthroughIdleTimeout) * time.Second
			}
		}
		if !ok || serverCfg.IdleTimeout <= 0 {
			return 0
		}
		return time.Duration(serverCfg.IdleTimeout) * time.Second
	})

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

	// Create proxy outbound config manager
	// Requirements: 8.1
	proxyOutboundConfigMgr := config.NewProxyOutboundConfigManager("proxy_outbounds.json")
	if err := proxyOutboundConfigMgr.Load(); err != nil {
		logger.Warn("Failed to load proxy outbound config: %v", err)
		// Continue without proxy outbounds - they can be added via API
	}

	// Create outbound manager and sync with config
	// Requirements: 8.1
	outboundMgr := NewOutboundManager(configMgr)
	for _, outbound := range proxyOutboundConfigMgr.GetAllOutbounds() {
		if err := outboundMgr.AddOutbound(outbound); err != nil {
			logger.Warn("Failed to add outbound %s to manager: %v", outbound.Name, err)
		}
	}

	// Create proxy port config manager
	proxyPortConfigMgr := config.NewProxyPortConfigManager("proxy_ports.json")
	if err := proxyPortConfigMgr.Load(); err != nil {
		logger.Warn("Failed to load proxy port config: %v", err)
	}
	proxyPortManager := NewProxyPortManager(proxyPortConfigMgr, outboundMgr)

	// Set up session end callback for persistence
	sessionMgr.OnSessionEnd = func(sess *session.Session) {
		persistSession(sess, sessionRepo, playerRepo, errorHandler)
	}

	return &ProxyServer{
		config:                 globalConfig,
		configMgr:              configMgr,
		sessionMgr:             sessionMgr,
		db:                     database,
		sessionRepo:            sessionRepo,
		playerRepo:             playerRepo,
		bufferPool:             bufferPool,
		forwarder:              forwarder,
		errorHandler:           errorHandler,
		externalVerifier:       externalVerifier,
		outboundMgr:            outboundMgr,
		proxyOutboundConfigMgr: proxyOutboundConfigMgr,
		proxyPortConfigMgr:     proxyPortConfigMgr,
		proxyPortManager:       proxyPortManager,
		listeners:              make(map[string]Listener),
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

// SetOutboundManager sets the outbound manager for proxy routing.
// This must be called before Start() to enable proxy outbound routing.
// Requirements: 2.1
func (p *ProxyServer) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

// GetOutboundManager returns the outbound manager (may be nil if not set).
func (p *ProxyServer) GetOutboundManager() OutboundManager {
	return p.outboundMgr
}

// GetProxyOutboundConfigManager returns the proxy outbound config manager.
func (p *ProxyServer) GetProxyOutboundConfigManager() *config.ProxyOutboundConfigManager {
	return p.proxyOutboundConfigMgr
}

// GetProxyPortConfigManager returns the proxy port config manager.
func (p *ProxyServer) GetProxyPortConfigManager() *config.ProxyPortConfigManager {
	return p.proxyPortConfigMgr
}

// persistSession saves session data to the database when a session ends.
// Uses retry logic for database operations per requirement 9.3.
func persistSession(sess *session.Session, sessionRepo *db.SessionRepository, playerRepo *db.PlayerRepository, errorHandler *proxyerrors.ErrorHandler) {
	// Create session record
	endTime := time.Now()
	snap := sess.Snapshot()
	duration := endTime.Sub(snap.StartTime)
	record := &session.SessionRecord{
		ID:          snap.ID,
		ClientAddr:  snap.ClientAddr,
		ServerID:    snap.ServerID,
		UUID:        snap.UUID,
		DisplayName: snap.DisplayName,
		BytesUp:     snap.BytesUp,
		BytesDown:   snap.BytesDown,
		StartTime:   snap.StartTime,
		EndTime:     endTime,
	}

	// Log player disconnect event (requirement 9.5)
	if snap.UUID != "" {
		logger.LogPlayerDisconnect(snap.UUID, snap.DisplayName, snap.ServerID, snap.ClientAddr, duration, snap.BytesUp, snap.BytesDown)
	}
	logger.LogSessionEnded(snap.ClientAddr, snap.ServerID, duration)

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
	if snap.DisplayName != "" {
		totalBytes := snap.BytesUp + snap.BytesDown

		// Try to get existing player by display name
		player, err := playerRepo.GetByDisplayName(snap.DisplayName)
		if err != nil {
			// Create new player record with retry
			player = &db.PlayerRecord{
				DisplayName:   snap.DisplayName,
				UUID:          snap.UUID,
				XUID:          snap.XUID,
				FirstSeen:     snap.StartTime,
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
				return playerRepo.UpdateStats(snap.DisplayName, totalBytes, duration)
			})
			if err != nil {
				logger.LogDatabaseError("update player stats", err)
			}
		}
	}
}

// Start starts the proxy server and all configured listeners.
// Requirements: 8.1 - Initialize sing-box outbound instances on start
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

	// Initialize sing-box outbound instances for all configured proxy outbounds
	// Requirements: 8.1
	if p.outboundMgr != nil {
		if err := p.outboundMgr.Start(); err != nil {
			logger.Error("Failed to start outbound manager: %v", err)
		} else {
			logger.Info("Outbound manager started")
		}
	}

	// Start garbage collection for idle sessions
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		// Track this goroutine as a background task (expected to run for app lifetime)
		gm := monitor.GetGoroutineManager()
		gid := gm.TrackBackground("session-gc", "proxy-server", "Session garbage collector", p.cancel)
		defer gm.Untrack(gid)
		p.sessionMgr.GarbageCollect(p.ctx)
	}()

	// Start DNS refresh
	p.configMgr.StartDNSRefresh(p.ctx, 60*time.Second)

	// Start config file watcher
	if err := p.configMgr.Watch(p.ctx); err != nil {
		log.Printf("Warning: failed to start config watcher: %v", err)
	}

	// Start proxy outbound config file watcher
	// Requirements: 8.2
	if p.proxyOutboundConfigMgr != nil {
		if err := p.proxyOutboundConfigMgr.Watch(p.ctx); err != nil {
			log.Printf("Warning: failed to start proxy outbound config watcher: %v", err)
		}

		// Set up proxy outbound config change callback
		// Requirements: 8.2
		p.proxyOutboundConfigMgr.SetOnChange(func() {
			if err := p.reloadProxyOutbounds(); err != nil {
				logger.Error("Failed to reload proxy outbounds after config change: %v", err)
			}
		})
	}

	// Start proxy port config file watcher
	if p.proxyPortConfigMgr != nil {
		if err := p.proxyPortConfigMgr.Watch(p.ctx); err != nil {
			log.Printf("Warning: failed to start proxy port config watcher: %v", err)
		}
		p.proxyPortConfigMgr.SetOnChange(func() {
			if err := p.ReloadProxyPorts(); err != nil {
				logger.Error("Failed to reload proxy ports after config change: %v", err)
			}
		})
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

	// Start auto ping scheduler (per-server, per-node latency cache)
	p.startAutoPingScheduler()

	// Start proxy ports (local HTTP/SOCKS) if enabled
	if p.proxyPortManager != nil {
		if err := p.proxyPortManager.Start(p.config != nil && p.config.ProxyPortsEnabled); err != nil {
			logger.Error("Failed to start proxy ports: %v", err)
		}
	}

	logger.Info("Proxy server started with %d listeners", p.listenerCount())
	return nil
}

func (p *ProxyServer) startAutoPingScheduler() {
	if p.configMgr == nil || p.outboundMgr == nil {
		return
	}
	if p.ctx == nil {
		return
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		gm := monitor.GetGoroutineManager()
		gid := gm.TrackBackground("auto-ping", "proxy-server", "Auto ping scheduler", p.cancel)
		defer gm.Untrack(gid)

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		lastRun := make(map[string]time.Time)

		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
			}

			servers := p.configMgr.GetAllServers()
			now := time.Now()

			for _, serverCfg := range servers {
				if serverCfg == nil {
					continue
				}
				if !serverCfg.AutoPingEnabled {
					continue
				}
				intervalMin := serverCfg.AutoPingIntervalMinutes
				if intervalMin <= 0 {
					intervalMin = defaultAutoPingIntervalMinutes
				}

				if t, ok := lastRun[serverCfg.ID]; ok {
					if now.Sub(t) < time.Duration(intervalMin)*time.Minute {
						continue
					}
				}

				p.pingAllNodesForServer(serverCfg)
				lastRun[serverCfg.ID] = now
			}
		}
	}()
}

func (p *ProxyServer) pingAllNodesForServer(serverCfg *config.ServerConfig) {
	if serverCfg == nil || p.outboundMgr == nil {
		return
	}

	proxyOutbound := strings.TrimSpace(serverCfg.GetProxyOutbound())
	if proxyOutbound == "" || proxyOutbound == "direct" {
		return
	}

	targetAddr := serverCfg.GetTargetAddr()
	destAddr, err := resolveUDPAddr(targetAddr)
	if err != nil {
		logger.Debug("auto ping resolve target failed: server=%s target=%s err=%v", serverCfg.ID, targetAddr, err)
		return
	}

	sortBy := serverCfg.GetLoadBalanceSort()
	if sortBy == "" {
		sortBy = config.LoadBalanceSortUDP
	}

	nodeNames := p.getServerNodeNames(serverCfg)
	if len(nodeNames) == 0 {
		return
	}

	for _, nodeName := range nodeNames {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		latencyMs := p.pingServerThroughNode(serverCfg.ID, nodeName, targetAddr, destAddr)
		if latencyMs > 0 {
			p.outboundMgr.SetServerNodeLatency(serverCfg.ID, nodeName, sortBy, latencyMs)
		} else {
			p.outboundMgr.SetServerNodeLatency(serverCfg.ID, nodeName, sortBy, 0)
		}
	}
}

func (p *ProxyServer) getServerNodeNames(serverCfg *config.ServerConfig) []string {
	if serverCfg == nil || p.outboundMgr == nil {
		return nil
	}
	proxyOutbound := strings.TrimSpace(serverCfg.GetProxyOutbound())
	if proxyOutbound == "" || proxyOutbound == "direct" {
		return nil
	}

	// Group selection
	if serverCfg.IsGroupSelection() {
		groupName := serverCfg.GetGroupName()
		nodes := p.outboundMgr.GetOutboundsByGroup(groupName)
		out := make([]string, 0, len(nodes))
		for _, n := range nodes {
			if n == nil {
				continue
			}
			out = append(out, n.Name)
		}
		return out
	}

	// Multi node selection
	if serverCfg.IsMultiNodeSelection() {
		ns := serverCfg.GetNodeList()
		out := make([]string, 0, len(ns))
		for _, n := range ns {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			out = append(out, n)
		}
		return out
	}

	// Single node
	return []string{proxyOutbound}
}

func (p *ProxyServer) pingServerThroughNode(serverID, nodeName, targetAddr string, destAddr *net.UDPAddr) int64 {
	if p.outboundMgr == nil {
		return -1
	}

	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()

	conn, err := p.outboundMgr.DialPacketConn(ctx, nodeName, targetAddr)
	if err != nil {
		logger.Debug("auto ping dial failed: server=%s node=%s target=%s err=%v", serverID, nodeName, targetAddr, err)
		return -1
	}
	defer conn.Close()

	pingPacket := buildRakNetPingPacket()

	startTime := time.Now()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.WriteTo(pingPacket, destAddr)
	if err != nil {
		logger.Debug("auto ping write failed: server=%s node=%s target=%s err=%v", serverID, nodeName, targetAddr, err)
		return -1
	}

	buf := make([]byte, 1500)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	latencyMs := time.Since(startTime).Milliseconds()
	if err != nil {
		logger.Debug("auto ping read failed: server=%s node=%s target=%s err=%v", serverID, nodeName, targetAddr, err)
		return -1
	}
	if n <= 0 || buf[0] != 0x1c {
		logger.Debug("auto ping invalid pong: server=%s node=%s target=%s", serverID, nodeName, targetAddr)
		return -1
	}

	return latencyMs
}

func buildRakNetPingPacket() []byte {
	// 0x01 + timestamp(8 bytes BE) + MAGIC(16 bytes) + clientGUID(8 bytes)
	var pingPacket bytes.Buffer
	pingPacket.WriteByte(0x01)
	_ = binary.Write(&pingPacket, binary.BigEndian, time.Now().UnixMilli())
	pingPacket.Write(raknetMagic)
	_ = binary.Write(&pingPacket, binary.BigEndian, uint64(12345678901234567))
	return pingPacket.Bytes()
}

func resolveUDPAddr(address string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	udpAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	if udpAddr.IP != nil {
		return udpAddr, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("no A/AAAA records")
		}
		return nil, err
	}
	udpAddr.IP = ips[0]
	return udpAddr, nil
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
	protocol := strings.ToLower(serverCfg.Protocol)
	proxyMode := serverCfg.GetProxyMode()

	if protocol != "" && protocol != "raknet" {
		switch protocol {
		case "udp":
			udpProxy := NewPlainUDPProxy(serverCfg.ID, serverCfg)
			if p.outboundMgr != nil {
				udpProxy.SetOutboundManager(p.outboundMgr)
			}
			listener = udpProxy
			logger.Info("Using plain UDP forwarding for server %s", serverCfg.ID)
		case "tcp":
			tcpProxy := NewPlainTCPProxy(serverCfg.ID, serverCfg)
			if p.outboundMgr != nil {
				tcpProxy.SetOutboundManager(p.outboundMgr)
			}
			listener = tcpProxy
			logger.Info("Using plain TCP forwarding for server %s", serverCfg.ID)
		case "tcp_udp":
			udpProxy := NewPlainUDPProxy(serverCfg.ID, serverCfg)
			tcpProxy := NewPlainTCPProxy(serverCfg.ID, serverCfg)
			if p.outboundMgr != nil {
				udpProxy.SetOutboundManager(p.outboundMgr)
				tcpProxy.SetOutboundManager(p.outboundMgr)
			}
			listener = newCombinedListener(tcpProxy, udpProxy)
			logger.Info("Using plain TCP+UDP forwarding for server %s", serverCfg.ID)
		default:
			logger.Warn("Unknown protocol %s for server %s, falling back to raknet proxy mode", protocol, serverCfg.ID)
		}
	}

	if listener == nil {
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
			// Inject outbound manager for proxy routing (Requirement 2.1)
			if p.outboundMgr != nil {
				raknetProxy.SetOutboundManager(p.outboundMgr)
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
			// Global override for passthrough idle timeout
			if p.config != nil && p.config.PassthroughIdleTimeout > 0 {
				passthroughProxy.SetPassthroughIdleTimeoutOverride(time.Duration(p.config.PassthroughIdleTimeout) * time.Second)
			}
			// Inject ACL manager for access control (Requirement 5.1)
			if p.aclManager != nil {
				passthroughProxy.SetACLManager(p.aclManager)
			}
			// Inject external verifier for auth verification
			if p.externalVerifier != nil {
				passthroughProxy.SetExternalVerifier(p.externalVerifier)
			}
			// Inject outbound manager for proxy routing (Requirement 2.1)
			if p.outboundMgr != nil {
				passthroughProxy.SetOutboundManager(p.outboundMgr)
			}
			listener = passthroughProxy
			logger.Info("Using passthrough proxy mode for server %s (auth forwarded)", serverCfg.ID)
		case "raw_udp":
			// Use raw UDP forwarding proxy (no RakNet processing, pure UDP forwarding)
			rawUDPProxy := NewRawUDPProxy(
				serverCfg.ID,
				serverCfg,
				p.configMgr,
				p.sessionMgr,
			)
			// Inject ACL manager for access control
			if p.aclManager != nil {
				rawUDPProxy.SetACLManager(p.aclManager)
			}
			// Inject external verifier for auth verification
			if p.externalVerifier != nil {
				rawUDPProxy.SetExternalVerifier(p.externalVerifier)
			}
			// Inject outbound manager for proxy routing
			if p.outboundMgr != nil {
				rawUDPProxy.SetOutboundManager(p.outboundMgr)
			}
			listener = rawUDPProxy
			logger.Info("Using raw UDP forwarding mode for server %s (no RakNet processing)", serverCfg.ID)
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
// Requirements: 8.3 - Close all sing-box outbound connections on Stop
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

	// Stop proxy outbound config watcher
	// Requirements: 8.3
	if p.proxyOutboundConfigMgr != nil {
		p.proxyOutboundConfigMgr.StopWatch()
	}
	// Stop proxy port config watcher
	if p.proxyPortConfigMgr != nil {
		p.proxyPortConfigMgr.StopWatch()
	}

	// Stop all listeners
	p.listenersMu.Lock()
	for serverID, listener := range p.listeners {
		if err := listener.Stop(); err != nil {
			logger.Error("Error stopping listener %s: %v", serverID, err)
		}
	}
	p.listeners = make(map[string]Listener)
	p.listenersMu.Unlock()

	// Stop proxy ports
	if p.proxyPortManager != nil {
		p.proxyPortManager.Stop()
	}

	// Clean up all sessions (persist to database)
	sessions := p.sessionMgr.GetAllSessions()
	for _, sess := range sessions {
		p.sessionMgr.Remove(sess.ClientAddr)
	}

	// Gracefully close all sing-box outbound connections
	// Requirements: 8.3
	if p.outboundMgr != nil {
		if err := p.outboundMgr.Stop(); err != nil {
			logger.Error("Error stopping outbound manager: %v", err)
		} else {
			logger.Info("Outbound manager stopped")
		}
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

	// Get current listeners and their configs
	p.listenersMu.RLock()
	currentListeners := make(map[string]Listener)
	for id, listener := range p.listeners {
		currentListeners[id] = listener
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

	// Start or restart listeners for servers
	for _, serverCfg := range servers {
		if serverCfg.Enabled {
			existingListener, exists := currentListeners[serverCfg.ID]
			if !exists {
				// New server - start listener
				if err := p.startListener(serverCfg); err != nil {
					logger.Error("Failed to start listener for server %s: %v", serverCfg.ID, err)
				}
			} else {
				// Existing server - check if config changed (especially proxy_outbound)
				// Update the listener's config reference
				if updater, ok := existingListener.(interface{ UpdateConfig(*config.ServerConfig) }); ok {
					updater.UpdateConfig(serverCfg)
					logger.Debug("Updated config for server %s", serverCfg.ID)
				}
			}
		}
	}

	logger.LogConfigReloaded(p.listenerCount())
	return nil
}

// ReloadProxyPorts reloads proxy port listeners based on current config.
func (p *ProxyServer) ReloadProxyPorts() error {
	if p.proxyPortManager == nil {
		return nil
	}
	enabled := p.config != nil && p.config.ProxyPortsEnabled
	return p.proxyPortManager.Reload(enabled)
}

// reloadProxyOutbounds reloads proxy outbound configurations and recreates sing-box outbounds.
// Requirements: 8.2 - Recreate sing-box outbounds on config change
func (p *ProxyServer) reloadProxyOutbounds() error {
	p.runningMu.RLock()
	if !p.running {
		p.runningMu.RUnlock()
		return fmt.Errorf("proxy server is not running")
	}
	p.runningMu.RUnlock()

	if p.proxyOutboundConfigMgr == nil || p.outboundMgr == nil {
		return nil
	}

	// Get current outbounds from config manager
	configOutbounds := p.proxyOutboundConfigMgr.GetAllOutbounds()
	configMap := make(map[string]*config.ProxyOutbound)
	for _, cfg := range configOutbounds {
		configMap[cfg.Name] = cfg
	}

	// Get current outbounds from outbound manager
	currentOutbounds := p.outboundMgr.ListOutbounds()
	currentMap := make(map[string]*config.ProxyOutbound)
	for _, cfg := range currentOutbounds {
		currentMap[cfg.Name] = cfg
	}

	// Remove outbounds that no longer exist in config
	var deletedCount, addedCount, updatedCount int
	for name := range currentMap {
		if _, exists := configMap[name]; !exists {
			if err := p.outboundMgr.DeleteOutbound(name); err != nil {
				logger.Error("Failed to delete outbound %s: %v", name, err)
			} else {
				logger.Debug("Deleted proxy outbound: %s", name)
				deletedCount++
			}
		}
	}

	// Add or update outbounds from config
	for name, cfg := range configMap {
		if _, exists := currentMap[name]; !exists {
			// Add new outbound
			if err := p.outboundMgr.AddOutbound(cfg); err != nil {
				logger.Error("Failed to add outbound %s: %v", name, err)
			} else {
				logger.Debug("Added proxy outbound: %s", name)
				addedCount++
			}
		} else {
			// Update existing outbound (only updates runtime state like latency)
			if err := p.outboundMgr.UpdateOutbound(name, cfg); err != nil {
				logger.Error("Failed to update outbound %s: %v", name, err)
			} else {
				updatedCount++
			}
		}
	}

	// Log summary of changes only if there are actual additions or deletions
	if addedCount > 0 || deletedCount > 0 {
		logger.Info("Proxy outbounds changed: %d added, %d deleted", addedCount, deletedCount)
	}

	// Reload sing-box outbounds only if there are changes
	// Requirements: 8.2
	if addedCount > 0 || deletedCount > 0 {
		if err := p.outboundMgr.Reload(); err != nil {
			logger.Error("Failed to reload outbound manager: %v", err)
			return err
		}
		logger.Info("Proxy outbounds reloaded, %d outbounds configured", len(configOutbounds))
	}

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
	sessionCounts := make(map[string]int, len(servers))
	if p.sessionMgr != nil {
		sessions := p.sessionMgr.GetAllSessions()
		for _, sess := range sessions {
			sessionCounts[sess.ServerID]++
		}
	}

	for _, server := range servers {
		status := p.GetServerStatus(server.ID)
		activeSessions := sessionCounts[server.ID]
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
		name := sess.GetDisplayName()
		if name != "" && strings.EqualFold(name, playerName) {
			p.sessionMgr.Remove(sess.ClientAddr)
			logger.Info("Removed session for kicked player %s", playerName)
		}
	}

	logger.Info("ProxyServer.KickPlayer finished: total kickedCount=%d", kickedCount)
	return kickedCount
}

// LatencyProvider interface for listeners that provide latency information
type LatencyProvider interface {
	GetCachedLatency() int64
	GetCachedPong() []byte
}

func extractMotdFromPong(pong []byte) string {
	if len(pong) == 0 {
		return ""
	}

	if _, advertisement, ok := parseUnconnectedPong(pong); ok {
		return string(advertisement)
	}

	text := string(pong)
	if idx := strings.Index(text, "MCPE;"); idx >= 0 {
		return text[idx:]
	}
	if idx := strings.Index(text, "MCEE;"); idx >= 0 {
		return text[idx:]
	}
	return text
}

// GetServerLatency returns the cached latency for a server.
// Returns (latency_ms, true) if available, or (0, false) if not.
func (p *ProxyServer) GetServerLatency(serverID string) (int64, bool) {
	p.listenersMu.RLock()
	defer p.listenersMu.RUnlock()

	listener, exists := p.listeners[serverID]
	if !exists {
		return 0, false
	}

	if provider, ok := listener.(LatencyProvider); ok {
		latency := provider.GetCachedLatency()
		pong := provider.GetCachedPong()
		if latency == 0 && len(pong) == 0 {
			return 0, false
		}
		return latency, true
	}

	return 0, false
}

// GetServerLatencyInfoRaw returns detailed latency and MOTD information for a server.
// This method is used by the API to get raw latency info without type dependencies.
func (p *ProxyServer) GetServerLatencyInfoRaw(serverID string) (latency int64, online bool, motd string, ok bool) {
	p.listenersMu.RLock()
	defer p.listenersMu.RUnlock()

	listener, exists := p.listeners[serverID]
	if !exists {
		return 0, false, "", false
	}

	if provider, ok := listener.(LatencyProvider); ok {
		latency := provider.GetCachedLatency()
		motd := extractMotdFromPong(provider.GetCachedPong())
		if latency <= 0 && motd == "" {
			return 0, false, "", false
		}
		online := latency >= 0 || motd != ""
		return latency, online, motd, true
	}

	return 0, false, "", false
}
