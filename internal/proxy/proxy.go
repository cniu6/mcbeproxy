// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
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

type ServerLatencyRecorder interface {
	RecordServerLatency(serverID string, timestampMs int64, latencyMs int64, online bool, stopped bool, source string)
}

const defaultAutoPingIntervalMinutes = 10
const defaultAutoPingTopCandidates = 10
const autoPingParallelism = 4
const autoPingGlobalParallelism = 8
const defaultAutoPingHTTPProbeURL = "https://1.1.1.1/cdn-cgi/trace"
const defaultAutoPingTCPProbeTarget = "1.1.1.1:443"
const defaultAutoPingUDPProbeTarget = "mco.cubecraft.net:19132"

type autoPingRunResult struct {
	key          string
	didFullScan  bool
	scannedNodes int
}

type topologyRefreshSummary struct {
	servers        int
	serverNodes    int
	serverFull     int
	proxyPorts     int
	proxyPortNodes int
	proxyPortFull  int
}

type connectedPacketWriter interface {
	Write([]byte) (int, error)
}

func proxyPortSelectorID(portID string) string {
	portID = strings.TrimSpace(portID)
	if portID == "" {
		return ""
	}
	return "proxy-port:" + portID
}

func serverAutoPingResultKey(serverID string) string {
	return "server:" + strings.TrimSpace(serverID)
}

func proxyPortAutoPingResultKey(portID string) string {
	return proxyPortSelectorID(portID)
}

func writePacketConn(conn net.PacketConn, payload []byte, addr net.Addr) (int, error) {
	n, err := conn.WriteTo(payload, addr)
	if err == nil {
		return n, nil
	}
	if writer, ok := conn.(connectedPacketWriter); ok && shouldFallbackToConnectedWrite(err) {
		return writer.Write(payload)
	}
	return n, err
}

// HostnamePortAddr is a net.Addr that carries an unresolved hostname and port.
// Proxy-tunneled PacketConns (VLESS/Trojan/VMess/Hysteria2/SS/SOCKS5) embed the
// destination at ListenPacket time and ignore the addr passed to WriteTo, so
// callers can pass this type to avoid a local DNS lookup that would be
// poisoned by a running TUN proxy's fake-IP replies (100.64/10, 198.18/15, ...).
type HostnamePortAddr struct {
	Host string
	Port int
}

// Network returns "udp" so this addr is compatible with UDP PacketConns.
func (a *HostnamePortAddr) Network() string { return "udp" }

// String returns the canonical host:port form.
func (a *HostnamePortAddr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

func buildUDPDestinationAddr(ctx context.Context, address string, preserveHostname bool) (net.Addr, *net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		udpAddr := &net.UDPAddr{IP: ip, Port: port}
		return udpAddr, udpAddr, nil
	}
	if preserveHostname {
		return &HostnamePortAddr{Host: host, Port: port}, nil, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resolvedIP, _, err := resolveOutboundServerIP(lookupCtx, host)
	if err != nil {
		return nil, nil, err
	}
	udpAddr := &net.UDPAddr{IP: resolvedIP, Port: port}
	return udpAddr, udpAddr, nil
}

func shouldFallbackToConnectedWrite(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "pre-connected") ||
		strings.Contains(errText, "use of writeto with") ||
		strings.Contains(errText, "connected connection")
}

const autoSwitchMinDwell = 3 * time.Minute
const autoSwitchMinLatencyGainMs int64 = 8
const autoSwitchMinRelativeGain = 0.10

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
	serverLatencyRecorder  ServerLatencyRecorder
	autoPingStateMu        sync.RWMutex
	serverAutoPingLastRun  map[string]time.Time
	topologyRefreshMu      sync.RWMutex
	topologyRefreshSeq     uint64
	topologyRefreshReason  string
	topologyRefreshSignal  chan struct{}
	autoPingBootstrapMu   sync.Mutex
	autoPingBootstrapPos  map[string]int
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
	outboundMgr := NewOutboundManagerWithConfig(configMgr, globalConfig)
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
		serverAutoPingLastRun:  make(map[string]time.Time),
		topologyRefreshSignal:  make(chan struct{}, 1),
		autoPingBootstrapPos:   make(map[string]int),
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

func (p *ProxyServer) SetServerLatencyRecorder(recorder ServerLatencyRecorder) {
	p.serverLatencyRecorder = recorder
}

func (p *ProxyServer) setServerAutoPingLastRun(serverID string, at time.Time) {
	serverID = strings.TrimSpace(serverID)
	if p == nil || serverID == "" {
		return
	}
	p.autoPingStateMu.Lock()
	p.serverAutoPingLastRun[serverID] = at
	p.autoPingStateMu.Unlock()
}

func (p *ProxyServer) effectiveServerAutoPingIntervalMinutes(serverCfg *config.ServerConfig) int {
	if serverCfg != nil && serverCfg.AutoPingIntervalMinutes > 0 {
		return serverCfg.AutoPingIntervalMinutes
	}
	if p != nil && p.config != nil {
		return p.config.GetServerAutoPingIntervalMinutesDefault()
	}
	return defaultAutoPingIntervalMinutes
}

func (p *ProxyServer) effectiveServerAutoPingTopCandidates(serverCfg *config.ServerConfig) int {
	if serverCfg != nil && serverCfg.AutoPingTopCandidates > 0 {
		return serverCfg.AutoPingTopCandidates
	}
	if serverCfg != nil && serverCfg.AutoPingTopCandidates < 0 {
		return 0
	}
	if p != nil && p.config != nil {
		return p.config.GetServerAutoPingTopCandidatesDefault()
	}
	return defaultAutoPingTopCandidates
}

func (p *ProxyServer) effectiveProxyPortAutoPingIntervalMinutes(portCfg *config.ProxyPortConfig) int {
	if portCfg != nil && portCfg.AutoPingIntervalMinutes > 0 {
		return portCfg.AutoPingIntervalMinutes
	}
	if p != nil && p.config != nil {
		return p.config.GetProxyPortAutoPingIntervalMinutesDefault()
	}
	return defaultAutoPingIntervalMinutes
}

func (p *ProxyServer) effectiveProxyPortAutoPingTopCandidates(portCfg *config.ProxyPortConfig) int {
	if portCfg != nil && portCfg.AutoPingTopCandidates > 0 {
		return portCfg.AutoPingTopCandidates
	}
	if portCfg != nil && portCfg.AutoPingTopCandidates < 0 {
		return 0
	}
	if p != nil && p.config != nil {
		return p.config.GetProxyPortAutoPingTopCandidatesDefault()
	}
	return defaultAutoPingTopCandidates
}

func autoPingHistoryMinIntervalOverrideMs(intervalMinutes int) int64 {
	if intervalMinutes <= 0 {
		return 0
	}
	return int64(time.Duration(intervalMinutes) * time.Minute / time.Millisecond)
}

func (p *ProxyServer) recordAutoPingOutboundLatency(nodeName, sortBy string, latencyMs int64, recordedAt time.Time, minIntervalOverrideMs int64) {
	nodeName = strings.TrimSpace(nodeName)
	if p == nil || p.outboundMgr == nil || p.proxyOutboundConfigMgr == nil || nodeName == "" || nodeName == DirectNodeName {
		return
	}
	if _, exists := p.proxyOutboundConfigMgr.GetOutbound(nodeName); !exists {
		return
	}
	if recorder, ok := p.outboundMgr.(outboundLatencyOverrideRecorder); ok {
		recorder.setOutboundLatencyAt(nodeName, sortBy, latencyMs, recordedAt, minIntervalOverrideMs)
		return
	}
	p.outboundMgr.SetOutboundLatency(nodeName, sortBy, latencyMs)
}

func (p *ProxyServer) getServerAutoPingSchedule(serverCfg *config.ServerConfig, status string, now time.Time) (int64, int64) {
	if p == nil || serverCfg == nil || !serverCfg.IsAutoPingEnabled() || status != "running" {
		return 0, 0
	}
	interval := time.Duration(p.effectiveServerAutoPingIntervalMinutes(serverCfg)) * time.Minute
	p.autoPingStateMu.RLock()
	lastRun, ok := p.serverAutoPingLastRun[serverCfg.ID]
	p.autoPingStateMu.RUnlock()
	if !ok || lastRun.IsZero() {
		return 0, now.UnixMilli()
	}
	return lastRun.UnixMilli(), lastRun.Add(interval).UnixMilli()
}

func (p *ProxyServer) recordServerLatencyFromAutoPing(serverCfg *config.ServerConfig, recordedAt time.Time) {
	if p == nil || p.outboundMgr == nil || p.serverLatencyRecorder == nil || serverCfg == nil {
		return
	}
	sortBy := serverCfg.GetLoadBalanceSort()
	selectedNode, _ := p.outboundMgr.GetServerSelectedNode(serverCfg.ID)
	selectedNode = strings.TrimSpace(selectedNode)
	latencyMs := int64(0)
	online := false
	if selectedNode != "" {
		if value, ok := p.outboundMgr.GetServerNodeLatency(serverCfg.ID, selectedNode, sortBy); ok && value > 0 {
			latencyMs = value
			online = true
		}
	}
	if !online {
		for _, nodeName := range dedupeNodeNames(p.getServerNodeNames(serverCfg)) {
			if value, ok := p.outboundMgr.GetServerNodeLatency(serverCfg.ID, nodeName, sortBy); ok && value > 0 {
				if !online || value < latencyMs {
					latencyMs = value
					online = true
				}
			}
		}
	}
	p.serverLatencyRecorder.RecordServerLatency(serverCfg.ID, recordedAt.UnixMilli(), latencyMs, online, false, "auto_ping")
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
	// Determine connection status
	status := snap.DisconnectStatus
	if status == "" {
		status = "disconnected" // normal disconnect
	}
	statusReason := snap.DisconnectReason

	record := &session.SessionRecord{
		ID:           snap.ID,
		ClientAddr:   snap.ClientAddr,
		ServerID:     snap.ServerID,
		UUID:         snap.UUID,
		DisplayName:  snap.DisplayName,
		BytesUp:      snap.BytesUp,
		BytesDown:    snap.BytesDown,
		StartTime:    snap.StartTime,
		EndTime:      endTime,
		Status:       status,
		StatusReason: statusReason,
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
	p.startTopologyRefreshWorker()

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

		serverLastRun := make(map[string]time.Time)
		serverLastFullScan := make(map[string]time.Time)
		serverLastSwitch := make(map[string]time.Time)
		observedServerNode := make(map[string]string)
		portLastRun := make(map[string]time.Time)
		portLastFullScan := make(map[string]time.Time)
		portLastSwitch := make(map[string]time.Time)
		observedPortNode := make(map[string]string)

		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
			}

			now := time.Now()
			var dueServers []*config.ServerConfig
			for _, serverCfg := range p.configMgr.GetAllServers() {
				if serverCfg == nil {
					continue
				}
				if !serverCfg.IsAutoPingEnabled() {
					continue
				}
				intervalMin := p.effectiveServerAutoPingIntervalMinutes(serverCfg)

				if t, ok := serverLastRun[serverCfg.ID]; ok {
					if now.Sub(t) < time.Duration(intervalMin)*time.Minute {
						continue
					}
				}
				dueServers = append(dueServers, serverCfg)
			}

			var duePorts []*config.ProxyPortConfig
			if p.proxyPortConfigMgr != nil {
				for _, portCfg := range p.proxyPortConfigMgr.GetAllPorts() {
					if portCfg == nil {
						continue
					}
					if !portCfg.Enabled || !portCfg.AutoPingEnabled {
						continue
					}
					if portCfg.IsDirectConnection() {
						continue
					}
					intervalMin := p.effectiveProxyPortAutoPingIntervalMinutes(portCfg)
					if t, ok := portLastRun[portCfg.ID]; ok {
						if now.Sub(t) < time.Duration(intervalMin)*time.Minute {
							continue
						}
					}
					duePorts = append(duePorts, portCfg)
				}
			}

			if len(dueServers) == 0 && len(duePorts) == 0 {
				continue
			}

			pingBudget := make(chan struct{}, autoPingGlobalParallelism)
			results := make(chan autoPingRunResult, len(dueServers)+len(duePorts))
			var pingWG sync.WaitGroup
			for _, serverCfg := range dueServers {
				pingWG.Add(1)
				go func(serverCfg *config.ServerConfig) {
					defer pingWG.Done()
					fullScanDue, _ := shouldRunScheduledFullScan(serverCfg, now, serverLastFullScan[serverCfg.ID])
					results <- p.pingAllNodesForServer(serverCfg, pingBudget, fullScanDue)
				}(serverCfg)
			}
			for _, portCfg := range duePorts {
				pingWG.Add(1)
				go func(portCfg *config.ProxyPortConfig) {
					defer pingWG.Done()
					fullScanDue, _ := shouldRunScheduledFullScanForProxyPort(portCfg, now, portLastFullScan[portCfg.ID])
					results <- p.pingAllNodesForProxyPort(portCfg, pingBudget, fullScanDue)
				}(portCfg)
			}
			pingWG.Wait()
			close(results)
			completedAt := time.Now()
			for result := range results {
				if result.key == "" || !result.didFullScan {
					continue
				}
				if strings.HasPrefix(result.key, "server:") {
					serverLastFullScan[strings.TrimPrefix(result.key, "server:")] = completedAt
					continue
				}
				if strings.HasPrefix(result.key, "proxy-port:") {
					portLastFullScan[strings.TrimPrefix(result.key, "proxy-port:")] = completedAt
				}
			}
			for _, serverCfg := range dueServers {
				serverLastRun[serverCfg.ID] = completedAt
				p.setServerAutoPingLastRun(serverCfg.ID, completedAt)
				p.maybeAutoSwitchServerNode(serverCfg, completedAt, serverLastSwitch, observedServerNode)
				p.recordServerLatencyFromAutoPing(serverCfg, completedAt)
			}
			for _, portCfg := range duePorts {
				portLastRun[portCfg.ID] = completedAt
				p.maybeAutoSwitchProxyPortNode(portCfg, completedAt, portLastSwitch, observedPortNode)
			}
		}
	}()
}

func (p *ProxyServer) startTopologyRefreshWorker() {
	if p.ctx == nil {
		return
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		gm := monitor.GetGoroutineManager()
		gid := gm.TrackBackground("topology-refresh", "proxy-server", "Topology refresh worker", p.cancel)
		defer gm.Untrack(gid)

		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		var lastProcessed uint64
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-ticker.C:
			case <-p.topologyRefreshSignal:
			}

			seq, reason := p.latestTopologyRefreshRequest()
			if seq == 0 || seq == lastProcessed {
				continue
			}

			activeSessions := p.GetActiveSessionCount()
			activeProxyPorts := p.GetActiveProxyPortConnectionCount()
			if activeSessions > 0 || activeProxyPorts > 0 {
				logger.Info("Deferred topology refresh #%d: %s (active_sessions=%d, active_proxy_ports=%d)", seq, reason, activeSessions, activeProxyPorts)
				continue
			}

			logger.Info("Running topology refresh #%d: %s", seq, reason)
			summary := p.runAutoLatencyRefresh(true)
			lastProcessed = seq
			logger.Info(
				"Completed topology refresh #%d: %s (servers=%d, server_nodes=%d, server_full=%d, proxy_ports=%d, proxy_port_nodes=%d, proxy_port_full=%d)",
				seq,
				reason,
				summary.servers,
				summary.serverNodes,
				summary.serverFull,
				summary.proxyPorts,
				summary.proxyPortNodes,
				summary.proxyPortFull,
			)
		}
	}()
}

func (p *ProxyServer) TriggerAutoLatencyRefresh(reason string) {
	if p == nil {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "subscription update"
	}

	p.topologyRefreshMu.Lock()
	p.topologyRefreshSeq++
	seq := p.topologyRefreshSeq
	p.topologyRefreshReason = reason
	p.topologyRefreshMu.Unlock()

	logger.Info("Queued topology refresh #%d: %s", seq, reason)

	if p.topologyRefreshSignal != nil {
		select {
		case p.topologyRefreshSignal <- struct{}{}:
		default:
		}
	}
}

func (p *ProxyServer) latestTopologyRefreshRequest() (uint64, string) {
	if p == nil {
		return 0, ""
	}
	p.topologyRefreshMu.RLock()
	defer p.topologyRefreshMu.RUnlock()
	return p.topologyRefreshSeq, p.topologyRefreshReason
}

func (p *ProxyServer) runAutoLatencyRefresh(forceFullScan bool) topologyRefreshSummary {
	summary := topologyRefreshSummary{}
	if p == nil || p.outboundMgr == nil || p.configMgr == nil {
		return summary
	}

	pingBudget := make(chan struct{}, autoPingGlobalParallelism)
	results := make(chan autoPingRunResult)
	var pingWG sync.WaitGroup

	for _, serverCfg := range p.configMgr.GetAllServers() {
		if serverCfg == nil || !serverCfg.IsAutoPingEnabled() {
			continue
		}
		summary.servers++
		pingWG.Add(1)
		go func(serverCfg *config.ServerConfig) {
			defer pingWG.Done()
			results <- p.pingAllNodesForServer(serverCfg, pingBudget, forceFullScan)
		}(serverCfg)
	}

	if p.proxyPortConfigMgr != nil {
		for _, portCfg := range p.proxyPortConfigMgr.GetAllPorts() {
			if portCfg == nil || !portCfg.Enabled || !portCfg.AutoPingEnabled || portCfg.IsDirectConnection() {
				continue
			}
			summary.proxyPorts++
			pingWG.Add(1)
			go func(portCfg *config.ProxyPortConfig) {
				defer pingWG.Done()
				results <- p.pingAllNodesForProxyPort(portCfg, pingBudget, forceFullScan)
			}(portCfg)
		}
	}

	go func() {
		pingWG.Wait()
		close(results)
	}()

	now := time.Now()
	serverLastSwitch := make(map[string]time.Time)
	observedServerNode := make(map[string]string)
	portLastSwitch := make(map[string]time.Time)
	observedPortNode := make(map[string]string)

	for result := range results {
		switch {
		case strings.HasPrefix(result.key, "server:"):
			summary.serverNodes += result.scannedNodes
			if result.didFullScan {
				summary.serverFull++
			}
		case strings.HasPrefix(result.key, "proxy-port:"):
			summary.proxyPortNodes += result.scannedNodes
			if result.didFullScan {
				summary.proxyPortFull++
			}
		}
	}

	for _, serverCfg := range p.configMgr.GetAllServers() {
		if serverCfg == nil || !serverCfg.IsAutoPingEnabled() {
			continue
		}
		p.setServerAutoPingLastRun(serverCfg.ID, now)
		p.maybeAutoSwitchServerNode(serverCfg, now, serverLastSwitch, observedServerNode)
		p.recordServerLatencyFromAutoPing(serverCfg, now)
	}
	if p.proxyPortConfigMgr != nil {
		for _, portCfg := range p.proxyPortConfigMgr.GetAllPorts() {
			if portCfg == nil || !portCfg.Enabled || !portCfg.AutoPingEnabled || portCfg.IsDirectConnection() {
				continue
			}
			p.maybeAutoSwitchProxyPortNode(portCfg, now, portLastSwitch, observedPortNode)
		}
	}

	return summary
}

func (p *ProxyServer) maybeAutoSwitchServerNode(serverCfg *config.ServerConfig, now time.Time, lastSwitch map[string]time.Time, observedSelectedNode map[string]string) {
	if serverCfg == nil || p.outboundMgr == nil {
		return
	}
	if serverCfg.GetLoadBalance() != config.LoadBalanceLeastLatency {
		return
	}

	proxyOutbound := strings.TrimSpace(serverCfg.GetProxyOutbound())
	sortBy := serverCfg.GetLoadBalanceSort()
	bestNode, bestLatency := p.outboundMgr.GetBestNodeForServer(serverCfg.ID, proxyOutbound, sortBy)
	if bestNode == "" {
		return
	}

	currentNode, _ := p.outboundMgr.GetServerSelectedNode(serverCfg.ID)
	if observedSelectedNode[serverCfg.ID] != currentNode {
		observedSelectedNode[serverCfg.ID] = currentNode
		if currentNode == "" {
			delete(lastSwitch, serverCfg.ID)
		} else {
			lastSwitch[serverCfg.ID] = now
		}
	}
	if currentNode == bestNode {
		return
	}

	activeSessions := p.GetActiveSessionsForServer(serverCfg.ID)
	if activeSessions != 0 {
		logger.Debug("Auto-switch deferred for server %s: %s -> %s (%d active sessions)", serverCfg.ID, currentNode, bestNode, activeSessions)
		return
	}

	currentLatency, currentLatencyOK := p.outboundMgr.GetServerNodeLatency(serverCfg.ID, currentNode, sortBy)
	if shouldSwitch, reason := shouldAutoSwitchNode(currentNode, currentLatency, currentLatencyOK, bestLatency, lastSwitch[serverCfg.ID], now); !shouldSwitch {
		logger.Debug("Auto-switch skipped for server %s: %s (current=%s, best=%s, current_latency=%dms, best_latency=%dms)",
			serverCfg.ID, reason, currentNode, bestNode, currentLatency, bestLatency)
		return
	}

	p.outboundMgr.SetServerSelectedNode(serverCfg.ID, bestNode)
	observedSelectedNode[serverCfg.ID] = bestNode
	lastSwitch[serverCfg.ID] = now
	logger.Info("Auto-switch server %s node: %s -> %s (0 active sessions, current=%dms, best=%dms)", serverCfg.ID, currentNode, bestNode, currentLatency, bestLatency)
}

func (p *ProxyServer) maybeAutoSwitchProxyPortNode(portCfg *config.ProxyPortConfig, now time.Time, lastSwitch map[string]time.Time, observedSelectedNode map[string]string) {
	if portCfg == nil || p.outboundMgr == nil {
		return
	}
	if portCfg.GetLoadBalance() != config.LoadBalanceLeastLatency {
		return
	}

	selectorID := proxyPortSelectorID(portCfg.ID)
	proxyOutbound := strings.TrimSpace(portCfg.ProxyOutbound)
	sortBy := portCfg.GetLoadBalanceSort()
	bestNode, bestLatency := p.outboundMgr.GetBestNodeForServer(selectorID, proxyOutbound, sortBy)
	if bestNode == "" {
		return
	}

	currentNode, _ := p.outboundMgr.GetServerSelectedNode(selectorID)
	if observedSelectedNode[portCfg.ID] != currentNode {
		observedSelectedNode[portCfg.ID] = currentNode
		if currentNode == "" {
			delete(lastSwitch, portCfg.ID)
		} else {
			lastSwitch[portCfg.ID] = now
		}
	}
	if currentNode == bestNode {
		return
	}

	activeConnections := p.GetActiveConnectionsForProxyPort(portCfg.ID)
	if activeConnections != 0 {
		logger.Debug("Auto-switch deferred for proxy port %s: %s -> %s (%d active connections)", portCfg.ID, currentNode, bestNode, activeConnections)
		return
	}

	currentLatency, currentLatencyOK := p.outboundMgr.GetServerNodeLatency(selectorID, currentNode, sortBy)
	if shouldSwitch, reason := shouldAutoSwitchNode(currentNode, currentLatency, currentLatencyOK, bestLatency, lastSwitch[portCfg.ID], now); !shouldSwitch {
		logger.Debug("Auto-switch skipped for proxy port %s: %s (current=%s, best=%s, current_latency=%dms, best_latency=%dms)",
			portCfg.ID, reason, currentNode, bestNode, currentLatency, bestLatency)
		return
	}

	p.outboundMgr.SetServerSelectedNode(selectorID, bestNode)
	observedSelectedNode[portCfg.ID] = bestNode
	lastSwitch[portCfg.ID] = now
	logger.Info("Auto-switch proxy port %s node: %s -> %s (0 active connections, current=%dms, best=%dms)", portCfg.ID, currentNode, bestNode, currentLatency, bestLatency)
}

func shouldAutoSwitchNode(currentNode string, currentLatency int64, currentLatencyOK bool, bestLatency int64, lastSwitchAt time.Time, now time.Time) (bool, string) {
	if bestLatency <= 0 {
		return false, "best node has no latency sample"
	}
	if currentNode == "" {
		return true, ""
	}
	if !currentLatencyOK || currentLatency <= 0 {
		return true, ""
	}
	improvement := currentLatency - bestLatency
	if improvement <= 0 {
		return false, "best node is not faster than current node"
	}
	absoluteGainOK := improvement >= autoSwitchMinLatencyGainMs
	relativeGainOK := float64(improvement) >= float64(currentLatency)*autoSwitchMinRelativeGain
	if !absoluteGainOK && !relativeGainOK {
		return false, "latency improvement is below hysteresis threshold"
	}
	if !lastSwitchAt.IsZero() && now.Sub(lastSwitchAt) < autoSwitchMinDwell {
		return false, "minimum dwell time not reached"
	}
	return true, ""
}

func (p *ProxyServer) pingAllNodesForServer(serverCfg *config.ServerConfig, globalSem chan struct{}, scheduledFullScan bool) autoPingRunResult {
	result := autoPingRunResult{}
	if serverCfg == nil || p.outboundMgr == nil {
		return result
	}
	result.key = serverAutoPingResultKey(serverCfg.ID)

	proxyOutbound := strings.TrimSpace(serverCfg.GetProxyOutbound())
	if proxyOutbound == "" || proxyOutbound == "direct" {
		return result
	}
	if p.GetActiveSessionsForServer(serverCfg.ID) > 0 {
		return result
	}

	targetAddr := serverCfg.GetTargetAddr()
	destAddr, _, err := buildUDPDestinationAddr(context.Background(), targetAddr, true)
	if err != nil {
		logger.Debug("auto ping resolve target failed: server=%s target=%s err=%v", serverCfg.ID, targetAddr, err)
		return result
	}

	sortBy := serverCfg.GetLoadBalanceSort()
	if sortBy == "" {
		sortBy = config.LoadBalanceSortUDP
	}

	nodeNames := p.getServerNodeNames(serverCfg)
	nodeNames = dedupeNodeNames(nodeNames)
	if len(nodeNames) == 0 {
		return result
	}
	fullScan := scheduledFullScan
	scanTargets := nodeNames
	if !fullScan {
		var fallbackFullScan bool
		scanTargets, fallbackFullScan = p.selectAutoPingTargets(serverCfg, nodeNames, sortBy)
		if fallbackFullScan {
			fullScan = true
			scanTargets = nodeNames
		}
	}
	if len(scanTargets) == 0 {
		return result
	}
	result.didFullScan = fullScan
	result.scannedNodes = len(scanTargets)

	parallelism := autoPingParallelism
	if parallelism <= 0 {
		parallelism = 1
	}
	if len(scanTargets) < parallelism {
		parallelism = len(scanTargets)
	}
	if parallelism <= 0 {
		return result
	}

	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for _, nodeName := range scanTargets {
		if !acquireAutoPingSlot(p.ctx, sem, globalSem) {
			wg.Wait()
			return result
		}

		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			defer releaseAutoPingSlot(sem, globalSem)

			latencyMs := p.probeServerThroughNode(serverCfg.ID, nodeName, targetAddr, destAddr, sortBy)
			recordedAt := time.Now()
			if latencyMs > 0 {
				p.outboundMgr.SetServerNodeLatency(serverCfg.ID, nodeName, sortBy, latencyMs)
			} else {
				p.outboundMgr.SetServerNodeLatency(serverCfg.ID, nodeName, sortBy, 0)
			}
			p.recordAutoPingOutboundLatency(nodeName, sortBy, latencyMs, recordedAt, autoPingHistoryMinIntervalOverrideMs(p.effectiveServerAutoPingIntervalMinutes(serverCfg)))
		}(nodeName)
	}
	wg.Wait()
	if fullScan {
		logger.Debug("auto ping full scan complete: server=%s sort=%s nodes=%d", serverCfg.ID, sortBy, len(scanTargets))
	} else {
		logger.Debug("auto ping partial scan complete: server=%s sort=%s nodes=%d", serverCfg.ID, sortBy, len(scanTargets))
	}
	return result
}

func shouldRunScheduledFullScanForProxyPort(portCfg *config.ProxyPortConfig, now, lastFullScan time.Time) (bool, string) {
	if portCfg == nil {
		return false, ""
	}
	switch portCfg.GetAutoPingFullScanMode() {
	case config.AutoPingFullScanModeDisabled:
		return false, ""
	case config.AutoPingFullScanModeDaily:
		clock, err := configTimeOnly(portCfg.GetAutoPingFullScanTime())
		if err != nil {
			return false, ""
		}
		scheduledAt := time.Date(now.Year(), now.Month(), now.Day(), clock.Hour(), clock.Minute(), 0, 0, now.Location())
		if now.Before(scheduledAt) {
			return false, ""
		}
		if !lastFullScan.IsZero() && !lastFullScan.Before(scheduledAt) {
			return false, ""
		}
		return true, "daily"
	case config.AutoPingFullScanModeInterval:
		interval := time.Duration(portCfg.GetAutoPingFullScanIntervalHours()) * time.Hour
		if interval <= 0 || lastFullScan.IsZero() || now.Sub(lastFullScan) < interval {
			return false, ""
		}
		return true, "interval"
	default:
		return false, ""
	}
}

func (p *ProxyServer) pingAllNodesForProxyPort(portCfg *config.ProxyPortConfig, globalSem chan struct{}, scheduledFullScan bool) autoPingRunResult {
	result := autoPingRunResult{}
	if portCfg == nil || p.outboundMgr == nil {
		return result
	}
	result.key = proxyPortAutoPingResultKey(portCfg.ID)

	if !portCfg.Enabled || portCfg.IsDirectConnection() {
		return result
	}
	if p.GetActiveConnectionsForProxyPort(portCfg.ID) > 0 {
		return result
	}

	sortBy := portCfg.GetLoadBalanceSort()
	if sortBy == "" {
		sortBy = config.LoadBalanceSortTCP
	}

	targetAddr := defaultAutoPingTCPProbeTarget
	var destAddr net.Addr
	if sortBy == config.LoadBalanceSortUDP {
		targetAddr = defaultAutoPingUDPProbeTarget
		udpDestAddr, _, err := buildUDPDestinationAddr(context.Background(), targetAddr, true)
		if err != nil {
			logger.Debug("auto ping resolve proxy port target failed: port=%s target=%s err=%v", portCfg.ID, targetAddr, err)
			return result
		}
		destAddr = udpDestAddr
	}

	nodeNames := dedupeNodeNames(p.getProxyPortNodeNames(portCfg))
	if len(nodeNames) == 0 {
		return result
	}

	selectorID := proxyPortSelectorID(portCfg.ID)
	fullScan := scheduledFullScan
	scanTargets := nodeNames
	if !fullScan {
		var fallbackFullScan bool
		scanTargets, fallbackFullScan = p.selectAutoPingTargetsForSelector(selectorID, p.effectiveProxyPortAutoPingTopCandidates(portCfg), nodeNames, sortBy)
		if fallbackFullScan {
			fullScan = true
			scanTargets = nodeNames
		}
	}
	if len(scanTargets) == 0 {
		return result
	}
	result.didFullScan = fullScan
	result.scannedNodes = len(scanTargets)

	parallelism := autoPingParallelism
	if parallelism <= 0 {
		parallelism = 1
	}
	if len(scanTargets) < parallelism {
		parallelism = len(scanTargets)
	}
	if parallelism <= 0 {
		return result
	}

	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for _, nodeName := range scanTargets {
		if !acquireAutoPingSlot(p.ctx, sem, globalSem) {
			wg.Wait()
			return result
		}

		wg.Add(1)
		go func(nodeName string) {
			defer wg.Done()
			defer releaseAutoPingSlot(sem, globalSem)

			latencyMs := p.probeProxyPortThroughNode(selectorID, nodeName, targetAddr, destAddr, sortBy)
			recordedAt := time.Now()
			if latencyMs > 0 {
				p.outboundMgr.SetServerNodeLatency(selectorID, nodeName, sortBy, latencyMs)
			} else {
				p.outboundMgr.SetServerNodeLatency(selectorID, nodeName, sortBy, 0)
			}
			p.recordAutoPingOutboundLatency(nodeName, sortBy, latencyMs, recordedAt, autoPingHistoryMinIntervalOverrideMs(p.effectiveProxyPortAutoPingIntervalMinutes(portCfg)))
		}(nodeName)
	}
	wg.Wait()
	if fullScan {
		logger.Debug("auto ping full scan complete: proxy_port=%s sort=%s nodes=%d", portCfg.ID, sortBy, len(scanTargets))
	} else {
		logger.Debug("auto ping partial scan complete: proxy_port=%s sort=%s nodes=%d", portCfg.ID, sortBy, len(scanTargets))
	}
	return result
}

func (p *ProxyServer) probeProxyPortThroughNode(selectorID, nodeName, targetAddr string, destAddr net.Addr, sortBy string) int64 {
	switch sortBy {
	case config.LoadBalanceSortTCP:
		if nodeName == DirectNodeName {
			return p.probeTCPDirect(selectorID, targetAddr)
		}
		return p.probeTCPThroughNode(selectorID, nodeName, targetAddr)
	case config.LoadBalanceSortHTTP:
		if nodeName == DirectNodeName {
			return p.probeHTTPDirect(selectorID)
		}
		return p.probeHTTPThroughNode(selectorID, nodeName)
	case config.LoadBalanceSortUDP:
		fallthrough
	default:
		if nodeName == DirectNodeName {
			return p.pingServerDirect(selectorID, targetAddr)
		}
		return p.pingServerThroughNode(selectorID, nodeName, targetAddr, destAddr)
	}
}

func acquireAutoPingSlot(ctx context.Context, localSem chan struct{}, globalSem chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case localSem <- struct{}{}:
	}
	if globalSem == nil {
		return true
	}
	select {
	case <-ctx.Done():
		<-localSem
		return false
	case globalSem <- struct{}{}:
		return true
	}
}

func releaseAutoPingSlot(localSem chan struct{}, globalSem chan struct{}) {
	if globalSem != nil {
		<-globalSem
	}
	<-localSem
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
		return p.filterAutoPingNodeNames(out)
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
		return p.filterAutoPingNodeNames(out)
	}

	// Single node
	return p.filterAutoPingNodeNames([]string{proxyOutbound})
}

func (p *ProxyServer) getProxyPortNodeNames(portCfg *config.ProxyPortConfig) []string {
	if portCfg == nil || p.outboundMgr == nil {
		return nil
	}
	proxyOutbound := strings.TrimSpace(portCfg.ProxyOutbound)
	if proxyOutbound == "" || proxyOutbound == "direct" {
		return nil
	}

	if portCfg.IsGroupSelection() {
		groupName := portCfg.GetGroupName()
		nodes := p.outboundMgr.GetOutboundsByGroup(groupName)
		out := make([]string, 0, len(nodes))
		for _, n := range nodes {
			if n == nil {
				continue
			}
			out = append(out, n.Name)
		}
		return p.filterAutoPingNodeNames(out)
	}

	if portCfg.IsMultiNodeSelection() {
		ns := portCfg.GetNodeList()
		out := make([]string, 0, len(ns))
		for _, n := range ns {
			n = strings.TrimSpace(n)
			if n == "" {
				continue
			}
			out = append(out, n)
		}
		return p.filterAutoPingNodeNames(out)
	}

	return p.filterAutoPingNodeNames([]string{proxyOutbound})
}

func (p *ProxyServer) filterAutoPingNodeNames(nodeNames []string) []string {
	if len(nodeNames) == 0 || p == nil || p.outboundMgr == nil {
		return nil
	}
	result := make([]string, 0, len(nodeNames))
	for _, nodeName := range nodeNames {
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			continue
		}
		if nodeName == DirectNodeName {
			result = append(result, nodeName)
			continue
		}
		if isMetadataLikeOutboundName(nodeName) {
			continue
		}
		outbound, exists := p.outboundMgr.GetOutbound(nodeName)
		if !exists || outbound == nil || !outbound.Enabled {
			continue
		}
		result = append(result, nodeName)
	}
	return result
}

func shouldRunScheduledFullScan(serverCfg *config.ServerConfig, now, lastFullScan time.Time) (bool, string) {
	if serverCfg == nil {
		return false, ""
	}
	switch serverCfg.GetAutoPingFullScanMode() {
	case config.AutoPingFullScanModeDisabled:
		return false, ""
	case config.AutoPingFullScanModeDaily:
		clock, err := configTimeOnly(serverCfg.GetAutoPingFullScanTime())
		if err != nil {
			return false, ""
		}
		scheduledAt := time.Date(now.Year(), now.Month(), now.Day(), clock.Hour(), clock.Minute(), 0, 0, now.Location())
		if now.Before(scheduledAt) {
			return false, ""
		}
		if !lastFullScan.IsZero() && !lastFullScan.Before(scheduledAt) {
			return false, ""
		}
		return true, "daily"
	case config.AutoPingFullScanModeInterval:
		interval := time.Duration(serverCfg.GetAutoPingFullScanIntervalHours()) * time.Hour
		if interval <= 0 || lastFullScan.IsZero() || now.Sub(lastFullScan) < interval {
			return false, ""
		}
		return true, "interval"
	default:
		return false, ""
	}
}

func configTimeOnly(value string) (time.Time, error) {
	return time.Parse("15:04", strings.TrimSpace(value))
}

func (p *ProxyServer) selectAutoPingTargets(serverCfg *config.ServerConfig, nodeNames []string, sortBy string) ([]string, bool) {
	if serverCfg == nil {
		return dedupeNodeNames(nodeNames), false
	}
	return p.selectAutoPingTargetsForSelector(serverCfg.ID, p.effectiveServerAutoPingTopCandidates(serverCfg), nodeNames, sortBy)
}

func (p *ProxyServer) selectAutoPingTargetsForSelector(selectorID string, topCandidates int, nodeNames []string, sortBy string) ([]string, bool) {
	if len(nodeNames) <= 1 {
		return dedupeNodeNames(nodeNames), false
	}

	currentNode, _ := p.outboundMgr.GetServerSelectedNode(selectorID)
	selected := make([]string, 0, len(nodeNames))
	selectedSet := make(map[string]struct{}, len(nodeNames))
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, exists := selectedSet[name]; exists {
			return
		}
		selectedSet[name] = struct{}{}
		selected = append(selected, name)
	}

	nodeSet := make(map[string]struct{}, len(nodeNames))
	for _, nodeName := range nodeNames {
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			continue
		}
		nodeSet[nodeName] = struct{}{}
	}
	if _, exists := nodeSet[currentNode]; exists {
		add(currentNode)
	}

	type rankedCandidate struct {
		name      string
		latencyMs int64
	}
	ranked := make([]rankedCandidate, 0, len(nodeNames))
	for _, nodeName := range nodeNames {
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" || nodeName == currentNode {
			continue
		}
		if latencyMs, ok := p.lookupAutoPingLatency(selectorID, nodeName, sortBy); ok && latencyMs > 0 {
			ranked = append(ranked, rankedCandidate{name: nodeName, latencyMs: latencyMs})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].latencyMs == ranked[j].latencyMs {
			return ranked[i].name < ranked[j].name
		}
		return ranked[i].latencyMs < ranked[j].latencyMs
	})

	if topCandidates < 1 {
		topCandidates = 1
	}
	limit := topCandidates
	if currentNode != "" {
		if _, exists := nodeSet[currentNode]; exists {
			limit++
		}
	}
	for _, candidate := range ranked {
		if len(selected) >= limit {
			break
		}
		add(candidate.name)
	}

	if len(selected) == 0 {
		return p.nextAutoPingBootstrapTargets(selectorID, topCandidates, nodeNames), false
	}
	return selected, false
}

func (p *ProxyServer) nextAutoPingBootstrapTargets(selectorID string, topCandidates int, nodeNames []string) []string {
	nodeNames = dedupeNodeNames(nodeNames)
	if len(nodeNames) == 0 {
		return nil
	}
	if topCandidates < 1 {
		topCandidates = 1
	}
	if topCandidates >= len(nodeNames) {
		return nodeNames
	}

	p.autoPingBootstrapMu.Lock()
	defer p.autoPingBootstrapMu.Unlock()

	if p.autoPingBootstrapPos == nil {
		p.autoPingBootstrapPos = make(map[string]int)
	}
	start := p.autoPingBootstrapPos[selectorID]
	if start < 0 || start >= len(nodeNames) {
		start = 0
	}

	selected := make([]string, 0, topCandidates)
	for i := 0; i < topCandidates && i < len(nodeNames); i++ {
		selected = append(selected, nodeNames[(start+i)%len(nodeNames)])
	}
	p.autoPingBootstrapPos[selectorID] = (start + len(selected)) % len(nodeNames)
	return selected
}

func dedupeNodeNames(nodeNames []string) []string {
	seen := make(map[string]struct{}, len(nodeNames))
	result := make([]string, 0, len(nodeNames))
	for _, nodeName := range nodeNames {
		nodeName = strings.TrimSpace(nodeName)
		if nodeName == "" {
			continue
		}
		if _, exists := seen[nodeName]; exists {
			continue
		}
		seen[nodeName] = struct{}{}
		result = append(result, nodeName)
	}
	return result
}

func (p *ProxyServer) lookupAutoPingLatency(selectorID, nodeName, sortBy string) (int64, bool) {
	if p.outboundMgr != nil {
		if latencyMs, ok := p.outboundMgr.GetServerNodeLatency(selectorID, nodeName, sortBy); ok && latencyMs > 0 {
			return latencyMs, true
		}
	}
	if nodeName == DirectNodeName || p.proxyOutboundConfigMgr == nil {
		return 0, false
	}
	outbound, exists := p.proxyOutboundConfigMgr.GetOutbound(nodeName)
	if !exists || outbound == nil {
		return 0, false
	}
	switch sortBy {
	case config.LoadBalanceSortTCP:
		if outbound.TCPLatencyMs > 0 {
			return outbound.TCPLatencyMs, true
		}
	case config.LoadBalanceSortHTTP:
		if outbound.HTTPLatencyMs > 0 {
			return outbound.HTTPLatencyMs, true
		}
	default:
		if outbound.UDPLatencyMs > 0 {
			return outbound.UDPLatencyMs, true
		}
	}
	return 0, false
}

func (p *ProxyServer) probeServerThroughNode(serverID, nodeName, targetAddr string, destAddr net.Addr, sortBy string) int64 {
	switch sortBy {
	case config.LoadBalanceSortTCP:
		if nodeName == DirectNodeName {
			return p.probeTCPDirect(serverID, targetAddr)
		}
		return p.probeTCPThroughNode(serverID, nodeName, targetAddr)
	case config.LoadBalanceSortHTTP:
		if nodeName == DirectNodeName {
			return p.probeHTTPDirect(serverID)
		}
		return p.probeHTTPThroughNode(serverID, nodeName)
	case config.LoadBalanceSortUDP:
		fallthrough
	default:
		if nodeName == DirectNodeName {
			return p.pingServerDirect(serverID, targetAddr)
		}
		return p.pingServerThroughNode(serverID, nodeName, targetAddr, destAddr)
	}
}

func (p *ProxyServer) pingServerThroughNode(serverID, nodeName, targetAddr string, destAddr net.Addr) int64 {
	if p.outboundMgr == nil {
		return -1
	}

	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()

	var (
		conn net.PacketConn
		err  error
	)
	if noRetryDialer, ok := p.outboundMgr.(outboundPacketConnNoRetryDialer); ok {
		conn, err = noRetryDialer.DialPacketConnNoRetry(ctx, nodeName, targetAddr)
	} else {
		conn, err = p.outboundMgr.DialPacketConn(ctx, nodeName, targetAddr)
	}
	if err != nil {
		logger.Debug("auto ping dial failed: server=%s node=%s target=%s err=%v", serverID, nodeName, targetAddr, err)
		return -1
	}
	defer conn.Close()

	pingPacket := buildRakNetPingPacket()

	startTime := time.Now()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = writePacketConn(conn, pingPacket, destAddr)
	if err != nil {
		logger.Debug("auto ping write failed: server=%s node=%s target=%s err=%v", serverID, nodeName, targetAddr, err)
		return -1
	}

	bufPtr := GetSmallBuffer()
	buf := *bufPtr
	defer PutSmallBuffer(bufPtr)
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

func (p *ProxyServer) pingServerDirect(serverID, targetAddr string) int64 {
	ctx := context.Background()
	if p != nil && p.ctx != nil {
		ctx = p.ctx
	}
	udpAddr, err := resolveUDPAddrWithContext(ctx, targetAddr)
	if err != nil || udpAddr == nil {
		logger.Debug("auto ping direct resolve failed: server=%s target=%s err=%v", serverID, targetAddr, err)
		return -1
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logger.Debug("auto ping direct dial failed: server=%s target=%s err=%v", serverID, targetAddr, err)
		return -1
	}
	defer conn.Close()

	pingPacket := buildRakNetPingPacket()
	startTime := time.Now()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(pingPacket); err != nil {
		logger.Debug("auto ping direct write failed: server=%s target=%s err=%v", serverID, targetAddr, err)
		return -1
	}

	bufPtr := GetSmallBuffer()
	buf := *bufPtr
	defer PutSmallBuffer(bufPtr)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	latencyMs := time.Since(startTime).Milliseconds()
	if err != nil {
		logger.Debug("auto ping direct read failed: server=%s target=%s err=%v", serverID, targetAddr, err)
		return -1
	}
	if n <= 0 || buf[0] != 0x1c {
		logger.Debug("auto ping direct invalid pong: server=%s target=%s", serverID, targetAddr)
		return -1
	}
	return latencyMs
}

func (p *ProxyServer) probeTCPThroughNode(serverID, nodeName, targetAddr string) int64 {
	if p == nil || p.outboundMgr == nil {
		return -1
	}
	cfg, exists := p.outboundMgr.GetOutbound(nodeName)
	if !exists || cfg == nil {
		logger.Debug("auto ping tcp probe failed: server=%s node=%s target=%s err=proxy outbound not found", serverID, nodeName, targetAddr)
		return -1
	}
	ctx := context.Background()
	if p.ctx != nil {
		ctx = p.ctx
	}
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	dialer, err := NewSingboxCoreFactory().CreateDialer(probeCtx, cfg)
	if err != nil {
		logger.Debug("auto ping tcp dialer create failed: server=%s node=%s target=%s err=%v", serverID, nodeName, targetAddr, err)
		return -1
	}
	defer dialer.Close()

	startTime := time.Now()
	conn, err := dialer.DialContext(probeCtx, "tcp", targetAddr)
	latencyMs := time.Since(startTime).Milliseconds()
	if err != nil {
		logger.Debug("auto ping tcp dial failed: server=%s node=%s target=%s err=%v", serverID, nodeName, targetAddr, err)
		return -1
	}
	_ = conn.Close()
	return latencyMs
}

func (p *ProxyServer) probeTCPDirect(serverID, targetAddr string) int64 {
	ctx := context.Background()
	if p != nil && p.ctx != nil {
		ctx = p.ctx
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	startTime := time.Now()
	conn, err := dialer.DialContext(probeCtx, "tcp", targetAddr)
	latencyMs := time.Since(startTime).Milliseconds()
	if err != nil {
		logger.Debug("auto ping direct tcp dial failed: server=%s target=%s err=%v", serverID, targetAddr, err)
		return -1
	}
	_ = conn.Close()
	return latencyMs
}

func (p *ProxyServer) probeHTTPThroughNode(serverID, nodeName string) int64 {
	if p == nil || p.outboundMgr == nil {
		return -1
	}
	cfg, exists := p.outboundMgr.GetOutbound(nodeName)
	if !exists || cfg == nil {
		logger.Debug("auto ping http probe failed: server=%s node=%s err=proxy outbound not found", serverID, nodeName)
		return -1
	}
	ctx := context.Background()
	if p.ctx != nil {
		ctx = p.ctx
	}
	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	dialer, err := NewSingboxCoreFactory().CreateDialer(probeCtx, cfg)
	if err != nil {
		logger.Debug("auto ping http dialer create failed: server=%s node=%s err=%v", serverID, nodeName, err)
		return -1
	}
	defer dialer.Close()
	return doHTTPProbe(probeCtx, serverID, "node="+nodeName, func(transport *http.Transport) {
		transport.DialContext = dialer.DialContext
	})
}

func (p *ProxyServer) probeHTTPDirect(serverID string) int64 {
	ctx := context.Background()
	if p != nil && p.ctx != nil {
		ctx = p.ctx
	}
	probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	return doHTTPProbe(probeCtx, serverID, "node=direct", nil)
}

func doHTTPProbe(ctx context.Context, serverID, label string, customizeTransport func(*http.Transport)) int64 {
	transport := &http.Transport{
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   1,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	if customizeTransport != nil {
		customizeTransport(transport)
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   12 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultAutoPingHTTPProbeURL, nil)
	if err != nil {
		logger.Debug("auto ping http request create failed: server=%s %s err=%v", serverID, label, err)
		return -1
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (MCPE Proxy AutoPing)")
	req.Header.Set("Accept", "*/*")

	startTime := time.Now()
	resp, err := client.Do(req)
	latencyMs := time.Since(startTime).Milliseconds()
	if err != nil {
		logger.Debug("auto ping http failed: server=%s %s url=%s err=%v", serverID, label, defaultAutoPingHTTPProbeURL, err)
		return -1
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		logger.Debug("auto ping http non-success: server=%s %s status=%d", serverID, label, resp.StatusCode)
		return -1
	}
	return latencyMs
}

func buildRakNetPingPacket() []byte {
	pkt := make([]byte, 33)
	pkt[0] = raknetUnconnectedPing
	binary.BigEndian.PutUint64(pkt[1:9], uint64(time.Now().UnixMilli()))
	copy(pkt[9:25], raknetMagic)
	binary.BigEndian.PutUint64(pkt[25:33], uint64(12345678901234567))
	return pkt
}

func resolveUDPAddrWithContext(ctx context.Context, address string) (*net.UDPAddr, error) {
	_, udpAddr, err := buildUDPDestinationAddr(ctx, address, false)
	if err != nil {
		return nil, err
	}
	return udpAddr, nil
}

func resolveUDPAddr(address string) (*net.UDPAddr, error) {
	return resolveUDPAddrWithContext(context.Background(), address)
}

func ResolveUDPAddress(address string) (*net.UDPAddr, error) {
	return resolveUDPAddr(address)
}

func ResolveUDPAddressContext(ctx context.Context, address string) (*net.UDPAddr, error) {
	return resolveUDPAddrWithContext(ctx, address)
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

	cfgForListener := serverCfg
	var cleanup func() error
	if serverCfg.UDPSpeeder != nil && serverCfg.UDPSpeeder.Enabled {
		proc, localAddr, err := startUDPSpeeder(serverCfg.ID, serverCfg)
		if err != nil {
			return err
		}
		if proc != nil {
			_, portStr, err := net.SplitHostPort(localAddr)
			if err != nil {
				_ = proc.Stop()
				return fmt.Errorf("udp_speeder local_listen_addr invalid: %w", err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				_ = proc.Stop()
				return fmt.Errorf("udp_speeder local_listen_addr invalid: %w", err)
			}
			cfgCopy := *serverCfg
			cfgCopy.Target = "127.0.0.1"
			cfgCopy.Port = port
			cfgCopy.UDPSpeeder = nil
			cfgForListener = &cfgCopy
			cleanup = proc.Stop
		}
	}

	var listener Listener
	protocol := strings.ToLower(cfgForListener.Protocol)
	proxyMode := cfgForListener.GetProxyMode()

	if protocol != "" && protocol != "raknet" {
		switch protocol {
		case "udp":
			udpProxy := NewPlainUDPProxy(serverCfg.ID, cfgForListener)
			if p.outboundMgr != nil {
				udpProxy.SetOutboundManager(p.outboundMgr)
			}
			listener = udpProxy
			logger.Info("Using plain UDP forwarding for server %s", serverCfg.ID)
		case "tcp":
			tcpProxy := NewPlainTCPProxy(serverCfg.ID, cfgForListener)
			if p.outboundMgr != nil {
				tcpProxy.SetOutboundManager(p.outboundMgr)
			}
			listener = tcpProxy
			logger.Info("Using plain TCP forwarding for server %s", serverCfg.ID)
		case "tcp_udp":
			udpProxy := NewPlainUDPProxy(serverCfg.ID, cfgForListener)
			tcpProxy := NewPlainTCPProxy(serverCfg.ID, cfgForListener)
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
				cfgForListener,
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
				cfgForListener,
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
				cfgForListener,
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
				cfgForListener,
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
				cfgForListener,
				p.bufferPool,
				p.sessionMgr,
				p.forwarder,
				p.configMgr,
			)
			listener = udpListener
			logger.Debug("Using transparent proxy mode for server %s", serverCfg.ID)
		}
	}

	if cleanup != nil {
		listener = &listenerWithCleanup{inner: listener, cleanup: cleanup}
	}

	// Start the listener
	if err := listener.Start(); err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
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
				existingKind := listenerKind(existingListener)
				desiredKind := listenerKindFromConfig(serverCfg)
				if existingKind != desiredKind {
					if err := p.stopListener(serverCfg.ID); err != nil {
						logger.Error("Failed to stop listener for server %s during restart: %v", serverCfg.ID, err)
						continue
					}
					if err := p.startListener(serverCfg); err != nil {
						logger.Error("Failed to restart listener for server %s: %v", serverCfg.ID, err)
					}
					continue
				}

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

func listenerKind(l Listener) string {
	switch l.(type) {
	case *PlainUDPProxy:
		return "udp"
	case *PlainTCPProxy:
		return "tcp"
	case *combinedListener:
		return "tcp_udp"
	case *MITMProxy:
		return "mitm"
	case *RakNetProxy:
		return "raknet"
	case *PassthroughProxy:
		return "passthrough"
	case *RawUDPProxy:
		return "raw_udp"
	case *UDPListener:
		return "transparent"
	default:
		return fmt.Sprintf("%T", l)
	}
}

func listenerKindFromConfig(serverCfg *config.ServerConfig) string {
	if serverCfg == nil {
		return ""
	}
	protocolValue := strings.ToLower(serverCfg.Protocol)
	proxyMode := serverCfg.GetProxyMode()

	if protocolValue != "" && protocolValue != "raknet" {
		switch protocolValue {
		case "udp":
			return "udp"
		case "tcp":
			return "tcp"
		case "tcp_udp":
			return "tcp_udp"
		}
	}

	switch proxyMode {
	case "mitm":
		return "mitm"
	case "raknet":
		return "raknet"
	case "passthrough":
		return "passthrough"
	case "raw_udp":
		return "raw_udp"
	default:
		return "transparent"
	}
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
	if p == nil || p.sessionMgr == nil {
		return 0
	}
	return p.sessionMgr.Count()
}

func (p *ProxyServer) GetActiveProxyPortConnectionCount() int {
	if p == nil || p.proxyPortManager == nil {
		return 0
	}
	return p.proxyPortManager.GetActiveConnectionCount()
}

func (p *ProxyServer) GetActiveConnectionsForProxyPort(portID string) int {
	if p == nil || p.proxyPortManager == nil {
		return 0
	}
	return p.proxyPortManager.GetActiveConnectionCountForPort(portID)
}

// GetActiveSessionsForServer returns the number of active sessions for a specific server.
func (p *ProxyServer) GetActiveSessionsForServer(serverID string) int {
	if p == nil || p.sessionMgr == nil {
		return 0
	}
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
	now := time.Now()
	if p.sessionMgr != nil {
		sessions := p.sessionMgr.GetAllSessions()
		for _, sess := range sessions {
			sessionCounts[sess.ServerID]++
		}
	}

	for _, server := range servers {
		status := p.GetServerStatus(server.ID)
		activeSessions := sessionCounts[server.ID]
		dto := server.ToDTO(status, activeSessions)
		dto.AutoPingIntervalMinutes = p.effectiveServerAutoPingIntervalMinutes(server)
		dto.AutoPingTopCandidates = p.effectiveServerAutoPingTopCandidates(server)
		dto.LastAutoPingAt, dto.NextAutoPingAt = p.getServerAutoPingSchedule(server, status, now)
		result = append(result, dto)
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
			status := "kicked"
			switch {
			case strings.Contains(reason, "黑名单用户"):
				status = "blacklist"
			case strings.Contains(reason, "白名单") || strings.Contains(reason, "不在白名单"):
				status = "whitelist"
			}
			sess.SetDisconnectStatus(status, reason)
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
