// Package proxy provides the core UDP proxy functionality.
// This implements a raw UDP forwarding proxy that forwards UDP packets
// without any RakNet protocol processing, similar to doc/portf/main.go.
// It also parses RakNet packets to extract player info and log disconnect messages.
package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/session"

	"github.com/golang-jwt/jwt/v4"
	mcprotocol "github.com/sandertv/gophertunnel/minecraft/protocol"
	mcpacket "github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

const (
	// MaxUDPPacketSize is the maximum UDP packet size for Minecraft BE
	MaxUDPPacketSize = 8192
	// UDPReadTimeout is the read timeout for UDP connections
	UDPReadTimeout = 30 * time.Second
	// UDPWriteTimeout is the write timeout for UDP connections
	UDPWriteTimeout = 5 * time.Second
	// DefaultClientInactiveTimeout is used when config idle_timeout is not set.
	DefaultClientInactiveTimeout = 5 * time.Minute
	// RawUDPPingRefreshInterval throttles expensive proxy pings (QUIC handshakes).
	RawUDPPingRefreshInterval = 60 * time.Second
	// RawUDPUnconnectedPingMinIntervalPerIP rate-limits server-list pings to reduce CPU under scanning.
	RawUDPUnconnectedPingMinIntervalPerIP = 200 * time.Millisecond
	// RawUDPUnconnectedPingCacheTTL 控制每个 IP 的 ping 时间戳保留时长。
	RawUDPUnconnectedPingCacheTTL = 5 * time.Minute
)

// RakNet packet IDs
const (
	raknetFrameReliable    = 0x80 // 0x80-0x8f are reliable frames
	raknetFrameUnreliable  = 0x00
	raknetGamePacketHeader = 0xfe

	// RakNet disconnect notification
	raknetDisconnectNotification = 0x15

	// RakNet control packet IDs (unconnected)
	raknetUnconnectedPing      = 0x01
	raknetUnconnectedPingOpen  = 0x02
	raknetUnconnectedPong      = 0x1c
	raknetOpenConnectionReq1   = 0x05
	raknetOpenConnectionReply1 = 0x06
	raknetOpenConnectionReq2   = 0x07
	raknetOpenConnectionReply2 = 0x08
)

// splitPacketBuffer stores fragments for reassembly
type splitPacketBuffer struct {
	splitCount int
	fragments  map[int][]byte
	received   int
	totalBytes int
	createdAt  time.Time // For cleanup of incomplete splits
}

// SplitPacketTimeout is the timeout for incomplete split packets (30 seconds)
const SplitPacketTimeout = 30 * time.Second

// MaxSplitPacketsPerClient limits the number of concurrent split packet buffers per client
const MaxSplitPacketsPerClient = 16

// MaxSplitPacketFragments 限制单个分片包的最大分片数量。
const MaxSplitPacketFragments = 128

// MaxSplitPacketBytes 限制单个分片包的最大重组大小。
const MaxSplitPacketBytes = 1024 * 1024

// rawUDPClientInfo stores information about a connected client
type rawUDPClientInfo struct {
	clientAddr       *net.UDPAddr
	targetConn       net.PacketConn // Can be *net.UDPConn or proxy PacketConn
	targetAddr       net.Addr       // Target address for WriteTo
	startTime        time.Time      // Connection start time
	lastSeen         atomic.Int64   // Unix nano timestamp for lock-free access
	bytesUp          atomic.Int64   // Lock-free counter
	bytesDown        atomic.Int64   // Lock-free counter
	packetCount      atomic.Int64   // Lock-free counter
	playerName       string         // Extracted from Login packet
	playerUUID       string
	playerXUID       string
	proxyNode        string                        // Name of the proxy node used (empty if direct)
	loginParsed      atomic.Bool                   // Whether we've tried to parse login
	sessionID        string                        // Session ID for session manager
	splitPackets     map[uint16]*splitPacketBuffer // splitID -> buffer for reassembly
	compressionID    atomic.Uint32                 // Compression ID observed from client's Login packet (0x00/0x01/0xff)
	sendDatagramSeq  atomic.Uint32                 // Best-effort outgoing datagram sequence for injected packets (24-bit)
	sendMessageIndex atomic.Uint32                 // Best-effort outgoing messageIndex for reliable packets (24-bit)
	sendOrderIndex   atomic.Uint32                 // Best-effort outgoing orderIndex for reliable ordered packets (24-bit)
	encrypted        atomic.Bool                   // Whether we observed encrypted MC packets (0xfe + unknown ID)
	kicked           atomic.Bool                   // Whether this client was kicked
	mu               sync.Mutex                    // Only for splitPackets and player info writes
}

// initSplitPackets initializes the split packet map if needed
func (c *rawUDPClientInfo) initSplitPackets() {
	if c.splitPackets == nil {
		c.splitPackets = make(map[uint16]*splitPacketBuffer)
	}
}

// cleanupStaleSplitPackets removes split packet buffers that have timed out
// Must be called with c.mu held
func (c *rawUDPClientInfo) cleanupStaleSplitPackets() {
	if c.splitPackets == nil {
		return
	}
	now := time.Now()
	for splitID, buf := range c.splitPackets {
		if now.Sub(buf.createdAt) > SplitPacketTimeout {
			delete(c.splitPackets, splitID)
		}
	}
}

// addSplitPacket adds a split packet buffer, enforcing limits
// Must be called with c.mu held
func (c *rawUDPClientInfo) addSplitPacket(splitID uint16, buf *splitPacketBuffer) bool {
	c.initSplitPackets()
	// Clean up stale buffers first
	c.cleanupStaleSplitPackets()
	// Check limit
	if len(c.splitPackets) >= MaxSplitPacketsPerClient {
		// Remove oldest buffer to make room
		var oldestID uint16
		var oldestTime time.Time
		for id, b := range c.splitPackets {
			if oldestTime.IsZero() || b.createdAt.Before(oldestTime) {
				oldestID = id
				oldestTime = b.createdAt
			}
		}
		delete(c.splitPackets, oldestID)
	}
	c.splitPackets[splitID] = buf
	return true
}

// IPBanDuration is how long an IP stays banned after being kicked
const IPBanDuration = 5 * time.Minute

// bannedIPInfo stores information about a banned IP
type bannedIPInfo struct {
	playerName string
	reason     string
	bannedAt   time.Time
	expiresAt  time.Time
}

// RawUDPProxy implements a raw UDP forwarding proxy.
// It forwards UDP packets directly without any RakNet protocol processing.
type RawUDPProxy struct {
	serverID         string
	config           *config.ServerConfig
	configMgr        *config.ConfigManager
	sessionMgr       *session.SessionManager
	aclManager       ACLManager       // ACL manager for whitelist/blacklist
	externalVerifier ExternalVerifier // External auth verifier (defined in passthrough_proxy.go)
	listener         *net.UDPConn
	targetAddr       *net.UDPAddr
	clients          sync.Map // map[string]*rawUDPClientInfo (clientAddr.String() -> info)
	bannedIPs        sync.Map // map[string]*bannedIPInfo (IP without port -> ban info)
	closed           atomic.Bool
	wg               sync.WaitGroup
	ctx              context.Context
	cancel           context.CancelFunc
	outboundMgr      OutboundManager

	// Latency monitoring
	cachedLatency int64  // Cached latency in milliseconds (-1 = offline)
	cachedPong    []byte // Cached server advertisement (MOTD string, not the full RakNet pong packet)
	latencyMu     sync.RWMutex
	serverGUID    atomic.Uint64
	lastPingTry   atomic.Int64
	pingInFlight  atomic.Bool

	clientInactiveTimeout time.Duration

	// Basic unconnected ping rate limiting (per source IP, port-less).
	lastUnconnectedPing sync.Map // map[string]int64 unixnano
}

// ACLManager interface for access control
type ACLManager interface {
	CheckAccess(playerName, serverID string) (allowed bool, reason string)
}

// NewRawUDPProxy creates a new raw UDP forwarding proxy.
func NewRawUDPProxy(
	serverID string,
	cfg *config.ServerConfig,
	configMgr *config.ConfigManager,
	sessionMgr *session.SessionManager,
) *RawUDPProxy {
	return &RawUDPProxy{
		serverID:   serverID,
		config:     cfg,
		configMgr:  configMgr,
		sessionMgr: sessionMgr,
	}
}

// SetACLManager sets the ACL manager for access control
func (p *RawUDPProxy) SetACLManager(aclMgr ACLManager) {
	p.aclManager = aclMgr
}

// SetExternalVerifier sets the external verifier for auth verification
func (p *RawUDPProxy) SetExternalVerifier(verifier ExternalVerifier) {
	p.externalVerifier = verifier
}

// SetOutboundManager sets the outbound manager for proxy routing.
func (p *RawUDPProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

// GetOutboundManager returns the outbound manager.
func (p *RawUDPProxy) GetOutboundManager() OutboundManager {
	return p.outboundMgr
}

// UpdateConfig updates the server configuration.
func (p *RawUDPProxy) UpdateConfig(cfg *config.ServerConfig) {
	oldTarget := p.config.GetTargetAddr()
	p.config = cfg
	p.updateTimeouts()
	newTarget := cfg.GetTargetAddr()

	// Update target address if changed
	if oldTarget != newTarget {
		targetAddr, err := net.ResolveUDPAddr("udp", newTarget)
		if err != nil {
			logger.Error("RawUDPProxy: Failed to resolve new target address %s: %v", newTarget, err)
		} else {
			p.targetAddr = targetAddr
			logger.Info("RawUDPProxy: Target address updated from %s to %s for server %s (existing clients preserved)", oldTarget, newTarget, p.serverID)
			if p.config.IsShowRealLatency() {
				p.maybeRefreshPingCacheAsync(true)
			}
		}
	}

	logger.Debug("RawUDPProxy config updated for server %s", p.serverID)
}

// Start begins listening for UDP packets.
func (p *RawUDPProxy) Start() error {
	p.updateTimeouts()

	// Parse listen address
	listenAddr, err := net.ResolveUDPAddr("udp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address: %w", err)
	}

	// Parse target address
	targetAddr, err := net.ResolveUDPAddr("udp", p.config.GetTargetAddr())
	if err != nil {
		return fmt.Errorf("failed to resolve target address: %w", err)
	}
	p.targetAddr = targetAddr

	// Create UDP listener
	listener, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %w", err)
	}
	p.listener = listener
	p.closed.Store(false)

	// Set socket options
	if err := p.setUDPSocketOptions(listener); err != nil {
		logger.Warn("Failed to set UDP socket options: %v", err)
	}

	// Create cancellable context
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// Initialize cached latency state
	p.latencyMu.Lock()
	p.cachedLatency = -1
	p.cachedPong = nil
	p.latencyMu.Unlock()

	// Default GUID for locally generated pongs (stable per server ID)
	p.serverGUID.Store(stableGUIDFromString(p.serverID))

	// If show_real_latency is enabled, proactively populate cache in the background
	// and keep it fresh without doing per-ping outbound dials.
	if p.config.IsShowRealLatency() {
		p.maybeRefreshPingCacheAsync(true)
	}

	// Log proxy mode
	if p.shouldUseProxy() {
		logger.Info("Raw UDP proxy started: id=%s, listen=%s, target=%s (via proxy: %s)",
			p.serverID, p.config.ListenAddr, p.config.GetTargetAddr(), p.config.GetProxyOutbound())
	} else {
		logger.Info("Raw UDP proxy started: id=%s, listen=%s, target=%s (direct)",
			p.serverID, p.config.ListenAddr, p.config.GetTargetAddr())
	}

	return nil
}

// extractIP extracts the IP address without port from an address string
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // Return as-is if can't parse
	}
	return host
}

// banIP adds an IP to the temporary ban list
func (p *RawUDPProxy) banIP(ip, playerName, reason string) {
	now := time.Now()
	banInfo := &bannedIPInfo{
		playerName: playerName,
		reason:     reason,
		bannedAt:   now,
		expiresAt:  now.Add(IPBanDuration),
	}
	p.bannedIPs.Store(ip, banInfo)
	logger.Info("IP %s banned for %v (player: %s, reason: %s)", ip, IPBanDuration, playerName, reason)
}

// isIPBanned checks if an IP is currently banned
// Returns (banned, playerName, reason)
func (p *RawUDPProxy) isIPBanned(ip string) (bool, string, string) {
	if val, ok := p.bannedIPs.Load(ip); ok {
		banInfo := val.(*bannedIPInfo)
		if time.Now().Before(banInfo.expiresAt) {
			return true, banInfo.playerName, banInfo.reason
		}
		// Ban expired, remove it
		p.bannedIPs.Delete(ip)
	}
	return false, "", ""
}

// cleanupExpiredBans removes expired IP bans
func (p *RawUDPProxy) cleanupExpiredBans() {
	now := time.Now()
	p.bannedIPs.Range(func(key, value interface{}) bool {
		banInfo := value.(*bannedIPInfo)
		if now.After(banInfo.expiresAt) {
			p.bannedIPs.Delete(key)
		}
		return true
	})
}

// shouldUseProxy returns true if proxy outbound should be used
func (p *RawUDPProxy) shouldUseProxy() bool {
	return p.outboundMgr != nil && !p.config.IsDirectConnection()
}

// setUDPSocketOptions sets buffer sizes for UDP connections
func (p *RawUDPProxy) setUDPSocketOptions(conn *net.UDPConn) error {
	bufferSize := MaxUDPPacketSize * 10

	if err := conn.SetReadBuffer(bufferSize); err != nil {
		return fmt.Errorf("set read buffer: %w", err)
	}

	if err := conn.SetWriteBuffer(bufferSize); err != nil {
		return fmt.Errorf("set write buffer: %w", err)
	}

	return nil
}

// Listen starts accepting and forwarding UDP packets.
func (p *RawUDPProxy) Listen(ctx context.Context) error {
	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	// Start client cleanup goroutine
	p.wg.Add(1)
	go p.cleanupInactiveClients()

	// Main packet forwarding loop
	buffer := make([]byte, MaxUDPPacketSize)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.ctx.Done():
			return nil
		default:
			// Set read deadline
			p.listener.SetReadDeadline(time.Now().Add(UDPReadTimeout))

			n, clientAddr, err := p.listener.ReadFromUDP(buffer)
			if err != nil {
				if p.closed.Load() {
					return nil
				}
				if isTimeoutError(err) {
					continue
				}
				logger.Debug("Read UDP error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Handle RakNet unconnected pings without creating sessions.
			// IMPORTANT: never dial proxy outbounds per ping (can cause CPU/GC spikes in production).
			if n > 0 && isRakNetUnconnectedPing(buffer[0]) {
				p.handleUnconnectedPing(buffer[:n], clientAddr)
				continue
			}

			// Check if this is a RakNet disconnect notification from client
			if n > 0 && buffer[0] == raknetDisconnectNotification {
				clientKey := clientAddr.String()
				logger.Debug("Received RakNet disconnect from client %s", clientKey)
				p.removeClient(clientKey)
				continue
			}

			// Get or create client connection
			clientInfo, isNew := p.getOrCreateClient(clientAddr)
			if clientInfo == nil {
				continue
			}

			// Check if client was kicked - don't process packets from kicked clients
			if clientInfo.kicked.Load() {
				continue
			}

			// Update stats (lock-free)
			clientInfo.lastSeen.Store(time.Now().UnixNano())
			clientInfo.bytesUp.Add(int64(n))
			clientInfo.packetCount.Add(1)

			// Update session stats
			if sess, exists := p.sessionMgr.Get(clientInfo.sessionID); exists {
				sess.AddBytesUp(int64(n))
				sess.UpdateLastSeen()
			}

			// Log new connection
			if isNew {
				if p.shouldUseProxy() {
					logger.Info("Raw UDP client connected: %s -> %s (via proxy: %s)", clientAddr.String(), p.targetAddr.String(), clientInfo.proxyNode)
				} else {
					logger.Info("Raw UDP client connected: %s -> %s (direct)", clientAddr.String(), p.targetAddr.String())
				}
			}

			// Check if we need to verify login first (lock-free check)
			loginParsed := clientInfo.loginParsed.Load()

			// If login not yet parsed, check if this packet contains Login
			if !loginParsed {
				// Make a copy only when we need to parse login
				packetCopy := make([]byte, n)
				copy(packetCopy, buffer[:n])

				// Try to detect and parse Login packet
				// This will kick the player if they're on the blacklist
				p.handlePacketWithLoginCheck(packetCopy, clientInfo)

				// Check if player was kicked (lock-free)
				if clientInfo.kicked.Load() {
					// Player was kicked, remove client immediately
					p.removeClient(clientAddr.String())
					continue
				}

				// Forward the packet (whether or not it's a Login packet)
				clientInfo.targetConn.SetWriteDeadline(time.Now().Add(UDPWriteTimeout))
				_, err = clientInfo.targetConn.WriteTo(packetCopy, clientInfo.targetAddr)
			} else {
				// Login already parsed, forward directly without copying
				clientInfo.targetConn.SetWriteDeadline(time.Now().Add(UDPWriteTimeout))
				_, err = clientInfo.targetConn.WriteTo(buffer[:n], clientInfo.targetAddr)
			}

			if err != nil {
				if !isTimeoutError(err) {
					logger.Debug("Write to target failed for %s: %v", clientAddr.String(), err)
				}
				p.removeClient(clientAddr.String())
				continue
			}
		}
	}
}

// getOrCreateClient gets or creates a client connection
func (p *RawUDPProxy) getOrCreateClient(clientAddr *net.UDPAddr) (*rawUDPClientInfo, bool) {
	clientKey := clientAddr.String()

	// Check if client already exists
	if val, ok := p.clients.Load(clientKey); ok {
		existingClient := val.(*rawUDPClientInfo)
		// If client was kicked, remove it and create a new one
		if existingClient.kicked.Load() {
			logger.Info("RawUDP: Removing kicked client %s for reconnection", clientKey)
			p.clients.Delete(clientKey)
			// Close the old connection
			existingClient.targetConn.Close()
		} else {
			return existingClient, false
		}
	}

	logger.Debug("RawUDP: Creating new client for %s", clientKey)

	var targetConn net.PacketConn
	var targetAddr net.Addr
	var err error
	var selectedNode string

	// Create connection to target (direct or via proxy)
	if p.shouldUseProxy() {
		// Use proxy outbound
		targetConn, selectedNode, err = p.dialThroughProxy()
		if err != nil {
			logger.Error("Failed to connect to target %s via proxy: %v", p.targetAddr.String(), err)
			return nil, false
		}
		targetAddr = p.targetAddr
	} else {
		// Direct connection
		directConn, dialErr := net.DialUDP("udp", nil, p.targetAddr)
		if dialErr != nil {
			logger.Error("Failed to connect to target %s: %v", p.targetAddr.String(), dialErr)
			return nil, false
		}
		// Set socket options
		if err := p.setUDPSocketOptions(directConn); err != nil {
			logger.Warn("Failed to set target socket options: %v", err)
		}
		targetConn = directConn
		targetAddr = p.targetAddr
	}

	// NOTE: Session is NOT created here - it will be created when Login packet is parsed
	// This prevents empty DisplayName sessions from appearing in the session list

	now := time.Now()
	clientInfo := &rawUDPClientInfo{
		clientAddr: clientAddr,
		targetConn: targetConn,
		targetAddr: targetAddr,
		startTime:  now,
		sessionID:  clientKey,
		proxyNode:  selectedNode,
	}
	clientInfo.lastSeen.Store(now.UnixNano())

	// Store client
	p.clients.Store(clientKey, clientInfo)

	// Start response forwarding goroutine
	p.wg.Add(1)
	go p.forwardResponses(clientAddr, clientInfo)

	return clientInfo, true
}

// dialThroughProxy creates a PacketConn through the proxy outbound
// Returns the connection and the name of the selected outbound node
func (p *RawUDPProxy) dialThroughProxy() (net.PacketConn, string, error) {
	return p.dialThroughProxyWithTimeout(15 * time.Second)
}

func (p *RawUDPProxy) dialThroughProxyWithTimeout(timeout time.Duration) (net.PacketConn, string, error) {
	baseCtx := p.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	proxyOutbound := p.config.GetProxyOutbound()
	targetAddr := p.config.GetTargetAddr()

	// Check if this is a group or multi-node selection
	if p.config.IsGroupSelection() || p.config.IsMultiNodeSelection() {
		strategy := p.config.GetLoadBalance()
		sortBy := p.config.GetLoadBalanceSort()

		// Select a node using load balancing
		selectedOutbound, err := p.outboundMgr.SelectOutboundWithFailover(proxyOutbound, strategy, sortBy, nil)
		if err != nil {
			return nil, "", fmt.Errorf("no healthy nodes available: %w", err)
		}

		logger.Info("RawUDPProxy: Selected node '%s' for %s", selectedOutbound.Name, targetAddr)
		conn, err := p.outboundMgr.DialPacketConn(ctx, selectedOutbound.Name, targetAddr)
		return conn, selectedOutbound.Name, err
	}

	// Single node mode
	logger.Info("RawUDPProxy: Using single node '%s' for %s", proxyOutbound, targetAddr)
	conn, err := p.outboundMgr.DialPacketConn(ctx, proxyOutbound, targetAddr)
	return conn, proxyOutbound, err
}

// forwardResponses forwards responses from target back to client
func (p *RawUDPProxy) forwardResponses(clientAddr *net.UDPAddr, clientInfo *rawUDPClientInfo) {
	defer p.wg.Done()
	defer p.removeClient(clientAddr.String())

	buffer := make([]byte, MaxUDPPacketSize)

	for {
		select {
		case <-p.ctx.Done():
			return
		default:
			// Check if client was kicked (lock-free)
			if clientInfo.kicked.Load() {
				return
			}

			// Set read deadline
			clientInfo.targetConn.SetReadDeadline(time.Now().Add(UDPReadTimeout))

			n, _, err := clientInfo.targetConn.ReadFrom(buffer)
			if err != nil {
				if p.closed.Load() {
					return
				}
				// Check if kicked (connection closed)
				if clientInfo.kicked.Load() {
					return
				}
				if err == io.EOF {
					return
				}
				if !isTimeoutError(err) {
					// Only log if not kicked
					if !strings.Contains(err.Error(), "use of closed") {
						logger.Debug("Read from target failed for %s: %v", clientAddr.String(), err)
					}
					return
				}
				// Check if client is still active (lock-free)
				lastSeenNano := clientInfo.lastSeen.Load()
				if time.Since(time.Unix(0, lastSeenNano)) > p.clientInactiveTimeout {
					logger.Debug("Client %s inactive, closing connection", clientAddr.String())
					return
				}
				continue
			}

			// Check if this is a RakNet disconnect notification from server
			if n > 0 && buffer[0] == raknetDisconnectNotification {
				logger.Debug("Received RakNet disconnect from server for client %s", clientAddr.String())
				// Forward to client and then close
				p.listener.WriteToUDP(buffer[:n], clientAddr)
				return
			}

			// Update stats (lock-free)
			clientInfo.bytesDown.Add(int64(n))
			clientInfo.lastSeen.Store(time.Now().UnixNano())

			p.updateRakNetSendStateFromDatagram(buffer[:n], clientInfo)

			// Update session stats
			if sess, exists := p.sessionMgr.Get(clientInfo.sessionID); exists {
				sess.AddBytesDown(int64(n))
				sess.UpdateLastSeen()
			}

			// Forward to client directly without parsing (parsing causes memory allocation)
			p.listener.SetWriteDeadline(time.Now().Add(UDPWriteTimeout))
			_, err = p.listener.WriteToUDP(buffer[:n], clientAddr)
			if err != nil {
				if !isTimeoutError(err) {
					logger.Debug("Write to client %s failed: %v", clientAddr.String(), err)
				}
				return
			}
		}
	}
}

func (p *RawUDPProxy) updateRakNetSendStateFromDatagram(datagram []byte, clientInfo *rawUDPClientInfo) {
	// RakNet datagrams have bitFlagDatagram (0x80) set in the first byte.
	if len(datagram) < 4 || (datagram[0]&0x80) == 0 {
		return
	}

	// Update datagram sequence (24-bit LE).
	seq := uint32(datagram[1]) | uint32(datagram[2])<<8 | uint32(datagram[3])<<16
	atomicMaxUint24(&clientInfo.sendDatagramSeq, seq)

	// Parse encapsulated packets to learn the current messageIndex/orderIndex used by the remote server.
	offset := 4
	for offset < len(datagram) {
		// Need: flags(1) + bitLength(2)
		if offset+3 > len(datagram) {
			return
		}

		flags := datagram[offset]
		offset++

		bitLength := uint16(datagram[offset])<<8 | uint16(datagram[offset+1])
		offset += 2
		byteLength := (int(bitLength) + 7) / 8

		reliability := (flags >> 5) & 0x07

		// messageIndex (reliable)
		if reliability == 2 || reliability == 3 || reliability == 4 || reliability == 6 || reliability == 7 {
			if offset+3 > len(datagram) {
				return
			}
			msgIndex := uint32(datagram[offset]) | uint32(datagram[offset+1])<<8 | uint32(datagram[offset+2])<<16
			offset += 3
			atomicMaxUint24(&clientInfo.sendMessageIndex, msgIndex)
		}

		// sequenceIndex (sequenced)
		if reliability == 1 || reliability == 4 {
			if offset+3 > len(datagram) {
				return
			}
			offset += 3
		}

		// orderIndex + channel (ordered)
		if reliability == 1 || reliability == 3 || reliability == 4 || reliability == 7 {
			if offset+4 > len(datagram) {
				return
			}
			orderIndex := uint32(datagram[offset]) | uint32(datagram[offset+1])<<8 | uint32(datagram[offset+2])<<16
			offset += 3
			orderChannel := datagram[offset]
			offset++
			// Most MCBE traffic uses channel 0. Tracking only channel 0 keeps this lightweight.
			if orderChannel == 0 {
				atomicMaxUint24(&clientInfo.sendOrderIndex, orderIndex)
			}
		}

		// split info
		if (flags & 0x10) != 0 {
			if offset+10 > len(datagram) {
				return
			}
			offset += 10
		}

		// payload
		if offset+byteLength > len(datagram) {
			return
		}

		// Detect encrypted MC packets after Login: game packets start with 0xfe, but the compression byte becomes random when encrypted.
		if byteLength >= 2 && datagram[offset] == 0xfe {
			compID := datagram[offset+1]
			if clientInfo.loginParsed.Load() && compID != 0x00 && compID != 0x01 && compID != 0xff {
				clientInfo.encrypted.Store(true)
			}
		}

		offset += byteLength
	}
}

func atomicMaxUint24(a *atomic.Uint32, v uint32) {
	v &= 0xFFFFFF
	for {
		cur := a.Load() & 0xFFFFFF
		if cur >= v {
			return
		}
		if a.CompareAndSwap(cur, v) {
			return
		}
	}
}

// removeClient removes a client and closes its connection
func (p *RawUDPProxy) removeClient(clientKey string) {
	if val, ok := p.clients.LoadAndDelete(clientKey); ok {
		clientInfo := val.(*rawUDPClientInfo)
		clientInfo.targetConn.Close()

		// Read stats (lock-free)
		bytesUp := clientInfo.bytesUp.Load()
		bytesDown := clientInfo.bytesDown.Load()
		kicked := clientInfo.kicked.Load()

		// Read player info and clear splitPackets (needs lock)
		clientInfo.mu.Lock()
		playerName := clientInfo.playerName
		playerUUID := clientInfo.playerUUID
		// Clear splitPackets to release memory
		clientInfo.splitPackets = nil
		clientInfo.mu.Unlock()

		startTime := clientInfo.startTime
		duration := time.Since(startTime)
		totalBytes := bytesUp + bytesDown

		// Format duration
		durationStr := formatDuration(duration)

		// Log with player info if available
		if playerName != "" {
			if kicked {
				logger.Info("Player kicked: name=%s, uuid=%s, client=%s, duration=%s, up=%s, down=%s, total=%s",
					playerName, playerUUID, clientKey, durationStr,
					formatBytes(bytesUp), formatBytes(bytesDown), formatBytes(totalBytes))
			} else {
				logger.Info("Player disconnected: name=%s, uuid=%s, client=%s, duration=%s, up=%s, down=%s, total=%s",
					playerName, playerUUID, clientKey, durationStr,
					formatBytes(bytesUp), formatBytes(bytesDown), formatBytes(totalBytes))
			}
		} else {
			logger.Info("Raw UDP client disconnected: %s, duration=%s, up=%s, down=%s, total=%s",
				clientKey, durationStr, formatBytes(bytesUp), formatBytes(bytesDown), formatBytes(totalBytes))
		}

		// Remove session
		if err := p.sessionMgr.Remove(clientKey); err != nil {
			logger.Debug("Failed to remove session for %s: %v", clientKey, err)
		}
	}
}

// formatDuration formats duration in human readable format
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm%ds", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}

// formatBytes formats bytes in human readable format
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// cleanupInactiveClients periodically removes inactive clients
func (p *RawUDPProxy) cleanupInactiveClients() {
	defer p.wg.Done()

	// Check every 10 seconds for faster cleanup
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.cleanupExpiredBans()
			p.cleanupUnconnectedPingLimiter()
			now := time.Now()
			p.clients.Range(func(key, value interface{}) bool {
				clientInfo := value.(*rawUDPClientInfo)
				lastSeenNano := clientInfo.lastSeen.Load()
				inactive := now.Sub(time.Unix(0, lastSeenNano)) > p.clientInactiveTimeout

				if inactive {
					logger.Debug("Cleaning up inactive client: %s", key.(string))
					p.removeClient(key.(string))
				} else {
					// Clean up stale split packets for active clients
					clientInfo.mu.Lock()
					clientInfo.cleanupStaleSplitPackets()
					clientInfo.mu.Unlock()
				}
				return true
			})
		}
	}
}

func (p *RawUDPProxy) cleanupUnconnectedPingLimiter() {
	now := time.Now()
	p.lastUnconnectedPing.Range(func(key, value interface{}) bool {
		last, ok := value.(int64)
		if !ok || now.Sub(time.Unix(0, last)) > RawUDPUnconnectedPingCacheTTL {
			p.lastUnconnectedPing.Delete(key)
		}
		return true
	})
}

func (p *RawUDPProxy) updateTimeouts() {
	timeout := DefaultClientInactiveTimeout
	if p.config != nil && p.config.IdleTimeout > 0 {
		timeout = time.Duration(p.config.IdleTimeout) * time.Second
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	p.clientInactiveTimeout = timeout
}

// Stop stops the proxy and closes all connections.
func (p *RawUDPProxy) Stop() error {
	if p.closed.Swap(true) {
		return nil // Already closed
	}

	// Cancel context
	if p.cancel != nil {
		p.cancel()
	}

	// Close listener
	if p.listener != nil {
		p.listener.Close()
	}

	// Close all client connections
	p.clients.Range(func(key, value interface{}) bool {
		clientInfo := value.(*rawUDPClientInfo)
		clientInfo.targetConn.Close()
		return true
	})

	// Wait for goroutines
	p.wg.Wait()

	logger.Info("Raw UDP proxy stopped: id=%s", p.serverID)
	return nil
}

// GetServerID returns the server ID.
func (p *RawUDPProxy) GetServerID() string {
	return p.serverID
}

// GetConfig returns the server configuration.
func (p *RawUDPProxy) GetConfig() *config.ServerConfig {
	return p.config
}

// isTimeoutError checks if an error is a timeout error
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

// isRakNetUnconnectedPing checks if a packet is a RakNet unconnected ping packet.
func isRakNetUnconnectedPing(packetID byte) bool {
	switch packetID {
	case raknetUnconnectedPing, raknetUnconnectedPingOpen:
		return true
	default:
		return false
	}
}

func (p *RawUDPProxy) handleUnconnectedPing(data []byte, clientAddr *net.UDPAddr) {
	// Basic per-IP rate limiting to reduce CPU under public port scanning.
	ipKey := clientAddr.IP.String()
	nowNano := time.Now().UnixNano()
	if v, ok := p.lastUnconnectedPing.Load(ipKey); ok {
		last := v.(int64)
		if time.Duration(nowNano-last) < RawUDPUnconnectedPingMinIntervalPerIP {
			return
		}
	}
	p.lastUnconnectedPing.Store(ipKey, nowNano)

	// Parse ping timestamp (8 bytes big-endian).
	if len(data) < 1+8 {
		return
	}
	pingTimestamp := binary.BigEndian.Uint64(data[1 : 1+8])

	// Refresh cached remote advertisement/latency in the background (throttled).
	p.maybeRefreshPingCacheAsync(false)

	// Choose advertisement to return.
	advertisement := p.getCachedAdvertisementForClient()
	latency := p.getCachedLatencyNoRefresh()
	if p.config != nil && p.config.IsShowRealLatency() {
		advertisement = embedLatencyInMOTDBytes(advertisement, latency)
	}

	pong := buildUnconnectedPongPacket(pingTimestamp, p.serverGUID.Load(), advertisement)
	p.listener.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := p.listener.WriteToUDP(pong, clientAddr); err != nil && !isTimeoutError(err) {
		logger.Debug("Failed to send unconnected pong to %s: %v", clientAddr.String(), err)
	}
}

func (p *RawUDPProxy) getCachedLatencyNoRefresh() int64 {
	p.latencyMu.RLock()
	defer p.latencyMu.RUnlock()
	return p.cachedLatency
}

func (p *RawUDPProxy) getCachedAdvertisementForAPI() []byte {
	p.latencyMu.RLock()
	cached := p.cachedPong
	p.latencyMu.RUnlock()
	if len(cached) > 0 {
		return cached
	}
	if p.config != nil {
		if custom := p.config.GetCustomMOTD(); custom != "" {
			return []byte(custom)
		}
	}
	return nil
}

func (p *RawUDPProxy) getCachedAdvertisementForClient() []byte {
	// Prefer custom MOTD for clients (matches other proxy modes).
	if p.config != nil {
		if custom := p.config.GetCustomMOTD(); custom != "" {
			return []byte(custom)
		}
	}
	p.latencyMu.RLock()
	cached := p.cachedPong
	p.latencyMu.RUnlock()
	if len(cached) > 0 {
		return cached
	}
	return defaultAdvertisementForServer(p.serverID)
}

func (p *RawUDPProxy) maybeRefreshPingCacheAsync(force bool) {
	now := time.Now()
	lastTry := time.Unix(0, p.lastPingTry.Load())
	if !force && !lastTry.IsZero() && now.Sub(lastTry) < RawUDPPingRefreshInterval {
		return
	}
	if !p.pingInFlight.CompareAndSwap(false, true) {
		return
	}
	p.lastPingTry.Store(now.UnixNano())

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer p.pingInFlight.Store(false)
		if p.closed.Load() {
			return
		}
		_ = p.pingTargetServer()
	}()
}

// ============================================================================
// RakNet Packet Parsing (for extracting player info and disconnect messages)
// ============================================================================

// handlePacketWithLoginCheck checks if packet contains Login, verifies player
// If player is on blacklist, kicks them and returns false
// Returns true if packet should be forwarded, false if player was kicked
func (p *RawUDPProxy) handlePacketWithLoginCheck(data []byte, clientInfo *rawUDPClientInfo) bool {
	if len(data) == 0 {
		return true
	}

	// Only need to perform Login parsing/ACL check once per session.
	if clientInfo.loginParsed.Load() {
		return true
	}

	frameType := data[0]

	// Only reliable frames (0x80-0x8f) can contain Login packets
	if frameType < 0x80 || frameType > 0x8f {
		return true // Not a reliable frame, forward it
	}

	// Always try to parse Login packet until we find one (no packet count limit)
	// This ensures reconnecting players are always checked

	// Try to extract game packet from RakNet frame (with split packet reassembly)
	gamePacket := p.extractGamePacketWithSplit(data, clientInfo)
	if gamePacket == nil {
		return true // Not a complete game packet yet
	}

	// Quick check: game packets start with 0xfe
	if len(gamePacket) < 3 || gamePacket[0] != raknetGamePacketHeader {
		return true // Not a game packet
	}

	// Try to parse as Login packet
	playerName, playerUUID, playerXUID := p.parseLoginPacket(gamePacket)
	if playerName == "" {
		// Not a Login packet, forward it
		return true
	}

	// This is a Login packet! Parse and verify before forwarding
	clientInfo.mu.Lock()
	clientInfo.playerName = playerName
	clientInfo.playerUUID = playerUUID
	clientInfo.playerXUID = playerXUID
	clientInfo.mu.Unlock()
	clientInfo.loginParsed.Store(true)
	clientInfo.compressionID.Store(uint32(gamePacket[1]))

	// Create session NOW (only after Login packet is parsed with player info)
	sess, _ := p.sessionMgr.GetOrCreate(clientInfo.sessionID, p.serverID)
	if sess != nil {
		sess.SetPlayerInfoWithXUID(playerUUID, playerName, playerXUID)
		sess.UpdateLastSeen()
		logger.Debug("Created session %s with player info: name=%s", clientInfo.sessionID, playerName)
	}

	logger.Info("Player login detected: name=%s, uuid=%s, xuid=%s, client=%s",
		playerName, playerUUID, playerXUID, clientInfo.clientAddr.String())

	// Check ACL (whitelist/blacklist) BEFORE forwarding Login packet
	if p.aclManager != nil {
		logger.Info("RawUDP ACL check: player=%s, serverID=%s", playerName, p.serverID)
		allowed, reason := p.aclManager.CheckAccess(playerName, p.serverID)

		if !allowed {
			logger.Info("Player %s blocked by ACL (serverID=%s): %s", playerName, p.serverID, reason)

			// Send disconnect packet to client
			p.sendDisconnectToClient(clientInfo, reason)

			// Mark as kicked and close connection
			clientInfo.kicked.Store(true)
			clientInfo.targetConn.Close()

			return false // Player kicked
		}
		logger.Info("Player %s passed ACL check (serverID=%s)", playerName, p.serverID)
	} else {
		logger.Warn("RawUDP: aclManager is nil, skipping ACL check for player %s", playerName)
	}

	// Check external auth verification (URL authorization)
	if p.externalVerifier != nil && p.externalVerifier.IsEnabled() {
		allowed, reason := p.externalVerifier.Verify(playerXUID, playerUUID, playerName, p.serverID, clientInfo.clientAddr.String())

		if !allowed {
			logger.Info("Player %s blocked by external auth: %s", playerName, reason)

			// Send disconnect packet to client
			if reason == "" {
				reason = "授权验证失败"
			}
			p.sendDisconnectToClient(clientInfo, reason)

			// Mark as kicked and close connection
			clientInfo.kicked.Store(true)
			clientInfo.targetConn.Close()

			return false // Player kicked
		}
		logger.Debug("Player %s passed external auth check", playerName)
	}

	// All checks passed
	logger.Info("Player connected: name=%s, uuid=%s, xuid=%s, client=%s",
		playerName, playerUUID, playerXUID, clientInfo.clientAddr.String())

	return true // Forward Login packet
}

// tryParseClientPacket is deprecated - use handlePacketWithLoginCheck instead
// Kept for backward compatibility but does nothing now
func (p *RawUDPProxy) tryParseClientPacket(data []byte, clientInfo *rawUDPClientInfo) {
	// All login parsing and verification is now done in handlePacketWithLoginCheck
	// This function is kept for backward compatibility but does nothing
}

// tryParseServerPacket tries to parse server packets for disconnect messages
// Only parses packets that are likely to contain important info (not every packet)
func (p *RawUDPProxy) tryParseServerPacket(data []byte, clientInfo *rawUDPClientInfo) {
	// Skip parsing for most packets to reduce memory allocation
	// Only parse if it looks like a game packet that might contain disconnect info
	if len(data) < 3 {
		return
	}

	// Only parse RakNet reliable frames that might contain disconnect
	frameType := data[0]
	if frameType < 0x80 || frameType > 0x8f {
		return // Not a reliable frame, skip
	}

	// Try to extract game packet from RakNet frame
	gamePacket := p.extractGamePacket(data)
	if gamePacket == nil {
		return
	}

	// Only parse if it's a game packet with known compression
	if len(gamePacket) < 3 || gamePacket[0] != raknetGamePacketHeader {
		return
	}

	// Only parse unencrypted packets (compression ID 0x00, 0x01, or 0xff)
	compressionID := gamePacket[1]
	if compressionID != 0x00 && compressionID != 0x01 && compressionID != 0xff {
		if clientInfo.loginParsed.Load() {
			clientInfo.encrypted.Store(true)
		}
		return // Encrypted, skip
	}

	// Parse important packets (disconnect, play status, etc.)
	p.parseAndLogGamePacket(gamePacket, clientInfo)
}

// extractGamePacket extracts the game packet (0xfe header) from RakNet frame
func (p *RawUDPProxy) extractGamePacket(data []byte) []byte {
	if len(data) < 4 {
		return nil
	}

	// Check if this is a RakNet reliable frame (0x80-0x8f)
	frameType := data[0]
	if frameType >= 0x80 && frameType <= 0x8f {
		// This is a reliable frame, need to parse RakNet encapsulation
		return p.parseRakNetFrame(data, nil)
	}

	// Check if this is directly a game packet (0xfe)
	if frameType == raknetGamePacketHeader {
		return data
	}

	return nil
}

// extractGamePacketWithSplit extracts game packet with split packet reassembly support
func (p *RawUDPProxy) extractGamePacketWithSplit(data []byte, clientInfo *rawUDPClientInfo) []byte {
	if len(data) < 4 {
		return nil
	}

	// Check if this is a RakNet reliable frame (0x80-0x8f)
	frameType := data[0]
	if frameType >= 0x80 && frameType <= 0x8f {
		// This is a reliable frame, need to parse RakNet encapsulation
		return p.parseRakNetFrame(data, clientInfo)
	}

	// Check if this is directly a game packet (0xfe)
	if frameType == raknetGamePacketHeader {
		return data
	}

	return nil
}

// parseRakNetFrame parses a RakNet reliable frame to extract game packets
// If clientInfo is provided, it will handle split packet reassembly
func (p *RawUDPProxy) parseRakNetFrame(data []byte, clientInfo *rawUDPClientInfo) []byte {
	if len(data) < 4 {
		return nil
	}

	// Skip frame type (1 byte) and sequence number (3 bytes LE)
	offset := 4

	// Parse encapsulated packets
	for offset < len(data) {
		if offset+3 > len(data) {
			break
		}

		// Read reliability and flags (1 byte)
		flags := data[offset]
		offset++

		// Read bit length (2 bytes BE)
		if offset+2 > len(data) {
			break
		}
		bitLength := uint16(data[offset])<<8 | uint16(data[offset+1])
		offset += 2
		byteLength := (int(bitLength) + 7) / 8

		// Check reliability type for additional fields
		reliability := (flags >> 5) & 0x07

		// Skip reliable frame index if present (reliability 2, 3, 4, 6, 7)
		if reliability == 2 || reliability == 3 || reliability == 4 || reliability == 6 || reliability == 7 {
			offset += 3 // 3 bytes LE
		}

		// Skip sequenced frame index if present (reliability 1, 4)
		if reliability == 1 || reliability == 4 {
			offset += 3 // 3 bytes LE
		}

		// Skip ordered frame index and channel if present (reliability 1, 3, 4, 7)
		if reliability == 1 || reliability == 3 || reliability == 4 || reliability == 7 {
			offset += 4 // 3 bytes index + 1 byte channel
		}

		// Check for split packet
		hasSplit := (flags & 0x10) != 0
		var splitCount uint32
		var splitID uint16
		var splitIndex uint32

		if hasSplit {
			if offset+10 > len(data) {
				break
			}
			// Split count (4 bytes BE)
			splitCount = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
			offset += 4
			// Split ID (2 bytes BE)
			splitID = uint16(data[offset])<<8 | uint16(data[offset+1])
			offset += 2
			// Split index (4 bytes BE)
			splitIndex = uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
			offset += 4
		}

		// Read payload
		if offset+byteLength > len(data) {
			break
		}

		payload := data[offset : offset+byteLength]
		offset += byteLength

		// Handle split packets
		if hasSplit && clientInfo != nil {
			reassembled := p.handleSplitPacket(clientInfo, splitID, splitIndex, splitCount, payload)
			if reassembled != nil {
				// Check if reassembled payload is a game packet
				if len(reassembled) > 0 && reassembled[0] == raknetGamePacketHeader {
					return reassembled
				}
			}
			continue
		}

		// Check if payload is a game packet
		if len(payload) > 0 && payload[0] == raknetGamePacketHeader {
			return payload
		}
	}

	return nil
}

// handleSplitPacket handles split packet reassembly
func (p *RawUDPProxy) handleSplitPacket(clientInfo *rawUDPClientInfo, splitID uint16, splitIndex, splitCount uint32, payload []byte) []byte {
	if splitCount == 0 || splitCount > MaxSplitPacketFragments {
		return nil
	}
	if splitIndex >= splitCount {
		return nil
	}

	clientInfo.mu.Lock()
	defer clientInfo.mu.Unlock()

	clientInfo.initSplitPackets()

	// Get or create buffer for this split ID
	buf, exists := clientInfo.splitPackets[splitID]
	if !exists {
		// Only clean up stale buffers when creating new ones (not on every packet)
		if len(clientInfo.splitPackets) >= MaxSplitPacketsPerClient {
			clientInfo.cleanupStaleSplitPackets()
			// If still at limit after cleanup, remove oldest
			if len(clientInfo.splitPackets) >= MaxSplitPacketsPerClient {
				var oldestID uint16
				var oldestTime time.Time
				for id, b := range clientInfo.splitPackets {
					if oldestTime.IsZero() || b.createdAt.Before(oldestTime) {
						oldestID = id
						oldestTime = b.createdAt
					}
				}
				delete(clientInfo.splitPackets, oldestID)
			}
		}

		buf = &splitPacketBuffer{
			splitCount: int(splitCount),
			fragments:  make(map[int][]byte),
			received:   0,
			totalBytes: 0,
			createdAt:  time.Now(),
		}
		clientInfo.splitPackets[splitID] = buf
	}

	// Store fragment (make a copy)
	if _, alreadyHave := buf.fragments[int(splitIndex)]; !alreadyHave {
		if buf.totalBytes+len(payload) > MaxSplitPacketBytes {
			delete(clientInfo.splitPackets, splitID)
			return nil
		}
		fragment := make([]byte, len(payload))
		copy(fragment, payload)
		buf.fragments[int(splitIndex)] = fragment
		buf.received++
		buf.totalBytes += len(fragment)
	}

	// Check if we have all fragments
	if buf.received < buf.splitCount {
		return nil
	}

	// Reassemble
	var totalLen int
	for i := 0; i < buf.splitCount; i++ {
		if frag, ok := buf.fragments[i]; ok {
			totalLen += len(frag)
		} else {
			// Missing fragment
			return nil
		}
	}

	if totalLen > MaxSplitPacketBytes {
		delete(clientInfo.splitPackets, splitID)
		return nil
	}
	reassembled := make([]byte, 0, totalLen)
	for i := 0; i < buf.splitCount; i++ {
		reassembled = append(reassembled, buf.fragments[i]...)
	}

	// Clean up
	delete(clientInfo.splitPackets, splitID)

	logger.Debug("RawUDP: Reassembled split packet: splitID=%d, fragments=%d, totalLen=%d", splitID, buf.splitCount, totalLen)

	return reassembled
}

// parseLoginPacket parses a Login packet to extract player info
func (p *RawUDPProxy) parseLoginPacket(data []byte) (playerName, playerUUID, playerXUID string) {
	if len(data) < 3 {
		return
	}

	// Check for game packet header (0xfe)
	if data[0] != raknetGamePacketHeader {
		return
	}

	// Get compression ID
	compressionID := data[1]
	compressedData := data[2:]

	// Decompress
	var decompressed []byte
	var err error

	switch compressionID {
	case 0x00: // Flate
		decompressed, err = p.decompressFlate(compressedData)
	case 0x01: // Snappy
		decompressed, err = decompressSnappyLimited(compressedData)
	default:
		return // Unknown compression or encrypted
	}

	if err != nil {
		return
	}

	// Parse batch format
	buf := bytes.NewBuffer(decompressed)

	// Read packet length
	var packetLen uint32
	if err := p.readVaruint32(buf, &packetLen); err != nil {
		return
	}

	// Read packet ID
	var packetID uint32
	if err := p.readVaruint32(buf, &packetID); err != nil {
		return
	}

	// Login packet ID is 0x01
	if packetID&0x3FF != 0x01 {
		return
	}

	// Read protocol version (int32 BE)
	var protocolVersion int32
	if err := binary.Read(buf, binary.BigEndian, &protocolVersion); err != nil {
		return
	}

	logger.Debug("RawUDP: Detected Login packet, protocol=%d", protocolVersion)

	// Read connection request length
	var connReqLen uint32
	if err := p.readVaruint32(buf, &connReqLen); err != nil {
		return
	}

	if connReqLen == 0 || connReqLen > uint32(buf.Len()) {
		return
	}

	// Read connection request data
	connReqData := buf.Next(int(connReqLen))

	// Parse connection request
	return p.parseConnectionRequest(connReqData)
}

// parseConnectionRequest parses the connection request to extract identity
func (p *RawUDPProxy) parseConnectionRequest(data []byte) (playerName, playerUUID, playerXUID string) {
	if len(data) < 4 {
		return
	}

	buf := bytes.NewBuffer(data)

	// Read chain length (int32 LE)
	var chainLen int32
	if err := binary.Read(buf, binary.LittleEndian, &chainLen); err != nil {
		return
	}

	if chainLen <= 0 || chainLen > int32(buf.Len()) {
		return
	}

	// Read chain JSON
	chainData := buf.Next(int(chainLen))

	// Parse outer JSON
	var outerWrapper struct {
		AuthenticationType int    `json:"AuthenticationType"`
		Certificate        string `json:"Certificate"`
	}
	if err := json.Unmarshal(chainData, &outerWrapper); err != nil {
		// Try direct chain format
		var chainWrapper struct {
			Chain []string `json:"chain"`
		}
		if err := json.Unmarshal(chainData, &chainWrapper); err != nil {
			return
		}
		return p.extractIdentityFromChain(chainWrapper.Chain)
	}

	// Parse inner Certificate JSON
	var chainWrapper struct {
		Chain []string `json:"chain"`
	}
	if err := json.Unmarshal([]byte(outerWrapper.Certificate), &chainWrapper); err != nil {
		return
	}

	return p.extractIdentityFromChain(chainWrapper.Chain)
}

// rawUDPIdentityClaims holds JWT claims for player identity
type rawUDPIdentityClaims struct {
	jwt.RegisteredClaims
	ExtraData struct {
		DisplayName string `json:"displayName"`
		Identity    string `json:"identity"`
		XUID        string `json:"XUID"`
	} `json:"extraData"`
}

// extractIdentityFromChain extracts player identity from JWT chain
func (p *RawUDPProxy) extractIdentityFromChain(chain []string) (playerName, playerUUID, playerXUID string) {
	jwtParser := jwt.Parser{}
	for _, token := range chain {
		var claims rawUDPIdentityClaims
		_, _, err := jwtParser.ParseUnverified(token, &claims)
		if err != nil {
			continue
		}

		if claims.ExtraData.DisplayName != "" {
			return claims.ExtraData.DisplayName, claims.ExtraData.Identity, claims.ExtraData.XUID
		}
	}
	return
}

// parseAndLogGamePacket parses and logs important game packets
// Only logs critical packets like PlayStatus, Disconnect, StartGame
func (p *RawUDPProxy) parseAndLogGamePacket(data []byte, clientInfo *rawUDPClientInfo) {
	if len(data) < 3 {
		return
	}

	// Check for game packet header
	if data[0] != raknetGamePacketHeader {
		return
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
		decompressed, err = decompressSnappyLimited(compressedData)
	case 0xff: // No compression
		decompressed = compressedData
	default:
		// Encrypted packet - can't parse
		return
	}

	if err != nil {
		return
	}

	// Parse batch format - only look at first packet to reduce overhead
	buf := bytes.NewBuffer(decompressed)

	var packetLen uint32
	if err := p.readVaruint32(buf, &packetLen); err != nil {
		return
	}
	if packetLen == 0 || packetLen > uint32(buf.Len()) {
		return
	}

	packetData := buf.Next(int(packetLen))
	if len(packetData) < 1 {
		return
	}

	// Parse packet ID
	packetBuf := bytes.NewBuffer(packetData)
	var packetID uint32
	if err := p.readVaruint32(packetBuf, &packetID); err != nil {
		return
	}

	packetID = packetID & 0x3FF
	clientAddr := clientInfo.clientAddr.String()

	// Only log critical packets
	switch packetID {
	case 0x02: // PlayStatus
		p.logPlayStatus(packetBuf, clientAddr)
	case 0x03: // ServerToClientHandshake
		logger.Info("[server->client] %s: ServerToClientHandshake (encryption starting)", clientAddr)
	case 0x05: // Disconnect
		p.logDisconnect(packetBuf, clientAddr)
	case 0x0b: // StartGame
		logger.Info("[server->client] %s: StartGame (player entering world)", clientAddr)
	}
}

// logPlayStatus logs PlayStatus packet
func (p *RawUDPProxy) logPlayStatus(buf *bytes.Buffer, clientAddr string) {
	if buf.Len() < 4 {
		return
	}

	statusBytes := buf.Next(4)
	status := int32(statusBytes[0])<<24 | int32(statusBytes[1])<<16 | int32(statusBytes[2])<<8 | int32(statusBytes[3])

	statusNames := map[int32]string{
		0: "LoginSuccess",
		1: "LoginFailedClient (客户端版本过旧)",
		2: "LoginFailedServer (服务器版本过旧)",
		3: "PlayerSpawn",
		4: "LoginFailedInvalidTenant",
		5: "LoginFailedVanillaEdu",
		6: "LoginFailedEduVanilla",
		7: "LoginFailedServerFull (服务器已满)",
		8: "LoginFailedEditorVanilla",
		9: "LoginFailedVanillaEditor",
	}

	statusStr := statusNames[status]
	if statusStr == "" {
		statusStr = fmt.Sprintf("Unknown(%d)", status)
	}

	logger.Info("[server->client] %s: PlayStatus = %s", clientAddr, statusStr)
}

// logDisconnect logs Disconnect packet
func (p *RawUDPProxy) logDisconnect(buf *bytes.Buffer, clientAddr string) {
	// Read reason code
	var reason uint32
	if err := p.readVaruint32(buf, &reason); err != nil {
		logger.Info("[server->client] %s: Disconnect (failed to read reason)", clientAddr)
		return
	}

	// Read hide screen flag
	hideScreen, err := buf.ReadByte()
	if err != nil {
		logger.Info("[server->client] %s: Disconnect reason=%d", clientAddr, reason)
		return
	}

	if hideScreen != 0 {
		logger.Info("[server->client] %s: Disconnect reason=%d (screen hidden)", clientAddr, reason)
		return
	}

	// Read message
	var msgLen uint32
	if err := p.readVaruint32(buf, &msgLen); err != nil || msgLen == 0 || msgLen > uint32(buf.Len()) {
		logger.Info("[server->client] %s: Disconnect reason=%d", clientAddr, reason)
		return
	}

	message := string(buf.Next(int(msgLen)))
	logger.Info("[server->client] %s: Disconnect reason=%d, message=%s", clientAddr, reason, message)
}

// logTextPacket logs Text packet
func (p *RawUDPProxy) logTextPacket(buf *bytes.Buffer, clientAddr string) {
	if buf.Len() < 1 {
		return
	}

	textType, _ := buf.ReadByte()
	typeNames := []string{"Raw", "Chat", "Translation", "Popup", "JukeboxPopup", "Tip", "System", "Whisper", "Announcement"}

	typeName := "Unknown"
	if int(textType) < len(typeNames) {
		typeName = typeNames[textType]
	}

	// Skip needs translation flag
	buf.ReadByte()

	// Skip source name for certain types
	if textType == 1 || textType == 7 || textType == 8 {
		var sourceLen uint32
		if err := p.readVaruint32(buf, &sourceLen); err == nil && sourceLen <= uint32(buf.Len()) {
			buf.Next(int(sourceLen))
		}
	}

	// Read message
	var msgLen uint32
	if err := p.readVaruint32(buf, &msgLen); err != nil || msgLen == 0 || msgLen > uint32(buf.Len()) {
		return
	}

	message := string(buf.Next(int(msgLen)))
	if len(message) > 100 {
		message = message[:100] + "..."
	}
	logger.Info("[server->client] %s: Text type=%s, message=%s", clientAddr, typeName, message)
}

// decompressFlate decompresses flate data
func (p *RawUDPProxy) decompressFlate(data []byte) ([]byte, error) {
	return decompressFlateLimited(data)
}

// readVaruint32 reads a variable-length uint32
func (p *RawUDPProxy) readVaruint32(r io.ByteReader, x *uint32) error {
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
	return fmt.Errorf("varuint32 overflow")
}

// KickPlayer kicks a player by display name.
// Returns the number of connections that were kicked.
func (p *RawUDPProxy) KickPlayer(playerName, reason string) int {
	kickedCount := 0
	checkedCount := 0

	logger.Info("RawUDP KickPlayer called: looking for player '%s'", playerName)

	p.clients.Range(func(key, value interface{}) bool {
		clientInfo := value.(*rawUDPClientInfo)
		clientInfo.mu.Lock()
		name := clientInfo.playerName
		clientInfo.mu.Unlock()

		checkedCount++
		logger.Debug("RawUDP KickPlayer: checking client %s, playerName='%s'", key, name)

		// Case-insensitive match
		if name != "" && strings.EqualFold(name, playerName) {
			logger.Info("RawUDP: Kicking player %s from %s (reason: %s)", playerName, key, reason)

			// Send disconnect packet to client first
			p.sendDisconnectToClient(clientInfo, reason)

			// Mark as kicked
			clientInfo.kicked.Store(true)

			// Close the connection - this will trigger removeClient
			clientInfo.targetConn.Close()
			kickedCount++
		}
		return true
	})

	logger.Info("RawUDP KickPlayer finished: checked %d clients, kicked %d", checkedCount, kickedCount)
	return kickedCount
}

// GetConnectedPlayers returns a list of currently connected players with their stats
func (p *RawUDPProxy) GetConnectedPlayers() []PlayerStats {
	var players []PlayerStats

	p.clients.Range(func(key, value interface{}) bool {
		clientInfo := value.(*rawUDPClientInfo)

		// Read player info (needs lock)
		clientInfo.mu.Lock()
		playerName := clientInfo.playerName
		playerUUID := clientInfo.playerUUID
		playerXUID := clientInfo.playerXUID
		clientInfo.mu.Unlock()

		stats := PlayerStats{
			ClientAddr:  clientInfo.clientAddr.String(),
			PlayerName:  playerName,
			PlayerUUID:  playerUUID,
			PlayerXUID:  playerXUID,
			StartTime:   clientInfo.startTime,
			Duration:    time.Since(clientInfo.startTime),
			BytesUp:     clientInfo.bytesUp.Load(),
			BytesDown:   clientInfo.bytesDown.Load(),
			PacketCount: clientInfo.packetCount.Load(),
		}

		players = append(players, stats)
		return true
	})

	return players
}

// PlayerStats holds statistics for a connected player
type PlayerStats struct {
	ClientAddr  string        `json:"client_addr"`
	PlayerName  string        `json:"player_name"`
	PlayerUUID  string        `json:"player_uuid"`
	PlayerXUID  string        `json:"player_xuid"`
	StartTime   time.Time     `json:"start_time"`
	Duration    time.Duration `json:"duration"`
	BytesUp     int64         `json:"bytes_up"`
	BytesDown   int64         `json:"bytes_down"`
	PacketCount int64         `json:"packet_count"`
}

// sendDisconnectToClient sends a Minecraft disconnect packet to the client
// This constructs a proper RakNet frame with a Disconnect game packet
func (p *RawUDPProxy) sendDisconnectToClient(clientInfo *rawUDPClientInfo, message string) {
	// Best-effort: try to send a proper game-level Disconnect message so the client shows the reason.
	p.sendGameDisconnectPacket(clientInfo, message)

	// Even if we sent a game-level disconnect, also send a RakNet-level disconnect shortly after to ensure the
	// connection actually closes (game-level disconnect may be dropped).
	time.Sleep(80 * time.Millisecond)
	p.sendRakNetDisconnect(clientInfo)

	if clientInfo.encrypted.Load() {
		logger.Info("Sent disconnect to client %s (encrypted session, message may not display): %s", clientInfo.clientAddr.String(), message)
		return
	}
	logger.Info("Sent disconnect to client %s: %s", clientInfo.clientAddr.String(), message)
}

// sendGameDisconnectPacket sends a Minecraft game-level Disconnect packet
func (p *RawUDPProxy) sendGameDisconnectPacket(clientInfo *rawUDPClientInfo, message string) {
	// In raw_udp mode, we can't encrypt packets. We can still send a valid Disconnect packet
	// for the pre-encryption stage (e.g., ACL rejection right after Login).
	// For established encrypted sessions, the client may ignore this and only process the RakNet-level disconnect.

	// Determine the compression negotiated by the remote server by looking at the client's Login packet wrapper.
	compID := byte(clientInfo.compressionID.Load())
	var compression mcpacket.Compression
	switch compID {
	case 0x01:
		compression = mcpacket.SnappyCompression
	case 0xff:
		compression = mcpacket.NopCompression
	default:
		compression = mcpacket.FlateCompression
	}

	formattedMsg := message
	if !strings.HasPrefix(formattedMsg, "§") {
		formattedMsg = "§c" + formattedMsg
	}

	pk := &mcpacket.Disconnect{
		Reason:                  mcpacket.DisconnectReasonKicked,
		HideDisconnectionScreen: false,
		Message:                 formattedMsg,
		FilteredMessage:         formattedMsg,
	}

	// Encode the Disconnect packet as a single batch packet with negotiated compression.
	var packetBuf bytes.Buffer
	packetWriter := mcprotocol.NewWriter(&packetBuf, 0)
	mcprotocol.WriteVaruint32(&packetBuf, pk.ID())
	pk.Marshal(packetWriter)

	var gameBuf bytes.Buffer
	encoder := mcpacket.NewEncoder(&gameBuf)
	encoder.EnableCompression(compression)
	if err := encoder.Encode([][]byte{packetBuf.Bytes()}); err != nil {
		logger.Error("Failed to encode disconnect packet: %v", err)
		return
	}
	gamePacket := gameBuf.Bytes()
	if len(gamePacket) == 0 {
		return
	}
	if len(gamePacket) > 8191 {
		logger.Warn("Disconnect packet too large (%d bytes), not sending", len(gamePacket))
		return
	}

	// Build a RakNet datagram containing a single reliable-ordered encapsulated packet.
	seq := clientInfo.sendDatagramSeq.Add(1) & 0xFFFFFF
	msgIndex := clientInfo.sendMessageIndex.Add(1) & 0xFFFFFF
	orderIndex := clientInfo.sendOrderIndex.Add(1) & 0xFFFFFF

	var raknetFrame bytes.Buffer
	raknetFrame.WriteByte(0x84) // Datagram (bitFlagDatagram + bitFlagNeedsBAndAS)
	raknetFrame.WriteByte(byte(seq))
	raknetFrame.WriteByte(byte(seq >> 8))
	raknetFrame.WriteByte(byte(seq >> 16))

	// Encapsulated packet header: reliability=3 (reliable ordered), no split.
	raknetFrame.WriteByte(0x60)

	// Bit length (2 bytes BE).
	bitLen := uint16(len(gamePacket) * 8)
	raknetFrame.WriteByte(byte(bitLen >> 8))
	raknetFrame.WriteByte(byte(bitLen & 0xff))

	// Reliable message index (3 bytes LE).
	writeUint24LE(&raknetFrame, msgIndex)

	// Ordered index (3 bytes LE) + order channel (1 byte, use 0).
	writeUint24LE(&raknetFrame, orderIndex)
	raknetFrame.WriteByte(0)

	// Payload.
	raknetFrame.Write(gamePacket)

	// Send multiple times to ensure delivery (UDP is unreliable)
	for i := 0; i < 3; i++ {
		p.listener.SetWriteDeadline(time.Now().Add(UDPWriteTimeout))
		_, err := p.listener.WriteToUDP(raknetFrame.Bytes(), clientInfo.clientAddr)
		if err != nil {
			logger.Error("Failed to send disconnect packet to client (attempt %d): %v", i+1, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func writeUint24LE(w *bytes.Buffer, v uint32) {
	v &= 0xFFFFFF
	w.WriteByte(byte(v))
	w.WriteByte(byte(v >> 8))
	w.WriteByte(byte(v >> 16))
}

// sendRakNetDisconnect sends a RakNet-level disconnection notification (0x15)
func (p *RawUDPProxy) sendRakNetDisconnect(clientInfo *rawUDPClientInfo) {
	// ID_DISCONNECTION_NOTIFICATION = 0x15
	disconnectPacket := []byte{0x15}

	// Send multiple times
	for i := 0; i < 3; i++ {
		p.listener.SetWriteDeadline(time.Now().Add(UDPWriteTimeout))
		_, err := p.listener.WriteToUDP(disconnectPacket, clientInfo.clientAddr)
		if err != nil {
			logger.Debug("Failed to send RakNet disconnect (attempt %d): %v", i+1, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// writeVaruint32 writes a variable-length uint32
func (p *RawUDPProxy) writeVaruint32(w *bytes.Buffer, x uint32) {
	for x >= 0x80 {
		w.WriteByte(byte(x&0x7f) | 0x80)
		x >>= 7
	}
	w.WriteByte(byte(x))
}

// ============================================================================
// Latency Monitoring (for LatencyProvider interface)
// ============================================================================

// GetCachedLatency returns the latency by pinging the server on-demand.
// Returns -1 if the server is offline or ping fails.
func (p *RawUDPProxy) GetCachedLatency() int64 {
	p.maybeRefreshPingCacheAsync(false)
	p.latencyMu.RLock()
	defer p.latencyMu.RUnlock()
	return p.cachedLatency
}

// GetCachedPong returns the cached pong response (MOTD).
func (p *RawUDPProxy) GetCachedPong() []byte {
	p.maybeRefreshPingCacheAsync(false)
	return p.getCachedAdvertisementForAPI()
}

// pingTargetServer sends a RakNet unconnected ping and measures latency
// Returns latency in milliseconds, or -1 if failed
func (p *RawUDPProxy) pingTargetServer() int64 {
	// Build unconnected ping packet
	// Format: 0x01 + timestamp(8 bytes BE) + MAGIC(16 bytes) + clientGUID(8 bytes)
	var pingPacket bytes.Buffer
	pingPacket.WriteByte(raknetUnconnectedPing)

	// Timestamp (8 bytes BE)
	timestamp := time.Now().UnixMilli()
	binary.Write(&pingPacket, binary.BigEndian, timestamp)

	// RakNet MAGIC (16 bytes)
	pingPacket.Write(raknetMagic)

	// Client GUID (8 bytes)
	binary.Write(&pingPacket, binary.BigEndian, uint64(12345678901234567))

	// Create connection for ping
	var conn net.PacketConn
	var err error

	if p.shouldUseProxy() {
		conn, _, err = p.dialThroughProxyWithTimeout(8 * time.Second)
	} else {
		conn, err = net.DialUDP("udp", nil, p.targetAddr)
	}

	if err != nil {
		p.latencyMu.Lock()
		p.cachedLatency = -1
		p.latencyMu.Unlock()
		return -1
	}
	defer conn.Close()

	// Send ping
	startTime := time.Now()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.WriteTo(pingPacket.Bytes(), p.targetAddr)
	if err != nil {
		p.latencyMu.Lock()
		p.cachedLatency = -1
		p.latencyMu.Unlock()
		return -1
	}

	// Wait for pong
	buffer := make([]byte, MaxUDPPacketSize)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		p.latencyMu.Lock()
		p.cachedLatency = -1
		p.latencyMu.Unlock()
		return -1
	}

	latency := time.Since(startTime).Milliseconds()

	// Check if it's a pong packet (0x1c)
	if n > 0 && buffer[0] == raknetUnconnectedPong {
		guid, advertisement, ok := parseUnconnectedPong(buffer[:n])
		if ok && guid != 0 {
			p.serverGUID.Store(guid)
		}
		p.latencyMu.Lock()
		p.cachedLatency = latency
		if ok && len(advertisement) > 0 {
			p.cachedPong = make([]byte, len(advertisement))
			copy(p.cachedPong, advertisement)
		} else {
			p.cachedPong = nil
		}
		p.latencyMu.Unlock()
		return latency
	}

	p.latencyMu.Lock()
	p.cachedLatency = -1
	p.latencyMu.Unlock()
	return -1
}

func stableGUIDFromString(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func buildUnconnectedPongPacket(pingTimestamp uint64, serverGUID uint64, advertisement []byte) []byte {
	// ID(1) + time(8) + guid(8) + magic(16) + len(2) + adv
	pkt := make([]byte, 1+8+8+len(raknetMagic)+2+len(advertisement))
	pkt[0] = raknetUnconnectedPong
	binary.BigEndian.PutUint64(pkt[1:9], pingTimestamp)
	binary.BigEndian.PutUint64(pkt[9:17], serverGUID)
	copy(pkt[17:17+len(raknetMagic)], raknetMagic)
	advLenOff := 17 + len(raknetMagic)
	binary.BigEndian.PutUint16(pkt[advLenOff:advLenOff+2], uint16(len(advertisement)))
	copy(pkt[advLenOff+2:], advertisement)
	return pkt
}

func parseUnconnectedPong(pongPacket []byte) (serverGUID uint64, advertisement []byte, ok bool) {
	if len(pongPacket) < 1+8+8+len(raknetMagic)+2 {
		return 0, nil, false
	}
	if pongPacket[0] != raknetUnconnectedPong {
		return 0, nil, false
	}
	// Find magic to locate the advertisement length safely.
	magicIdx := bytes.Index(pongPacket, raknetMagic)
	if magicIdx <= 0 || magicIdx+len(raknetMagic)+2 > len(pongPacket) {
		return 0, nil, false
	}
	// Best-effort parse: GUID is 8 bytes right before magic (common RakNet layout).
	if magicIdx >= 8 {
		serverGUID = binary.BigEndian.Uint64(pongPacket[magicIdx-8 : magicIdx])
	}
	advLenOff := magicIdx + len(raknetMagic)
	advLen := int(binary.BigEndian.Uint16(pongPacket[advLenOff : advLenOff+2]))
	if advLen < 0 || advLenOff+2+advLen > len(pongPacket) {
		return 0, nil, false
	}
	advertisement = pongPacket[advLenOff+2 : advLenOff+2+advLen]
	return serverGUID, advertisement, true
}

func defaultAdvertisementForServer(serverID string) []byte {
	// Minimal MCPE advertisement (server list).
	// Format: MCPE;ServerName;Protocol;Version;Players;MaxPlayers;ServerUID;WorldName;GameMode;...
	return []byte("MCPE;" + serverID + ";0;0.0.0;0;0;0;Proxy;Survival;1;0;0;")
}

func embedLatencyInMOTDBytes(pong []byte, latencyMs int64) []byte {
	if len(pong) == 0 {
		return pong
	}
	motd := string(pong)
	parts := strings.Split(motd, ";")
	if len(parts) < 2 {
		return pong
	}

	if latencyMs < 0 {
		parts[1] = fmt.Sprintf("%s §c[离线]", parts[1])
	} else {
		var color string
		switch {
		case latencyMs < 50:
			color = "§a"
		case latencyMs < 100:
			color = "§e"
		case latencyMs < 200:
			color = "§6"
		default:
			color = "§c"
		}
		parts[1] = fmt.Sprintf("%s %s[%dms]", parts[1], color, latencyMs)
	}

	return []byte(strings.Join(parts, ";"))
}
