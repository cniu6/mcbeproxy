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

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/protocol"
	"mcpeserverproxy/internal/session"

	"github.com/sandertv/go-raknet"
)

// UDPListener handles UDP packet reception for a specific server configuration.
type UDPListener struct {
	conn          *net.UDPConn
	serverID      string
	config        *config.ServerConfig
	bufferPool    *BufferPool
	sessionMgr    *session.SessionManager
	forwarder     *Forwarder
	configMgr     *config.ConfigManager
	raknetHandler *protocol.RakNetHandler
	cachedPong    []byte // Cached pong response from remote server
	cachedPongMu  sync.RWMutex
	lastPongTime  time.Time
	closed        atomic.Bool
}

// NewUDPListener creates a new UDP listener for the specified server configuration.
func NewUDPListener(
	serverID string,
	cfg *config.ServerConfig,
	bufferPool *BufferPool,
	sessionMgr *session.SessionManager,
	forwarder *Forwarder,
	configMgr *config.ConfigManager,
) *UDPListener {
	// Create RakNet handler for ping/pong handling
	raknetHandler := protocol.NewRakNetHandler(
		time.Now().UnixNano(), // Server GUID
		fmt.Sprintf("MCPE;%s;0;0;0;10;0;%s;Survival;1;0;0;0", cfg.Name, cfg.Name),
	)

	return &UDPListener{
		serverID:      serverID,
		config:        cfg,
		bufferPool:    bufferPool,
		sessionMgr:    sessionMgr,
		forwarder:     forwarder,
		configMgr:     configMgr,
		raknetHandler: raknetHandler,
	}
}

// Start begins listening for UDP packets on the configured address.
func (l *UDPListener) Start() error {
	addr, err := net.ResolveUDPAddr("udp", l.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address %s: %w", l.config.ListenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", l.config.ListenAddr, err)
	}

	l.conn = conn
	l.closed.Store(false)
	return nil
}

// Listen starts the packet reception loop. It blocks until the context is cancelled.
func (l *UDPListener) Listen(ctx context.Context) error {
	if l.conn == nil {
		return fmt.Errorf("listener not started")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Check if closed
			if l.closed.Load() {
				return nil
			}

			buf := l.bufferPool.Get()
			// Set read deadline to allow checking context
			l.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, clientAddr, err := l.conn.ReadFromUDP(*buf)
			if err != nil {
				l.bufferPool.Put(buf)
				// Check if closed or context cancelled
				if l.closed.Load() {
					return nil
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					// Timeout is expected, continue
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					// Only log non-timeout errors if not closed
					if !strings.Contains(err.Error(), "use of closed") {
						logger.LogPacketForwardError("read", "listener", err)
					}
					continue
				}
			}

			// Process packet in a goroutine to avoid blocking
			go l.handlePacket((*buf)[:n], clientAddr, buf)
		}
	}
}

// handlePacket processes an incoming UDP packet from a client.
func (l *UDPListener) handlePacket(data []byte, clientAddr *net.UDPAddr, buf *[]byte) {
	defer l.bufferPool.Put(buf)

	if l.closed.Load() {
		return
	}

	// Check if server is enabled (refresh config to get latest state)
	serverCfg, exists := l.configMgr.GetServer(l.serverID)
	if !exists {
		logger.Warn("Server config not found for %s", l.serverID)
		return
	}

	// Handle unconnected ping packets (server list ping) - these don't need a session
	if len(data) > 0 && (data[0] == protocol.IDUnconnectedPing || data[0] == protocol.IDUnconnectedPingOpenConn) {
		l.handlePingPacket(data, clientAddr, serverCfg)
		return
	}

	// Check if this is a connection request packet
	if len(data) > 0 && data[0] == protocol.IDOpenConnectionRequest1 {
		if !serverCfg.Enabled {
			// Server is disabled, send a proper RakNet incompatible protocol version response
			// This will show an error message to the client
			l.sendDisabledServerResponse(clientAddr, serverCfg.GetDisabledMessage())
			return
		}
	}

	if !serverCfg.Enabled {
		// For other packets when disabled, just ignore
		return
	}

	clientAddrStr := clientAddr.String()

	// Get or create session for this client
	sess, isNew := l.sessionMgr.GetOrCreate(clientAddrStr, l.serverID)
	if isNew {
		// New session - establish connection to remote server
		if err := l.setupRemoteConnection(sess, serverCfg); err != nil {
			// Remote server unreachable (requirement 9.2)
			logger.LogRemoteUnreachable(l.serverID, serverCfg.GetTargetAddr(), err)
			// Send disconnect packet to client
			disconnectPacket := l.forwarder.BuildDisconnectPacket("Unable to connect to remote server")
			l.conn.WriteToUDP(disconnectPacket, clientAddr)
			l.sessionMgr.Remove(clientAddrStr)
			return
		}
		logger.LogSessionCreated(clientAddrStr, l.serverID)
	}

	// Update session activity
	l.sessionMgr.UpdateActivity(clientAddrStr)

	// Forward packet to remote server
	if err := l.forwarder.ForwardToRemote(sess, data, serverCfg); err != nil {
		// Only log if not closed
		if !l.closed.Load() {
			logger.LogPacketForwardError("client->remote", clientAddrStr, err)
		}
	}
}

// handlePingPacket handles RakNet unconnected ping packets for server list display.
func (l *UDPListener) handlePingPacket(data []byte, clientAddr *net.UDPAddr, serverCfg *config.ServerConfig) {
	// If custom MOTD is set, use it directly without forwarding to remote (no logging for performance)
	if serverCfg.GetCustomMOTD() != "" {
		pongPacket := l.buildCustomPongPacket(data, serverCfg.GetCustomMOTD())
		l.conn.WriteToUDP(pongPacket, clientAddr)
		return
	}

	// Check if we have a recent cached pong
	l.cachedPongMu.RLock()
	cachedPong := l.cachedPong
	lastPongTime := l.lastPongTime
	l.cachedPongMu.RUnlock()

	// Use cached pong if it's less than 3 seconds old
	if cachedPong != nil && time.Since(lastPongTime) < 3*time.Second {
		logger.Debug("Using cached pong for %s (age: %v)", l.serverID, time.Since(lastPongTime))
		// Update the timestamp in the cached pong to match the ping
		pongCopy := make([]byte, len(cachedPong))
		copy(pongCopy, cachedPong)
		// Copy timestamp from ping to pong (bytes 1-8)
		if len(data) >= 9 && len(pongCopy) >= 9 {
			copy(pongCopy[1:9], data[1:9])
		}
		l.conn.WriteToUDP(pongCopy, clientAddr)
		return
	}

	// Forward ping to remote server asynchronously
	logger.Debug("Forwarding ping to remote server %s", serverCfg.GetTargetAddr())
	go l.forwardPingAsync(data, clientAddr, serverCfg)
}

// buildCustomPongPacket builds a pong packet with custom MOTD.
func (l *UDPListener) buildCustomPongPacket(pingData []byte, motd string) []byte {
	magic := []byte{
		0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
		0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
	}

	// MOTD format: MCPE;ServerName;ProtocolVersion;MCVersion;PlayerCount;MaxPlayers;ServerUID;WorldName;GameMode;...
	// Example: MCPE;My Server;712;1.21.0;0;20;12345;World;Survival;1;19132;19132;
	serverData := []byte(motd)

	pong := make([]byte, 35+len(serverData))
	pong[0] = 0x1c // IDUnconnectedPong

	// Copy timestamp from ping
	if len(pingData) >= 9 {
		copy(pong[1:9], pingData[1:9])
	}

	// Server GUID (8 bytes)
	guid := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		pong[9+i] = byte(guid >> (56 - i*8))
	}

	// Magic
	copy(pong[17:33], magic)

	// Server data length (big endian)
	pong[33] = byte(len(serverData) >> 8)
	pong[34] = byte(len(serverData))

	// Server data
	copy(pong[35:], serverData)

	return pong
}

// forwardPingAsync forwards a ping packet to the remote server asynchronously.
func (l *UDPListener) forwardPingAsync(data []byte, clientAddr *net.UDPAddr, serverCfg *config.ServerConfig) {
	targetAddr := serverCfg.GetTargetAddr()

	// Use go-raknet to ping the server
	pongData, err := raknet.Ping(targetAddr)
	if err != nil {
		logger.Debug("raknet.Ping failed for %s: %v, trying direct UDP", targetAddr, err)
		// Try direct UDP ping as fallback
		l.forwardPingDirect(data, clientAddr, serverCfg)
		return
	}

	logger.Debug("Got pong from %s: %d bytes", targetAddr, len(pongData))

	// Build pong response using the pong data
	pongPacket := l.buildPongPacket(data, pongData)

	// Cache the pong response
	l.cachedPongMu.Lock()
	l.cachedPong = pongPacket
	l.lastPongTime = time.Now()
	l.cachedPongMu.Unlock()

	// Forward pong to client
	if !l.closed.Load() {
		l.conn.WriteToUDP(pongPacket, clientAddr)
		logger.Debug("Sent pong to client %s", clientAddr)
	}
}

// forwardPingDirect forwards ping directly via UDP (fallback method).
func (l *UDPListener) forwardPingDirect(data []byte, clientAddr *net.UDPAddr, serverCfg *config.ServerConfig) {
	targetAddr := serverCfg.GetTargetAddr()
	logger.Debug("Direct UDP ping to %s", targetAddr)

	remoteAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		logger.Warn("Failed to resolve %s for ping: %v", targetAddr, err)
		return
	}

	tempConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		logger.Warn("Failed to dial %s for ping: %v", targetAddr, err)
		return
	}
	defer tempConn.Close()

	tempConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err = tempConn.Write(data)
	if err != nil {
		logger.Warn("Failed to send ping to %s: %v", targetAddr, err)
		return
	}

	buf := make([]byte, 2048)
	n, err := tempConn.Read(buf)
	if err != nil {
		logger.Warn("Failed to receive pong from %s: %v", targetAddr, err)
		return
	}

	logger.Debug("Got direct pong from %s: %d bytes", targetAddr, n)
	pongData := buf[:n]

	l.cachedPongMu.Lock()
	l.cachedPong = make([]byte, n)
	copy(l.cachedPong, pongData)
	l.lastPongTime = time.Now()
	l.cachedPongMu.Unlock()

	if !l.closed.Load() {
		l.conn.WriteToUDP(pongData, clientAddr)
		logger.Debug("Sent direct pong to client %s", clientAddr)
	}
}

// buildPongPacket builds a RakNet unconnected pong packet.
func (l *UDPListener) buildPongPacket(pingData []byte, serverData []byte) []byte {
	// Pong packet structure:
	// [0] = 0x1c (IDUnconnectedPong)
	// [1-8] = timestamp from ping
	// [9-16] = server GUID
	// [17-32] = RakNet magic
	// [33-34] = server data length
	// [35+] = server data (MOTD string)

	magic := []byte{
		0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
		0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
	}

	pong := make([]byte, 35+len(serverData))
	pong[0] = 0x1c // IDUnconnectedPong

	// Copy timestamp from ping
	if len(pingData) >= 9 {
		copy(pong[1:9], pingData[1:9])
	}

	// Server GUID (8 bytes)
	guid := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		pong[9+i] = byte(guid >> (56 - i*8))
	}

	// Magic
	copy(pong[17:33], magic)

	// Server data length (big endian)
	pong[33] = byte(len(serverData) >> 8)
	pong[34] = byte(len(serverData))

	// Server data
	copy(pong[35:], serverData)

	return pong
}

// sendDisabledServerResponse sends a response to client when server is disabled.
// Uses RakNet Incompatible Protocol Version packet to show error message.
func (l *UDPListener) sendDisabledServerResponse(clientAddr *net.UDPAddr, message string) {
	// Send an Incompatible Protocol Version packet (0x19)
	// This will cause the client to show "Unable to connect to world"
	// Format: [0x19] [protocol] [magic] [server_guid]
	magic := []byte{
		0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
		0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
	}

	response := make([]byte, 26)
	response[0] = 0x19 // ID_INCOMPATIBLE_PROTOCOL_VERSION
	response[1] = 0    // Protocol version (0 = incompatible)
	copy(response[2:18], magic)
	// Server GUID (8 bytes)
	guid := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		response[18+i] = byte(guid >> (56 - i*8))
	}

	l.conn.WriteToUDP(response, clientAddr)
}

// setupRemoteConnection establishes a UDP connection to the remote server.
func (l *UDPListener) setupRemoteConnection(sess *session.Session, cfg *config.ServerConfig) error {
	targetAddr := cfg.GetTargetAddr()
	remoteAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve remote address %s: %w", targetAddr, err)
	}

	remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to remote %s: %w", targetAddr, err)
	}

	sess.RemoteConn = remoteConn

	// Start goroutine to receive responses from remote server
	go l.receiveFromRemote(sess)

	return nil
}

// receiveFromRemote handles packets received from the remote server.
func (l *UDPListener) receiveFromRemote(sess *session.Session) {
	buf := make([]byte, l.bufferPool.Size())
	logger.Debug("Started receiving from remote for client %s", sess.ClientAddr)

	for {
		if l.closed.Load() {
			return
		}

		// Set read deadline to allow checking closed state
		sess.RemoteConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := sess.RemoteConn.Read(buf)
		if err != nil {
			if l.closed.Load() {
				return
			}
			// Timeout is expected
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Connection closed or error
			if strings.Contains(err.Error(), "use of closed") {
				return
			}
			logger.Debug("Error reading from remote for %s: %v", sess.ClientAddr, err)
			continue
		}

		// Only log important handshake packets to reduce log spam
		if n > 0 {
			packetID := buf[0]
			// Log handshake packets only
			if packetID == 0x06 && n >= 28 { // OpenConnectionReply1
				mtu := uint16(buf[25])<<8 | uint16(buf[26])
				logger.Debug("OpenConnectionReply1: MTU=%d, client=%s", mtu, sess.ClientAddr)
			} else if packetID == 0x08 && n >= 21 { // OpenConnectionReply2
				logger.Info("Connection established: client=%s", sess.ClientAddr)
			}
		}

		// Parse client address
		clientAddr, err := net.ResolveUDPAddr("udp", sess.ClientAddr)
		if err != nil {
			logger.Warn("Failed to resolve client address %s: %v", sess.ClientAddr, err)
			continue
		}

		// Forward packet to client
		if err := l.forwarder.ForwardToClient(l.conn, clientAddr, buf[:n], sess); err != nil {
			// Only log if not closed
			if !l.closed.Load() && !strings.Contains(err.Error(), "use of closed") {
				logger.LogPacketForwardError("remote->client", sess.ClientAddr, err)
			}
		}
	}
}

// rejectDisabledServer sends a disconnect packet to a client trying to connect to a disabled server.
func (l *UDPListener) rejectDisabledServer(clientAddr *net.UDPAddr, message string) {
	// Build disconnect packet with custom message
	disconnectPacket := l.forwarder.BuildDisconnectPacket(message)
	l.conn.WriteToUDP(disconnectPacket, clientAddr)
}

// Stop closes the UDP listener.
func (l *UDPListener) Stop() error {
	l.closed.Store(true)
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

// LocalAddr returns the local address the listener is bound to.
func (l *UDPListener) LocalAddr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return nil
}
