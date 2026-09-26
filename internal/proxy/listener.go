// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
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
	conn            *net.UDPConn
	serverID        string
	config          *config.ServerConfig
	bufferPool      *BufferPool
	sessionMgr      *session.SessionManager
	forwarder       *Forwarder
	configMgr       *config.ConfigManager
	raknetHandler   *protocol.RakNetHandler
	cachedPong      []byte // Cached pong response from remote server
	cachedPongMu    sync.RWMutex
	lastPongTime    time.Time
	lastPongLatency int64 // milliseconds
	pingInFlight    atomic.Bool
	closed          atomic.Bool
	remoteWG        sync.WaitGroup
	cfgCache        atomic.Pointer[listenerConfigCache]
}

type listenerPacketJob struct {
	data       []byte
	clientAddr *net.UDPAddr
	clientKey  string
	buf        *[]byte
}

func defaultUDPListenerWorkerCount() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 4 {
		workers = 4
	}
	workerCount := workers * 8
	if workerCount < 32 {
		workerCount = 32
	}
	if workerCount > 128 {
		workerCount = 128
	}
	return workerCount
}

func defaultUDPListenerQueueSize() int {
	return defaultUDPListenerWorkerCount() * 4
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
		serverID:        serverID,
		config:          cfg,
		bufferPool:      bufferPool,
		sessionMgr:      sessionMgr,
		forwarder:       forwarder,
		configMgr:       configMgr,
		raknetHandler:   raknetHandler,
		lastPongLatency: -1,
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
	tuneUDPSocketForServer(conn, l.config, "udp_listener:"+l.serverID)

	l.conn = conn
	l.closed.Store(false)
	return nil
}

// Listen starts the packet reception loop. It blocks until the context is cancelled.
//
// Packets are handed to worker shards chosen by client address, so each
// client's datagrams are processed by one worker in arrival order (a shared
// worker pool reordered them, which RakNet sees as jitter).
func (l *UDPListener) Listen(ctx context.Context) error {
	if l.conn == nil {
		return fmt.Errorf("listener not started")
	}

	const readTimeout = 500 * time.Millisecond
	const shardQueueSize = 64
	shards := make([]chan listenerPacketJob, defaultUDPListenerWorkerCount())
	var workerWG sync.WaitGroup
	for i := range shards {
		shards[i] = make(chan listenerPacketJob, shardQueueSize)
		workerWG.Add(1)
		go func(jobs <-chan listenerPacketJob) {
			defer workerWG.Done()
			for job := range jobs {
				l.handlePacket(job.data, job.clientAddr, job.clientKey, job.buf)
			}
		}(shards[i])
	}
	defer func() {
		for _, ch := range shards {
			close(ch)
		}
		workerWG.Wait()
	}()

	var addrCache udpAddrCache
	var readDeadlineSetAt time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if l.closed.Load() {
			return nil
		}

		buf := l.bufferPool.Get()
		// Deadlines are absolute; refresh about twice per timeout, not per packet.
		if now := time.Now(); now.Sub(readDeadlineSetAt) >= readTimeout/2 {
			l.conn.SetReadDeadline(now.Add(readTimeout))
			readDeadlineSetAt = now
		}
		n, clientAP, err := l.conn.ReadFromUDPAddrPort(*buf)
		if err != nil {
			l.bufferPool.Put(buf)
			if l.closed.Load() {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				readDeadlineSetAt = time.Time{}
				continue
			}
			if !strings.Contains(err.Error(), "use of closed") {
				logger.LogPacketForwardError("read", "listener", err)
			}
			continue
		}

		clientAddr, clientKey := addrCache.lookup(clientAP)
		job := listenerPacketJob{data: (*buf)[:n], clientAddr: clientAddr, clientKey: clientKey, buf: buf}
		shard := shards[listenerShardIndex(clientAP, len(shards))]
		// Backpressure when the shard is behind: handling inline would jump
		// ahead of this client's queued packets. The kernel socket buffer
		// absorbs the wait; an established session's forward is one UDP write.
		select {
		case shard <- job:
		case <-ctx.Done():
			l.bufferPool.Put(buf)
			return ctx.Err()
		}
	}
}

// listenerShardIndex maps a client address to a worker shard (FNV-1a over
// the address bytes and port; no allocation).
func listenerShardIndex(ap netip.AddrPort, shards int) int {
	h := uint32(2166136261)
	b := ap.Addr().As16()
	for _, c := range b {
		h = (h ^ uint32(c)) * 16777619
	}
	p := ap.Port()
	h = (h ^ uint32(p&0xff)) * 16777619
	h = (h ^ uint32(p>>8)) * 16777619
	return int(h % uint32(shards))
}

// serverConfig returns the server's config, re-reading it from the config
// manager at most once per second (GetServer copies the whole struct).
func (l *UDPListener) serverConfig() (*config.ServerConfig, bool) {
	now := time.Now().UnixNano()
	if c := l.cfgCache.Load(); c != nil && now-c.at < int64(time.Second) {
		return c.cfg, true
	}
	cfg, ok := l.configMgr.GetServer(l.serverID)
	if !ok {
		return nil, false
	}
	l.cfgCache.Store(&listenerConfigCache{cfg: cfg, at: now})
	return cfg, true
}

type listenerConfigCache struct {
	cfg *config.ServerConfig
	at  int64
}

// handlePacket processes an incoming UDP packet from a client.
func (l *UDPListener) handlePacket(data []byte, clientAddr *net.UDPAddr, clientAddrStr string, buf *[]byte) {
	defer l.bufferPool.Put(buf)

	if l.closed.Load() {
		return
	}

	// Check if server is enabled (refresh config to get latest state)
	serverCfg, exists := l.serverConfig()
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

	// Get or create session for this client
	sess, isNew := l.sessionMgr.GetOrCreate(clientAddrStr, l.serverID)
	sess.LockForward()
	defer sess.UnlockForward()
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

	// Avoid spawning duplicate upstream pings under server-list scanning bursts.
	if !l.pingInFlight.CompareAndSwap(false, true) {
		if cachedPong != nil {
			pongCopy := make([]byte, len(cachedPong))
			copy(pongCopy, cachedPong)
			if len(data) >= 9 && len(pongCopy) >= 9 {
				copy(pongCopy[1:9], data[1:9])
			}
			l.conn.WriteToUDP(pongCopy, clientAddr)
		}
		return
	}

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
	defer l.pingInFlight.Store(false)
	targetAddr := serverCfg.GetTargetAddr()

	// Use go-raknet to ping the server with latency measurement
	start := time.Now()
	pongData, err := raknet.Ping(targetAddr)
	latency := time.Since(start)

	if err != nil {
		logger.Debug("raknet.Ping failed for %s: %v, trying direct UDP", targetAddr, err)
		// Try direct UDP ping as fallback
		l.forwardPingDirect(data, clientAddr, serverCfg)
		return
	}

	logger.Debug("Got pong from %s: %d bytes, latency=%dms", targetAddr, len(pongData), latency.Milliseconds())

	// Build pong response using the pong data
	pongPacket := l.buildPongPacket(data, pongData)

	// Cache the pong response and latency
	l.cachedPongMu.Lock()
	l.cachedPong = pongData // Store original pong data for API
	l.lastPongTime = time.Now()
	l.lastPongLatency = latency.Milliseconds()
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

	remoteAddr, err := resolveUDPAddr(targetAddr)
	if err != nil {
		logger.Warn("Failed to resolve %s for ping: %v", targetAddr, err)
		l.markPingFailure()
		return
	}

	tempConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		logger.Warn("Failed to dial %s for ping: %v", targetAddr, err)
		l.markPingFailure()
		return
	}
	defer tempConn.Close()
	if err := configureUDPConnBuffers(tempConn, serverCfg.GetUDPSocketBufferSize()); err != nil {
		logger.Debug("Failed to tune direct ping UDP socket buffers for %s: %v", targetAddr, err)
	}

	tempConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	start := time.Now()
	_, err = tempConn.Write(data)
	if err != nil {
		logger.Warn("Failed to send ping to %s: %v", targetAddr, err)
		l.markPingFailure()
		return
	}

	// Use buffer pool to reduce GC pressure
	bufPtr := GetSmallBuffer()
	buf := *bufPtr
	defer PutSmallBuffer(bufPtr)

	n, err := tempConn.Read(buf)
	latency := time.Since(start)

	if err != nil {
		logger.Warn("Failed to receive pong from %s: %v", targetAddr, err)
		l.markPingFailure()
		return
	}

	logger.Debug("Got direct pong from %s: %d bytes, latency=%dms", targetAddr, n, latency.Milliseconds())
	pongData := buf[:n]

	l.cachedPongMu.Lock()
	l.cachedPong = make([]byte, n)
	copy(l.cachedPong, pongData)
	l.lastPongTime = time.Now()
	l.lastPongLatency = latency.Milliseconds()
	l.cachedPongMu.Unlock()

	if !l.closed.Load() {
		l.conn.WriteToUDP(pongData, clientAddr)
		logger.Debug("Sent direct pong to client %s", clientAddr)
	}
}

func (l *UDPListener) markPingFailure() {
	l.cachedPongMu.Lock()
	l.cachedPong = nil
	l.lastPongLatency = -1
	l.cachedPongMu.Unlock()
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
	remoteAddr, err := resolveUDPAddr(targetAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve remote address %s: %w", targetAddr, err)
	}

	remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to remote %s: %w", targetAddr, err)
	}
	tuneUDPSocketForServer(remoteConn, cfg, "udp_listener_remote:"+targetAddr)

	sess.RemoteConn = remoteConn

	// Start goroutine to receive responses from remote server. The listener
	// owns this goroutine, so Stop waits for it after closing the session conn.
	l.remoteWG.Add(1)
	go func() {
		defer l.remoteWG.Done()
		l.receiveFromRemote(sess)
	}()

	return nil
}

// receiveFromRemote handles packets received from the remote server.
func (l *UDPListener) receiveFromRemote(sess *session.Session) {
	// Use buffer pool to reduce GC pressure
	bufPtr := l.bufferPool.Get()
	buf := *bufPtr
	defer l.bufferPool.Put(bufPtr)
	clientAddr, err := net.ResolveUDPAddr("udp", sess.ClientAddr)
	if err != nil {
		logger.Warn("Failed to resolve client address %s: %v", sess.ClientAddr, err)
		return
	}

	logger.Debug("Started receiving from remote for client %s", sess.ClientAddr)

	// Use longer timeout to reduce CPU usage from frequent deadline checks
	// 500ms timeout means max 2 iterations per second when idle
	const readTimeout = 500 * time.Millisecond

	for {
		if l.closed.Load() {
			return
		}

		// Set read deadline to allow checking closed state
		sess.RemoteConn.SetReadDeadline(time.Now().Add(readTimeout))
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

// GetCachedLatency returns the cached latency in milliseconds.
// Returns -1 if not available or offline.
func (l *UDPListener) GetCachedLatency() int64 {
	l.cachedPongMu.RLock()
	defer l.cachedPongMu.RUnlock()
	return l.lastPongLatency
}

// GetCachedPong returns the cached pong data.
func (l *UDPListener) GetCachedPong() []byte {
	l.cachedPongMu.RLock()
	defer l.cachedPongMu.RUnlock()
	return l.cachedPong
}

func (l *UDPListener) closeServerSessions() {
	if l.sessionMgr == nil {
		return
	}
	for _, sess := range l.sessionMgr.GetAllSessions() {
		if sess != nil && sess.ServerID == l.serverID {
			_ = l.sessionMgr.Remove(sess.ClientAddr)
		}
	}
}

func (l *UDPListener) waitRemoteReceivers(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		l.remoteWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(timeout):
		logger.Warn("UDPListener: timed out waiting %s for remote receivers to stop (server=%s)", timeout, l.serverID)
	}
}

// Stop closes the UDP listener.
func (l *UDPListener) Stop() error {
	l.closed.Store(true)
	var err error
	if l.conn != nil {
		err = l.conn.Close()
	}
	l.closeServerSessions()
	l.waitRemoteReceivers(2 * time.Second)
	return err
}

// LocalAddr returns the local address the listener is bound to.
func (l *UDPListener) LocalAddr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return nil
}
