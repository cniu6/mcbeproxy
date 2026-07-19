package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

const (
	plainUDPReadTimeout  = 500 * time.Millisecond
	plainUDPWriteTimeout = 5 * time.Second
	defaultPlainIdle     = 5 * time.Minute
	// plainUDPUpstreamWriteTimeout bounds a single client-to-target write on the
	// per-client async writer (see forwardUpstreamWrites). UDP should drop under
	// congestion instead of stalling; kept short like RawUDP's equivalent.
	plainUDPUpstreamWriteTimeout = 250 * time.Millisecond
	// plainUDPUpstreamWriteQueueSize buffers short per-client bursts without
	// letting a blocked outbound consume unbounded memory.
	plainUDPUpstreamWriteQueueSize = 64
	// plainUDPPendingDialQueueCap bounds how many datagrams get buffered on a
	// still-connecting (pending) client while its proxy dial runs in the
	// background (see createPendingClientAndDialAsync).
	plainUDPPendingDialQueueCap = 16
)

var (
	errPlainUDPUpstreamQueueClosed = errors.New("plain udp upstream writer closed")
	errPlainUDPUpstreamQueueFull   = errors.New("plain udp upstream write queue full")
)

// plainUDPPendingWrite carries a buffer-pool packet through the async
// upstream write queue (or the pending-dial buffer) so the owning goroutine
// can return it to the pool once it's actually written (or discarded).
type plainUDPPendingWrite struct {
	buf *[]byte
	n   int
}

type plainUDPClient struct {
	clientAddr *net.UDPAddr
	targetConn net.PacketConn
	targetAddr net.Addr
	lastSeen   atomic.Int64

	// pending: true while the proxy dial for this client is still running on
	// createPendingClientAndDialAsync's background goroutine. Packets that
	// arrive while pending are buffered (pendingMu/pendingPackets) instead of
	// forwarded, since there's no targetConn yet. Like RawUDP's equivalent,
	// this placeholder's fields are write-once at creation (before being
	// published) and never mutated in place afterwards, other than lastSeen
	// and the pending buffer — the real client fully replaces it on success.
	pending        atomic.Bool
	pendingMu      sync.Mutex
	pendingPackets []*plainUDPPendingWrite

	// Async upstream write queue: Listen()'s hot receive loop enqueues
	// instead of writing to targetConn directly, so one client's slow/stuck
	// upstream can't stall reads for every other client on this listener.
	upstreamWriteCh chan *plainUDPPendingWrite
	upstreamDone    chan struct{}
	upstreamMu      sync.Mutex
	upstreamOnce    sync.Once
	upstreamClosed  bool
}

func (c *plainUDPClient) enqueueUpstreamPacket(item *plainUDPPendingWrite) error {
	if c == nil || c.upstreamWriteCh == nil {
		return errPlainUDPUpstreamQueueClosed
	}
	c.upstreamMu.Lock()
	defer c.upstreamMu.Unlock()
	if c.upstreamClosed {
		return errPlainUDPUpstreamQueueClosed
	}
	select {
	case c.upstreamWriteCh <- item:
		return nil
	default:
		return errPlainUDPUpstreamQueueFull
	}
}

func (c *plainUDPClient) stopUpstreamWriter() {
	if c == nil {
		return
	}
	c.upstreamOnce.Do(func() {
		c.upstreamMu.Lock()
		c.upstreamClosed = true
		if c.upstreamDone != nil {
			close(c.upstreamDone)
		}
		c.upstreamMu.Unlock()
	})
}

// drainUpstreamWriteQueue returns any still-queued buffers to the pool so
// they aren't just dropped for the GC; safe to call after the writer
// goroutine has stopped (or never started).
func (c *plainUDPClient) drainUpstreamWriteQueue(bp *BufferPool) {
	if c == nil || c.upstreamWriteCh == nil {
		return
	}
	for {
		select {
		case item := <-c.upstreamWriteCh:
			if item != nil && bp != nil {
				bp.Put(item.buf)
			}
		default:
			return
		}
	}
}

type PlainUDPProxy struct {
	serverID    string
	config      *config.ServerConfig
	outboundMgr OutboundManager
	listener    *net.UDPConn
	targetAddr  net.Addr
	clients     sync.Map
	closed      atomic.Bool
	wg          sync.WaitGroup
	bufferPool  *BufferPool
	idleTimeout time.Duration

	// ctx/cancel are owned internally (created in Start(), cancelled in
	// Stop()) and used for background dials and per-client goroutines —
	// independent of whatever ctx a caller passes to Listen(). This ensures
	// Stop() can always promptly unblock an in-flight async proxy dial
	// (see createPendingClientAndDialAsync) without depending on the
	// caller's own context being cancelled at the right time.
	ctx    context.Context
	cancel context.CancelFunc
}

// context returns the proxy's internally-owned lifecycle context, falling
// back to context.Background() if Start() hasn't run yet.
func (p *PlainUDPProxy) context() context.Context {
	if p == nil || p.ctx == nil {
		return context.Background()
	}
	return p.ctx
}

func NewPlainUDPProxy(serverID string, cfg *config.ServerConfig) *PlainUDPProxy {
	return &PlainUDPProxy{
		serverID: serverID,
		config:   cfg,
	}
}

func (p *PlainUDPProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

func (p *PlainUDPProxy) UpdateConfig(cfg *config.ServerConfig) {
	p.config = cfg
	p.refreshTargetAddr()
	p.updateIdleTimeout()
	p.bufferPool = NewBufferPool(p.effectiveBufferSize())
}

func (p *PlainUDPProxy) Start() error {
	addr, err := net.ResolveUDPAddr("udp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address %s: %w", p.config.ListenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.ListenAddr, err)
	}
	tuneUDPSocketForServer(conn, p.config, "plain_udp:"+p.serverID)
	p.listener = conn
	p.closed.Store(false)
	p.refreshTargetAddr()
	p.updateIdleTimeout()

	p.bufferPool = NewBufferPool(p.effectiveBufferSize())

	// Own lifecycle context, created before any background work can observe
	// it — see the PlainUDPProxy.ctx doc comment.
	p.ctx, p.cancel = context.WithCancel(context.Background())

	return nil
}

func (p *PlainUDPProxy) Listen(ctx context.Context) error {
	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		buf := p.bufferPool.Get()
		p.listener.SetReadDeadline(time.Now().Add(plainUDPReadTimeout))
		n, clientAddr, err := p.listener.ReadFromUDP(*buf)
		if err != nil {
			p.bufferPool.Put(buf)
			if p.closed.Load() {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if !strings.Contains(err.Error(), "use of closed") {
				return err
			}
			return nil
		}

		// getOrCreateClient always takes ownership of buf: it either hands it
		// off to the client's async upstream write queue, buffers it while a
		// proxy dial is still pending, or returns it to the pool itself on
		// error. The hot loop never writes to targetConn directly anymore —
		// see forwardUpstreamWrites — so one client's slow/stuck upstream
		// can't stall reads for every other client on this listener.
		p.getOrCreateClient(clientAddr, buf, n)
	}
}

func (p *PlainUDPProxy) Stop() error {
	p.closed.Store(true)
	// Cancel the internal lifecycle context first so any in-flight async
	// proxy dial (see createPendingClientAndDialAsync) unblocks promptly
	// instead of holding up p.wg.Wait() below indefinitely.
	if p.cancel != nil {
		p.cancel()
	}
	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.clients.Range(func(key, value interface{}) bool {
		if client, ok := value.(*plainUDPClient); ok {
			// Must stop the async writer goroutine (if any) before closing
			// targetConn, otherwise forwardUpstreamWrites can block forever on
			// an empty channel with nothing to wake it, leaking the goroutine
			// and hanging p.wg.Wait() below.
			client.stopUpstreamWriter()
			client.drainUpstreamWriteQueue(p.bufferPool)
			if client.targetConn != nil {
				_ = client.targetConn.Close()
			}
		}
		p.clients.Delete(key)
		return true
	})
	p.wg.Wait()
	return nil
}

func (p *PlainUDPProxy) effectiveTargetAddrString() string {
	if p.targetAddr != nil {
		return p.targetAddr.String()
	}
	if p.config != nil {
		return p.config.GetTargetAddr()
	}
	return ""
}

func (p *PlainUDPProxy) resolvedTargetAddr() (*net.UDPAddr, bool) {
	udpAddr, ok := p.targetAddr.(*net.UDPAddr)
	return udpAddr, ok
}

// getOrCreateClient gets or creates a client connection. It always takes
// ownership of buf/n (see call site in Listen()): depending on the outcome,
// buf is either forwarded (enqueued to the client's async writer), buffered
// on a still-pending client, or returned to the pool here on error. Dialing
// uses p.context() (Start()/Stop()-owned), not any externally-passed ctx.
func (p *PlainUDPProxy) getOrCreateClient(clientAddr *net.UDPAddr, buf *[]byte, n int) (*plainUDPClient, bool) {
	clientKey := clientAddr.String()
	if val, ok := p.clients.Load(clientKey); ok {
		existing := val.(*plainUDPClient)
		existing.lastSeen.Store(time.Now().UnixNano())
		if existing.pending.Load() {
			existing.pendingMu.Lock()
			if len(existing.pendingPackets) < plainUDPPendingDialQueueCap {
				existing.pendingPackets = append(existing.pendingPackets, &plainUDPPendingWrite{buf: buf, n: n})
			} else {
				p.bufferPool.Put(buf)
			}
			existing.pendingMu.Unlock()
			return nil, false
		}
		if err := existing.enqueueUpstreamPacket(&plainUDPPendingWrite{buf: buf, n: n}); err != nil {
			p.bufferPool.Put(buf)
		}
		return existing, false
	}

	p.cleanupStaleSameIPClients(clientAddr)

	// getOrCreateClient runs on the single hot receive-loop goroutine (see
	// Listen()). A synchronous proxy dial here can block that loop for
	// seconds, stalling every OTHER already-connected client on this same
	// server. When at least one other client is already active, offload the
	// dial to a background goroutine instead (buffering this packet and any
	// retries so nothing is lost). The very first client on an otherwise-idle
	// server still dials synchronously — nobody else could be blocked by it.
	if !p.config.IsDirectConnection() && p.GetActiveClientCount() > 0 {
		p.createPendingClientAndDialAsync(clientKey, clientAddr, buf, n)
		return nil, false
	}

	targetConn, targetAddr, err := p.dialTargetConn(p.context())
	if err != nil {
		p.bufferPool.Put(buf)
		logger.Error("PlainUDPProxy: failed to dial target %s (client=%s server=%s active_proxy_clients=%d): %v",
			p.config.GetTargetAddr(), clientKey, p.serverID, p.GetActiveClientCount(), err)
		return nil, false
	}

	client := &plainUDPClient{
		clientAddr:      clientAddr,
		targetConn:      targetConn,
		targetAddr:      targetAddr,
		upstreamWriteCh: make(chan *plainUDPPendingWrite, plainUDPUpstreamWriteQueueSize),
		upstreamDone:    make(chan struct{}),
	}
	client.lastSeen.Store(time.Now().UnixNano())

	p.clients.Store(clientKey, client)

	p.wg.Add(2)
	go p.forwardResponses(clientKey, client)
	go p.forwardUpstreamWrites(clientKey, client)

	if err := client.enqueueUpstreamPacket(&plainUDPPendingWrite{buf: buf, n: n}); err != nil {
		p.bufferPool.Put(buf)
	}

	logger.Info("PlainUDP: new proxy client server=%s client=%s active_proxy_clients=%d",
		p.serverID, clientKey, p.GetActiveClientCount())

	return client, true
}

// createPendingClientAndDialAsync registers an immediate placeholder for
// clientKey and performs the (possibly slow) proxy dial on a background
// goroutine instead of the hot receive-loop goroutine. Mirrors RawUDPProxy's
// equivalent — see its doc comment for the full head-of-line-blocking
// rationale.
func (p *PlainUDPProxy) createPendingClientAndDialAsync(clientKey string, clientAddr *net.UDPAddr, buf *[]byte, n int) {
	placeholder := &plainUDPClient{clientAddr: clientAddr}
	placeholder.pending.Store(true)
	placeholder.lastSeen.Store(time.Now().UnixNano())
	placeholder.pendingPackets = append(placeholder.pendingPackets, &plainUDPPendingWrite{buf: buf, n: n})
	p.clients.Store(clientKey, placeholder)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Info("PlainUDP async-dial panic recovered: client=%s err=%v", clientKey, r)
			}
		}()
		p.finishPendingClientDial(clientKey, clientAddr, placeholder)
	}()
}

// finishPendingClientDial runs on its own goroutine and dials the target
// without holding up the shared receive loop. On success it atomically
// swaps the pending placeholder for a fully-initialized client, flushes
// whatever was buffered while pending, and starts the normal forwarding
// goroutines. On failure, or if the placeholder was superseded/removed while
// dialing, it cleans up and does nothing further.
func (p *PlainUDPProxy) finishPendingClientDial(clientKey string, clientAddr *net.UDPAddr, placeholder *plainUDPClient) {
	targetConn, targetAddr, err := p.dialTargetConn(p.context())
	if err != nil {
		logger.Error("PlainUDPProxy: failed to dial target %s asynchronously (client=%s server=%s active_proxy_clients=%d): %v",
			p.config.GetTargetAddr(), clientKey, p.serverID, p.GetActiveClientCount(), err)
		p.removeClientIfMatch(clientKey, placeholder)
		return
	}

	client := &plainUDPClient{
		clientAddr:      clientAddr,
		targetConn:      targetConn,
		targetAddr:      targetAddr,
		upstreamWriteCh: make(chan *plainUDPPendingWrite, plainUDPUpstreamWriteQueueSize),
		upstreamDone:    make(chan struct{}),
	}
	client.lastSeen.Store(time.Now().UnixNano())

	// Flush everything buffered while pending into the new client's upstream
	// queue BEFORE publishing it, so ordering is preserved: any packet the
	// hot loop enqueues after it observes the swap is guaranteed to land
	// after these.
	placeholder.pendingMu.Lock()
	buffered := placeholder.pendingPackets
	placeholder.pendingPackets = nil
	placeholder.pendingMu.Unlock()
	for _, item := range buffered {
		if err := client.enqueueUpstreamPacket(item); err != nil {
			p.bufferPool.Put(item.buf)
		}
	}

	if !p.clients.CompareAndSwap(clientKey, placeholder, client) {
		_ = targetConn.Close()
		client.drainUpstreamWriteQueue(p.bufferPool)
		logger.Debug("PlainUDP: async dial finished but client %s was superseded, discarding connection", clientKey)
		return
	}

	p.wg.Add(2)
	go p.forwardResponses(clientKey, client)
	go p.forwardUpstreamWrites(clientKey, client)

	logger.Info("PlainUDP: new proxy client server=%s client=%s active_proxy_clients=%d",
		p.serverID, clientKey, p.GetActiveClientCount())
}

// forwardUpstreamWrites drains a client's async upstream write queue,
// writing each packet to targetConn off the hot receive loop.
func (p *PlainUDPProxy) forwardUpstreamWrites(clientKey string, clientInfo *plainUDPClient) {
	defer p.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Info("PlainUDP forwardUpstreamWrites panic recovered: client=%s err=%v", clientKey, r)
		}
	}()
	if clientInfo == nil || clientInfo.targetConn == nil || clientInfo.upstreamWriteCh == nil {
		return
	}
	defer clientInfo.drainUpstreamWriteQueue(p.bufferPool)

	for {
		select {
		case <-clientInfo.upstreamDone:
			return
		case item := <-clientInfo.upstreamWriteCh:
			if item == nil {
				continue
			}
			clientInfo.targetConn.SetWriteDeadline(time.Now().Add(plainUDPUpstreamWriteTimeout))
			_, err := writePacketConn(clientInfo.targetConn, (*item.buf)[:item.n], clientInfo.targetAddr)
			p.bufferPool.Put(item.buf)
			// A transient ICMP-induced error on a connected/direct UDP socket
			// (e.g. connection refused) must not drop the session; skip the datagram.
			if err != nil && !isTimeoutError(err) && !isRecoverableConnError(err) {
				logger.Debug("PlainUDPProxy: write to target failed for %s: %v", clientKey, err)
				p.removeClientIfMatch(clientKey, clientInfo)
				return
			}
		}
	}
}

func (p *PlainUDPProxy) dialTargetConn(ctx context.Context) (net.PacketConn, net.Addr, error) {
	if p.targetAddr == nil {
		return nil, nil, fmt.Errorf("target address not resolved")
	}
	if p.config == nil {
		return nil, nil, fmt.Errorf("plain udp proxy configuration is nil")
	}
	if p.config.IsDirectConnection() {
		udpAddr, ok := p.resolvedTargetAddr()
		if !ok || udpAddr == nil {
			return nil, nil, fmt.Errorf("target address %s is not resolved for direct dialing", p.effectiveTargetAddrString())
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, nil, err
		}
		tuneUDPSocketForServer(conn, p.config, "plain_udp_direct:"+udpAddr.String())
		return conn, udpAddr, nil
	}
	if p.outboundMgr == nil {
		return nil, nil, fmt.Errorf("proxy outbound manager unavailable for plain udp server %s", p.serverID)
	}

	proxyOutbound := p.config.GetProxyOutbound()
	if p.config.IsGroupSelection() || p.config.IsMultiNodeSelection() {
		strategy := p.config.GetLoadBalance()
		sortBy := p.config.GetLoadBalanceSort()
		exclude := make([]string, 0, 4)
		attempts := proxySelectionAttemptLimit(p.config, p.outboundMgr)
		for i := 0; i < attempts; i++ {
			selected, err := p.outboundMgr.SelectOutboundWithFailoverForServer(p.serverID, proxyOutbound, strategy, sortBy, exclude)
			if err != nil {
				return nil, nil, err
			}
			// "direct" token within a multi-node list: skip the outbound
			// dial path and resolve+dial the target ourselves. Failover
			// semantics still apply if the direct dial fails.
			if IsDirectSelection(selected) {
				udpAddr, ok := p.resolvedTargetAddr()
				if !ok || udpAddr == nil {
					exclude = append(exclude, DirectNodeName)
					continue
				}
				conn, derr := net.DialUDP("udp", nil, udpAddr)
				if derr == nil {
					tuneUDPSocketForServer(conn, p.config, "plain_udp_direct:"+udpAddr.String())
					return conn, p.targetAddr, nil
				}
				exclude = append(exclude, DirectNodeName)
				continue
			}
			conn, err := dialPacketConnForFailover(ctx, p.outboundMgr, selected.Name, p.config.GetTargetAddr())
			if err == nil {
				return conn, p.targetAddr, nil
			}
			exclude = append(exclude, selected.Name)
		}
		return nil, nil, fmt.Errorf("all proxy outbounds failed")
	}

	conn, err := p.outboundMgr.DialPacketConn(ctx, proxyOutbound, p.config.GetTargetAddr())
	if err != nil {
		return nil, nil, err
	}
	return conn, p.targetAddr, nil
}

func (p *PlainUDPProxy) forwardResponses(clientKey string, clientInfo *plainUDPClient) {
	defer p.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Info("PlainUDP forwardResponses panic recovered: client=%s err=%v", clientKey, r)
			p.removeClientIfMatch(clientKey, clientInfo)
		}
	}()
	defer p.removeClientIfMatch(clientKey, clientInfo)

	bufPtr := p.bufferPool.Get()
	buffer := *bufPtr
	defer p.bufferPool.Put(bufPtr)

	for {
		select {
		case <-p.context().Done():
			return
		default:
		}

		clientInfo.targetConn.SetReadDeadline(time.Now().Add(UDPReadTimeout))
		n, _, err := clientInfo.targetConn.ReadFrom(buffer)
		if err != nil {
			if p.closed.Load() {
				return
			}
			if err == io.EOF {
				return
			}
			if !isTimeoutError(err) {
				// Transient ICMP-induced error on a connected/direct UDP socket:
				// keep the session and rely on the idle reaper for dead peers.
				if isRecoverableConnError(err) {
					if p.isClientIdleExpired(clientInfo, time.Now()) {
						return
					}
					continue
				}
				if !strings.Contains(err.Error(), "use of closed") {
					logger.Debug("PlainUDPProxy: read from target failed for %s: %v", clientInfo.clientAddr.String(), err)
				}
				return
			}
			if p.isClientIdleExpired(clientInfo, time.Now()) {
				return
			}
			continue
		}

		clientInfo.lastSeen.Store(time.Now().UnixNano())
		p.listener.SetWriteDeadline(time.Now().Add(plainUDPWriteTimeout))
		_, err = p.listener.WriteToUDP(buffer[:n], clientInfo.clientAddr)
		if err != nil && !isTimeoutError(err) {
			// Transient ICMP-induced error on the shared listener socket:
			// drop this datagram only, keep the session.
			if isRecoverableConnError(err) {
				continue
			}
			if !strings.Contains(err.Error(), "use of closed") {
				logger.Debug("PlainUDPProxy: write to client failed for %s: %v", clientInfo.clientAddr.String(), err)
			}
			return
		}
	}
}

func (p *PlainUDPProxy) cleanupStaleSameIPClients(clientAddr *net.UDPAddr) {
	if clientAddr == nil || clientAddr.IP == nil {
		return
	}
	clientKey := clientAddr.String()
	clientIP := clientAddr.IP.String()
	now := time.Now()

	var staleKeys []struct {
		key    string
		reason string
	}
	p.clients.Range(func(key, value interface{}) bool {
		keyStr := key.(string)
		if keyStr == clientKey {
			return true
		}
		info := value.(*plainUDPClient)
		if info.clientAddr == nil || info.clientAddr.IP == nil || info.clientAddr.IP.String() != clientIP {
			return true
		}
		silence := now.Sub(time.Unix(0, info.lastSeen.Load()))
		if silence > sameIPReconnectGrace {
			staleKeys = append(staleKeys, struct {
				key    string
				reason string
			}{keyStr, fmt.Sprintf("silent_for_%v", silence.Round(time.Second))})
		}
		return true
	})
	for _, entry := range staleKeys {
		logger.Info("PlainUDP: removing stale same-IP client %s for new connection %s (reason=%s)",
			entry.key, clientKey, entry.reason)
		p.removeClient(entry.key)
	}
	if len(staleKeys) > 0 {
		logger.Info("PlainUDP: same-IP cleanup server=%s ip=%s removed=%d active_proxy_clients=%d",
			p.serverID, clientIP, len(staleKeys), p.GetActiveClientCount())
	}
}

// GetActiveClientCount returns the number of per-client upstream UDP links.
func (p *PlainUDPProxy) GetActiveClientCount() int {
	count := 0
	p.clients.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

func (p *PlainUDPProxy) removeClient(clientKey string) {
	p.removeClientIfMatch(clientKey, nil)
}

func (p *PlainUDPProxy) removeClientIfMatch(clientKey string, expected *plainUDPClient) {
	if expected != nil {
		if !p.clients.CompareAndDelete(clientKey, expected) {
			return
		}
		p.finalizePlainClientRemoval(clientKey, expected)
		return
	}
	if val, ok := p.clients.LoadAndDelete(clientKey); ok {
		p.finalizePlainClientRemoval(clientKey, val.(*plainUDPClient))
	}
}

func (p *PlainUDPProxy) finalizePlainClientRemoval(clientKey string, client *plainUDPClient) {
	if client == nil {
		return
	}
	client.stopUpstreamWriter()
	client.drainUpstreamWriteQueue(p.bufferPool)
	if client.targetConn != nil {
		_ = client.targetConn.Close()
	}
	logger.Info("PlainUDP: client disconnected server=%s client=%s active_proxy_clients=%d",
		p.serverID, clientKey, p.GetActiveClientCount())
}

func (p *PlainUDPProxy) effectiveBufferSize() int {
	if p.config == nil {
		return MaxUDPPacketSize
	}
	bufferSize := p.config.GetBufferSize()
	if bufferSize == AutoBufferSize || bufferSize <= 0 {
		return MaxUDPPacketSize
	}
	if bufferSize > MaxBufferSize {
		return MaxBufferSize
	}
	return bufferSize
}

func (p *PlainUDPProxy) refreshTargetAddr() {
	shouldPreserveHostname := p.config != nil && !p.config.IsDirectConnection()
	addr, _, err := buildUDPDestinationAddr(context.Background(), p.config.GetTargetAddr(), shouldPreserveHostname)
	if err != nil {
		logger.Warn("PlainUDPProxy: failed to resolve target %s: %v", p.config.GetTargetAddr(), err)
		return
	}
	p.targetAddr = addr
}

func (p *PlainUDPProxy) isClientIdleExpired(clientInfo *plainUDPClient, now time.Time) bool {
	if clientInfo == nil || p.idleTimeout < 0 {
		return false
	}
	timeout := p.idleTimeout
	if timeout == 0 {
		timeout = defaultPlainIdle
	}
	return now.Sub(time.Unix(0, clientInfo.lastSeen.Load())) > timeout
}

func (p *PlainUDPProxy) updateIdleTimeout() {
	if p.config != nil {
		if p.config.IdleTimeout == -1 {
			p.idleTimeout = -1
			return
		}
		if p.config.IdleTimeout > 0 {
			p.idleTimeout = time.Duration(p.config.IdleTimeout) * time.Second
			return
		}
	}
	p.idleTimeout = defaultPlainIdle
}
