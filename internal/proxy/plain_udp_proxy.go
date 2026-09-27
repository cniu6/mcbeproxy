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
	// letting a blocked outbound consume unbounded memory. Same as raw_udp:
	// while chunks stream in after joining, the client ACKs every datagram,
	// and a 64-slot queue dropped ACKs, which made the server retransmit.
	plainUDPUpstreamWriteQueueSize = RawUDPUpstreamWriteQueueSize
	// plainUDPPendingDialQueueCap bounds how many datagrams get buffered on a
	// still-connecting (pending) client while its proxy dial runs in the
	// background (see createPendingClientAndDialAsync).
	plainUDPPendingDialQueueCap = 16
	// plainUDPBlackholeProbeInterval is the target read deadline used while a
	// proxied client has not received any downstream packet yet, so blackhole
	// detection fires within seconds instead of after UDPReadTimeout (30s) —
	// Minecraft gives up on a connection attempt after roughly 10s.
	plainUDPBlackholeProbeInterval = time.Second
	// plainUDPBlackholeRecoverAfter is shorter than RawUDP's: RakNet retries
	// Open Connection Request every ~0.5-1s for ~10s, so tearing a dead
	// association down after 3s lets the same attempt retry on a fresh one.
	plainUDPBlackholeRecoverAfter = 3 * time.Second
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
	startTime  time.Time

	// Traffic counters: logged when the client is removed and used for
	// blackhole detection (upstream packets sent, nothing ever received).
	packetsUp   atomic.Int64
	packetsDown atomic.Int64
	bytesUp     atomic.Int64
	bytesDown   atomic.Int64

	// pending: true while the proxy dial for this client is still running on
	// createPendingClientAndDialAsync's background goroutine. Packets that
	// arrive while pending are buffered (pendingMu/pendingPackets) instead of
	// forwarded, since there's no targetConn yet. Like RawUDP's equivalent,
	// this placeholder's fields are write-once at creation (before being
	// published) and never mutated in place afterwards, other than lastSeen
	// and the pending buffer — the real client fully replaces it on success.
	pending        atomic.Bool
	pendingMu      sync.Mutex
	pendingPackets []plainUDPPendingWrite

	// Async upstream write queue: Listen()'s hot receive loop enqueues
	// instead of writing to targetConn directly, so one client's slow/stuck
	// upstream can't stall reads for every other client on this listener.
	upstreamWriteCh chan plainUDPPendingWrite
	upstreamDone    chan struct{}
	upstreamMu      sync.Mutex
	upstreamOnce    sync.Once
	upstreamClosed  bool
}

func (c *plainUDPClient) enqueueUpstreamPacket(item plainUDPPendingWrite) error {
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
			if item.buf != nil && bp != nil {
				bp.Put(item.buf)
			}
		default:
			return
		}
	}
}

type PlainUDPProxy struct {
	serverID    string
	cfgPtr      atomic.Pointer[config.ServerConfig] // read via conf(); swapped by UpdateConfig while forwarding
	outboundMgr OutboundManager
	listener    *net.UDPConn
	nnRelay     atomic.Pointer[netherNetRelay] // NetherNet media shares listener; nil unless nethernet_relay
	targetPtr   atomic.Pointer[plainUDPTarget] // resolved target, swapped by UpdateConfig
	clients     sync.Map
	closed      atomic.Bool
	wg          sync.WaitGroup
	bufferPool  atomic.Pointer[BufferPool] // read via pool(); swapped when buffer_size changes
	idleTimeout atomic.Int64               // time.Duration; -1 = never

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
	p := &PlainUDPProxy{serverID: serverID}
	p.cfgPtr.Store(cfg)
	return p
}

// plainUDPTarget is one immutable resolution of the target address.
type plainUDPTarget struct{ addr net.Addr }

// conf returns the current server config (hot-reloaded by UpdateConfig).
func (p *PlainUDPProxy) conf() *config.ServerConfig {
	return p.cfgPtr.Load()
}

// pool returns the current packet buffer pool.
func (p *PlainUDPProxy) pool() *BufferPool {
	return p.bufferPool.Load()
}

// target returns the resolved target address, or nil.
func (p *PlainUDPProxy) target() net.Addr {
	if t := p.targetPtr.Load(); t != nil {
		return t.addr
	}
	return nil
}

func (p *PlainUDPProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

func (p *PlainUDPProxy) UpdateConfig(cfg *config.ServerConfig) {
	p.cfgPtr.Store(cfg)
	p.refreshTargetAddr()
	p.updateIdleTimeout()
	// buffer_size applies live: new datagrams use the new pool, and buffers
	// still out from the old one are dropped on Put (size mismatch) instead of
	// being recycled.
	if size := p.effectiveBufferSize(); p.pool() == nil || p.pool().Size() != size {
		p.bufferPool.Store(NewBufferPool(size))
	}
	syncNetherNetRelay(&p.nnRelay, p.serverID, p.conf, p.outboundMgr, p.listener, p.closed.Load)
}

func (p *PlainUDPProxy) Start() error {
	addr, err := net.ResolveUDPAddr("udp", p.conf().ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address %s: %w", p.conf().ListenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.conf().ListenAddr, err)
	}
	tuneUDPSocketForServer(conn, p.conf(), "plain_udp:"+p.serverID)
	p.listener = conn
	p.closed.Store(false)
	p.refreshTargetAddr()
	p.updateIdleTimeout()

	p.bufferPool.Store(NewBufferPool(p.effectiveBufferSize()))

	// Own lifecycle context, created before any background work can observe
	// it — see the PlainUDPProxy.ctx doc comment.
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.nnRelay.Store(startNetherNetRelayIfEnabled(p.serverID, p.conf, p.outboundMgr, conn))

	return nil
}

func (p *PlainUDPProxy) Listen(ctx context.Context) error {
	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	// The shared listener is written by every client's response goroutine;
	// keep it free of per-packet write deadlines (see writes below).
	_ = p.listener.SetWriteDeadline(time.Time{})
	var readDeadlineSetAt time.Time
	var addrCache udpAddrCache
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		buf := p.pool().Get()
		if now := time.Now(); now.Sub(readDeadlineSetAt) >= plainUDPReadTimeout/2 {
			p.listener.SetReadDeadline(now.Add(plainUDPReadTimeout))
			readDeadlineSetAt = now
		}
		n, clientAddrPort, err := p.listener.ReadFromUDPAddrPort(*buf)
		if err != nil {
			p.pool().Put(buf)
			if p.closed.Load() {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				readDeadlineSetAt = time.Time{}
				continue
			}
			if !strings.Contains(err.Error(), "use of closed") {
				return err
			}
			return nil
		}

		// NetherNet media shares this port; the relay copies what it claims.
		if r := p.nnRelay.Load(); r != nil && r.handleDatagram((*buf)[:n], clientAddrPort) {
			p.pool().Put(buf)
			continue
		}

		// getOrCreateClient always takes ownership of buf: it either hands it
		// off to the client's async upstream write queue, buffers it while a
		// proxy dial is still pending, or returns it to the pool itself on
		// error. The hot loop never writes to targetConn directly anymore —
		// see forwardUpstreamWrites — so one client's slow/stuck upstream
		// can't stall reads for every other client on this listener.
		clientAddr, clientKey := addrCache.lookup(clientAddrPort)
		p.getOrCreateClientKeyed(clientAddr, clientKey, buf, n)
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
	_ = p.nnRelay.Swap(nil).Close()
	p.clients.Range(func(key, value interface{}) bool {
		if client, ok := value.(*plainUDPClient); ok {
			// Must stop the async writer goroutine (if any) before closing
			// targetConn, otherwise forwardUpstreamWrites can block forever on
			// an empty channel with nothing to wake it, leaking the goroutine
			// and hanging p.wg.Wait() below.
			client.stopUpstreamWriter()
			client.drainUpstreamWriteQueue(p.pool())
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
	if t := p.target(); t != nil {
		return t.String()
	}
	if p.conf() != nil {
		return p.conf().GetTargetAddr()
	}
	return ""
}

func (p *PlainUDPProxy) resolvedTargetAddr() (*net.UDPAddr, bool) {
	udpAddr, ok := p.target().(*net.UDPAddr)
	return udpAddr, ok
}

// getOrCreateClient gets or creates a client connection. It always takes
// ownership of buf/n (see call site in Listen()): depending on the outcome,
// buf is either forwarded (enqueued to the client's async writer), buffered
// on a still-pending client, or returned to the pool here on error. Dialing
// uses p.context() (Start()/Stop()-owned), not any externally-passed ctx.
func (p *PlainUDPProxy) getOrCreateClient(clientAddr *net.UDPAddr, buf *[]byte, n int) (*plainUDPClient, bool) {
	return p.getOrCreateClientKeyed(clientAddr, clientAddr.String(), buf, n)
}

// getOrCreateClientKeyed is getOrCreateClient with the map key precomputed
// (see udpAddrCache), so the hot receive loop does not format it per packet.
func (p *PlainUDPProxy) getOrCreateClientKeyed(clientAddr *net.UDPAddr, clientKey string, buf *[]byte, n int) (*plainUDPClient, bool) {
	if val, ok := p.clients.Load(clientKey); ok {
		existing := val.(*plainUDPClient)
		existing.lastSeen.Store(time.Now().UnixNano())
		if existing.pending.Load() {
			existing.pendingMu.Lock()
			if len(existing.pendingPackets) < plainUDPPendingDialQueueCap {
				existing.pendingPackets = append(existing.pendingPackets, plainUDPPendingWrite{buf: buf, n: n})
			} else {
				p.pool().Put(buf)
			}
			existing.pendingMu.Unlock()
			return nil, false
		}
		if err := existing.enqueueUpstreamPacket(plainUDPPendingWrite{buf: buf, n: n}); err != nil {
			p.pool().Put(buf)
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
	if !p.conf().IsDirectConnection() && p.GetActiveClientCount() > 0 {
		p.createPendingClientAndDialAsync(clientKey, clientAddr, buf, n)
		return nil, false
	}

	targetConn, targetAddr, err := p.dialTargetConn(p.context())
	if err != nil {
		p.pool().Put(buf)
		logger.Error("PlainUDPProxy: failed to dial target %s (client=%s server=%s active_proxy_clients=%d): %v",
			p.conf().GetTargetAddr(), clientKey, p.serverID, p.GetActiveClientCount(), err)
		return nil, false
	}

	client := &plainUDPClient{
		clientAddr:      clientAddr,
		targetConn:      targetConn,
		targetAddr:      targetAddr,
		startTime:       time.Now(),
		upstreamWriteCh: make(chan plainUDPPendingWrite, plainUDPUpstreamWriteQueueSize),
		upstreamDone:    make(chan struct{}),
	}
	client.lastSeen.Store(time.Now().UnixNano())

	p.clients.Store(clientKey, client)

	p.wg.Add(2)
	go p.forwardResponses(clientKey, client)
	go p.forwardUpstreamWrites(clientKey, client)

	if err := client.enqueueUpstreamPacket(plainUDPPendingWrite{buf: buf, n: n}); err != nil {
		p.pool().Put(buf)
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
	placeholder.pendingPackets = append(placeholder.pendingPackets, plainUDPPendingWrite{buf: buf, n: n})
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
			p.conf().GetTargetAddr(), clientKey, p.serverID, p.GetActiveClientCount(), err)
		p.removeClientIfMatch(clientKey, placeholder)
		return
	}

	client := &plainUDPClient{
		clientAddr:      clientAddr,
		targetConn:      targetConn,
		targetAddr:      targetAddr,
		startTime:       time.Now(),
		upstreamWriteCh: make(chan plainUDPPendingWrite, plainUDPUpstreamWriteQueueSize),
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
			p.pool().Put(item.buf)
		}
	}

	if !p.clients.CompareAndSwap(clientKey, placeholder, client) {
		_ = targetConn.Close()
		client.drainUpstreamWriteQueue(p.pool())
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
	defer clientInfo.drainUpstreamWriteQueue(p.pool())
	mtuClamp := p.conf().GetRakNetMTUClamp()
	var writeDeadlineAt time.Time // refreshed only when under half the timeout is left

	for {
		select {
		case <-clientInfo.upstreamDone:
			return
		case item := <-clientInfo.upstreamWriteCh:
			if item.buf == nil {
				continue
			}
			// Minecraft's first handshake pads to 1492 bytes, which no longer
			// fits a 1500-byte path once the proxy node adds its tunnel header
			// (see raknet_mtu.go); non-RakNet datagrams pass through unchanged.
			pkt := clampRakNetHandshakeMTU((*item.buf)[:item.n], mtuClamp)
			if now := time.Now(); writeDeadlineAt.Sub(now) < plainUDPUpstreamWriteTimeout/2 {
				writeDeadlineAt = now.Add(plainUDPUpstreamWriteTimeout)
				clientInfo.targetConn.SetWriteDeadline(writeDeadlineAt)
			}
			_, err := writePacketConn(clientInfo.targetConn, pkt, clientInfo.targetAddr)
			if err == nil {
				clientInfo.packetsUp.Add(1)
				clientInfo.bytesUp.Add(int64(len(pkt)))
			}
			p.pool().Put(item.buf)
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
	if p.target() == nil {
		return nil, nil, fmt.Errorf("target address not resolved")
	}
	if p.conf() == nil {
		return nil, nil, fmt.Errorf("plain udp proxy configuration is nil")
	}
	if p.conf().IsDirectConnection() {
		udpAddr, ok := p.resolvedTargetAddr()
		if !ok || udpAddr == nil {
			return nil, nil, fmt.Errorf("target address %s is not resolved for direct dialing", p.effectiveTargetAddrString())
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, nil, err
		}
		tuneUDPSocketForServer(conn, p.conf(), "plain_udp_direct:"+udpAddr.String())
		return conn, udpAddr, nil
	}
	if p.outboundMgr == nil {
		return nil, nil, fmt.Errorf("proxy outbound manager unavailable for plain udp server %s", p.serverID)
	}

	proxyOutbound := p.conf().GetProxyOutbound()
	if p.conf().IsGroupSelection() || p.conf().IsMultiNodeSelection() {
		strategy := p.conf().GetLoadBalance()
		sortBy := p.conf().GetLoadBalanceSort()
		exclude := make([]string, 0, 4)
		attempts := proxySelectionAttemptLimit(p.conf(), p.outboundMgr)
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
					tuneUDPSocketForServer(conn, p.conf(), "plain_udp_direct:"+udpAddr.String())
					return conn, p.target(), nil
				}
				exclude = append(exclude, DirectNodeName)
				continue
			}
			conn, err := dialPacketConnForFailover(ctx, p.outboundMgr, selected.Name, p.conf().GetTargetAddr())
			if err == nil {
				tunePacketConnBuffersForNode(conn, p.conf(), p.outboundMgr, selected.Name, "plain_udp_proxy:"+p.serverID+":"+selected.Name)
				return conn, p.target(), nil
			}
			exclude = append(exclude, selected.Name)
		}
		return nil, nil, fmt.Errorf("all proxy outbounds failed")
	}

	conn, err := p.outboundMgr.DialPacketConn(ctx, proxyOutbound, p.conf().GetTargetAddr())
	if err != nil {
		return nil, nil, err
	}
	// Like raw_udp: the node leg must absorb the spawn burst (several MB of
	// chunks in seconds). With the OS default buffer (about 208KB on Linux,
	// 64KB on Windows) it overflowed, RakNet stalled on retransmits for the
	// first seconds after joining, then recovered.
	tunePacketConnBuffersForNode(conn, p.conf(), p.outboundMgr, proxyOutbound, "plain_udp_proxy:"+p.serverID+":"+proxyOutbound)
	return conn, p.target(), nil
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

	bufPtr := p.pool().Get()
	buffer := *bufPtr
	defer p.pool().Put(bufPtr)

	// Reconnecting only helps when a proxy association can be replaced; a
	// direct socket to a dead target must survive (see isRecoverableConnError).
	probeBlackhole := !p.conf().IsDirectConnection()
	mtuClamp := p.conf().GetRakNetMTUClamp()
	var readDeadlineSetAt time.Time
	for {
		select {
		case <-p.context().Done():
			return
		default:
		}

		if now := time.Now(); now.Sub(readDeadlineSetAt) >= time.Second {
			readTimeout := UDPReadTimeout
			if probeBlackhole && clientInfo.packetsDown.Load() == 0 {
				readTimeout = plainUDPBlackholeProbeInterval
			}
			clientInfo.targetConn.SetReadDeadline(now.Add(readTimeout))
			readDeadlineSetAt = now
		}
		n, err := readPacketConn(clientInfo.targetConn, buffer)
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
			if probeBlackhole && p.isClientBlackholed(clientInfo, time.Now()) {
				logger.Warn("PlainUDP: blackhole detected (up_packets=%d down=0 after %v), closing for fresh ASSOCIATE: server=%s client=%s route=%s target=%s",
					clientInfo.packetsUp.Load(), time.Since(clientInfo.startTime).Round(time.Second),
					p.serverID, clientKey, p.conf().GetProxyOutbound(), p.effectiveTargetAddrString())
				return
			}
			if p.isClientIdleExpired(clientInfo, time.Now()) {
				return
			}
			readDeadlineSetAt = time.Time{}
			continue
		}

		clientInfo.packetsDown.Add(1)
		clientInfo.bytesDown.Add(int64(n))
		clientInfo.lastSeen.Store(time.Now().UnixNano())
		_, err = p.listener.WriteToUDP(clampRakNetHandshakeMTU(buffer[:n], mtuClamp), clientInfo.clientAddr)
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
	client.drainUpstreamWriteQueue(p.pool())
	if client.targetConn != nil {
		_ = client.targetConn.Close()
	}
	logger.Info("PlainUDP: client disconnected server=%s client=%s duration=%v up_packets=%d down_packets=%d up_bytes=%d down_bytes=%d active_proxy_clients=%d",
		p.serverID, clientKey, plainUDPClientDuration(client), client.packetsUp.Load(), client.packetsDown.Load(),
		client.bytesUp.Load(), client.bytesDown.Load(), p.GetActiveClientCount())
}

func plainUDPClientDuration(client *plainUDPClient) time.Duration {
	if client.startTime.IsZero() {
		return 0
	}
	return time.Since(client.startTime).Round(time.Second)
}

// isClientBlackholed reports whether the upstream path has been swallowing
// packets: the client kept sending but not a single datagram came back. The
// usual cause is a dead SOCKS5 UDP association; tearing the client down lets
// its next packet dial a fresh one.
func (p *PlainUDPProxy) isClientBlackholed(clientInfo *plainUDPClient, now time.Time) bool {
	return clientInfo.packetsDown.Load() == 0 &&
		clientInfo.packetsUp.Load() >= int64(RawUDPBlackholeMinUpPackets) &&
		now.Sub(clientInfo.startTime) >= plainUDPBlackholeRecoverAfter
}

func (p *PlainUDPProxy) effectiveBufferSize() int {
	if p.conf() == nil {
		return MaxUDPPacketSize
	}
	bufferSize := p.conf().GetBufferSize()
	if bufferSize == AutoBufferSize || bufferSize <= 0 {
		return MaxUDPPacketSize
	}
	if bufferSize > MaxBufferSize {
		return MaxBufferSize
	}
	return bufferSize
}

func (p *PlainUDPProxy) refreshTargetAddr() {
	shouldPreserveHostname := p.conf() != nil && !p.conf().IsDirectConnection()
	addr, _, err := buildUDPDestinationAddr(context.Background(), p.conf().GetTargetAddr(), shouldPreserveHostname)
	if err != nil {
		logger.Warn("PlainUDPProxy: failed to resolve target %s: %v", p.conf().GetTargetAddr(), err)
		return
	}
	p.targetPtr.Store(&plainUDPTarget{addr: addr})
}

func (p *PlainUDPProxy) isClientIdleExpired(clientInfo *plainUDPClient, now time.Time) bool {
	timeout := time.Duration(p.idleTimeout.Load())
	if clientInfo == nil || timeout < 0 {
		return false
	}
	if timeout == 0 {
		timeout = defaultPlainIdle
	}
	return now.Sub(time.Unix(0, clientInfo.lastSeen.Load())) > timeout
}

func (p *PlainUDPProxy) updateIdleTimeout() {
	if p.conf() != nil {
		if p.conf().IdleTimeout == -1 {
			p.idleTimeout.Store(-1)
			return
		}
		if p.conf().IdleTimeout > 0 {
			p.idleTimeout.Store(int64(time.Duration(p.conf().IdleTimeout) * time.Second))
			return
		}
	}
	p.idleTimeout.Store(int64(defaultPlainIdle))
}
