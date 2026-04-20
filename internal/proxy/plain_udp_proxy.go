package proxy

import (
	"context"
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
)

type plainUDPClient struct {
	clientAddr *net.UDPAddr
	targetConn net.PacketConn
	targetAddr net.Addr
	lastSeen   atomic.Int64
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

		clientInfo, _ := p.getOrCreateClient(ctx, clientAddr)
		if clientInfo == nil {
			p.bufferPool.Put(buf)
			continue
		}

		clientInfo.lastSeen.Store(time.Now().UnixNano())
		clientInfo.targetConn.SetWriteDeadline(time.Now().Add(plainUDPWriteTimeout))
		_, err = writePacketConn(clientInfo.targetConn, (*buf)[:n], clientInfo.targetAddr)
		p.bufferPool.Put(buf)
		if err != nil && !isTimeoutError(err) {
			logger.Debug("PlainUDPProxy: write to target failed for %s: %v", clientAddr.String(), err)
			p.removeClientIfMatch(clientAddr.String(), clientInfo)
		}
	}
}

func (p *PlainUDPProxy) Stop() error {
	p.closed.Store(true)
	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.clients.Range(func(key, value interface{}) bool {
		if client, ok := value.(*plainUDPClient); ok {
			_ = client.targetConn.Close()
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

func (p *PlainUDPProxy) getOrCreateClient(ctx context.Context, clientAddr *net.UDPAddr) (*plainUDPClient, bool) {
	clientKey := clientAddr.String()
	if val, ok := p.clients.Load(clientKey); ok {
		return val.(*plainUDPClient), false
	}

	targetConn, targetAddr, err := p.dialTargetConn(ctx)
	if err != nil {
		logger.Error("PlainUDPProxy: failed to dial target %s: %v", p.config.GetTargetAddr(), err)
		return nil, false
	}

	client := &plainUDPClient{
		clientAddr: clientAddr,
		targetConn: targetConn,
		targetAddr: targetAddr,
	}
	client.lastSeen.Store(time.Now().UnixNano())

	p.clients.Store(clientKey, client)

	p.wg.Add(1)
	go p.forwardResponses(ctx, clientKey, client)

	return client, true
}

func (p *PlainUDPProxy) dialTargetConn(ctx context.Context) (net.PacketConn, net.Addr, error) {
	if p.targetAddr == nil {
		return nil, nil, fmt.Errorf("target address not resolved")
	}
	if p.config == nil || p.outboundMgr == nil || p.config.IsDirectConnection() {
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

func (p *PlainUDPProxy) forwardResponses(ctx context.Context, clientKey string, clientInfo *plainUDPClient) {
	defer p.wg.Done()
	defer p.removeClientIfMatch(clientKey, clientInfo)

	bufPtr := p.bufferPool.Get()
	buffer := *bufPtr
	defer p.bufferPool.Put(bufPtr)

	for {
		select {
		case <-ctx.Done():
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
				if !strings.Contains(err.Error(), "use of closed") {
					logger.Debug("PlainUDPProxy: read from target failed for %s: %v", clientInfo.clientAddr.String(), err)
				}
				return
			}
			lastSeen := time.Unix(0, clientInfo.lastSeen.Load())
			if time.Since(lastSeen) > p.idleTimeout {
				return
			}
			continue
		}

		clientInfo.lastSeen.Store(time.Now().UnixNano())
		p.listener.SetWriteDeadline(time.Now().Add(plainUDPWriteTimeout))
		_, err = p.listener.WriteToUDP(buffer[:n], clientInfo.clientAddr)
		if err != nil && !isTimeoutError(err) {
			if !strings.Contains(err.Error(), "use of closed") {
				logger.Debug("PlainUDPProxy: write to client failed for %s: %v", clientInfo.clientAddr.String(), err)
			}
			return
		}
	}
}

func (p *PlainUDPProxy) removeClient(clientKey string) {
	p.removeClientIfMatch(clientKey, nil)
}

func (p *PlainUDPProxy) removeClientIfMatch(clientKey string, expected *plainUDPClient) {
	if expected != nil {
		if !p.clients.CompareAndDelete(clientKey, expected) {
			return
		}
		_ = expected.targetConn.Close()
		return
	}
	if val, ok := p.clients.LoadAndDelete(clientKey); ok {
		client := val.(*plainUDPClient)
		_ = client.targetConn.Close()
	}
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
	shouldPreserveHostname := p.config != nil && p.outboundMgr != nil && !p.config.IsDirectConnection()
	addr, _, err := buildUDPDestinationAddr(context.Background(), p.config.GetTargetAddr(), shouldPreserveHostname)
	if err != nil {
		logger.Warn("PlainUDPProxy: failed to resolve target %s: %v", p.config.GetTargetAddr(), err)
		return
	}
	p.targetAddr = addr
}

func (p *PlainUDPProxy) updateIdleTimeout() {
	if p.config != nil && p.config.IdleTimeout > 0 {
		p.idleTimeout = time.Duration(p.config.IdleTimeout) * time.Second
		return
	}
	p.idleTimeout = defaultPlainIdle
}
