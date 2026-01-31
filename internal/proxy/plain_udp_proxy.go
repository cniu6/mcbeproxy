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
	targetAddr  *net.UDPAddr
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
	p.listener = conn
	p.closed.Store(false)
	p.refreshTargetAddr()
	p.updateIdleTimeout()

	bufferSize := p.config.BufferSize
	if bufferSize <= 0 || bufferSize > MaxBufferSize {
		bufferSize = MaxBufferSize
	}
	p.bufferPool = NewBufferPool(bufferSize)

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
		p.listener.SetWriteDeadline(time.Now().Add(plainUDPWriteTimeout))
		clientInfo.targetConn.SetWriteDeadline(time.Now().Add(plainUDPWriteTimeout))
		_, err = clientInfo.targetConn.WriteTo((*buf)[:n], clientInfo.targetAddr)
		p.bufferPool.Put(buf)
		if err != nil && !isTimeoutError(err) {
			logger.Debug("PlainUDPProxy: write to target failed for %s: %v", clientAddr.String(), err)
			p.removeClient(clientAddr.String())
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
		conn, err := net.DialUDP("udp", nil, p.targetAddr)
		if err != nil {
			return nil, nil, err
		}
		return conn, p.targetAddr, nil
	}

	proxyOutbound := p.config.GetProxyOutbound()
	if p.config.IsGroupSelection() || p.config.IsMultiNodeSelection() {
		strategy := p.config.GetLoadBalance()
		sortBy := p.config.GetLoadBalanceSort()
		selected, err := p.outboundMgr.SelectOutboundWithFailoverForServer(p.serverID, proxyOutbound, strategy, sortBy, nil)
		if err != nil {
			return nil, nil, err
		}
		conn, err := p.outboundMgr.DialPacketConn(ctx, selected.Name, p.config.GetTargetAddr())
		if err != nil {
			return nil, nil, err
		}
		return conn, p.targetAddr, nil
	}

	conn, err := p.outboundMgr.DialPacketConn(ctx, proxyOutbound, p.config.GetTargetAddr())
	if err != nil {
		return nil, nil, err
	}
	return conn, p.targetAddr, nil
}

func (p *PlainUDPProxy) forwardResponses(ctx context.Context, clientKey string, clientInfo *plainUDPClient) {
	defer p.wg.Done()
	defer p.removeClient(clientKey)

	buffer := make([]byte, MaxBufferSize)

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
	if val, ok := p.clients.Load(clientKey); ok {
		client := val.(*plainUDPClient)
		_ = client.targetConn.Close()
		p.clients.Delete(clientKey)
	}
}

func (p *PlainUDPProxy) refreshTargetAddr() {
	addr, err := net.ResolveUDPAddr("udp", p.config.GetTargetAddr())
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
