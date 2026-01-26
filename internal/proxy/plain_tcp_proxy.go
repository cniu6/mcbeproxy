package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

const (
	plainTCPDialTimeout = 10 * time.Second
)

type PlainTCPProxy struct {
	serverID    string
	config      *config.ServerConfig
	outboundMgr OutboundManager
	listener    net.Listener
	closed      atomic.Bool
	wg          sync.WaitGroup
	dialerPool  *proxyPortDialerPool
	conns       sync.Map
}

func NewPlainTCPProxy(serverID string, cfg *config.ServerConfig) *PlainTCPProxy {
	return &PlainTCPProxy{
		serverID:   serverID,
		config:     cfg,
		dialerPool: newProxyPortDialerPool(),
	}
}

func (p *PlainTCPProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

func (p *PlainTCPProxy) UpdateConfig(cfg *config.ServerConfig) {
	p.config = cfg
}

func (p *PlainTCPProxy) Start() error {
	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = ln
	p.closed.Store(false)
	return nil
}

func (p *PlainTCPProxy) Listen(ctx context.Context) error {
	if p.listener == nil {
		return fmt.Errorf("listener not started")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := p.listener.Accept()
		if err != nil {
			if p.closed.Load() {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			p.handleConn(ctx, c)
		}(conn)
	}
}

func (p *PlainTCPProxy) Stop() error {
	p.closed.Store(true)
	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.conns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			_ = conn.Close()
		}
		p.conns.Delete(key)
		return true
	})
	p.wg.Wait()
	if p.dialerPool != nil {
		p.dialerPool.CloseAll()
	}
	return nil
}

func (p *PlainTCPProxy) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()
	p.conns.Store(client, client)
	defer p.conns.Delete(client)

	dialCtx, cancel := context.WithTimeout(ctx, plainTCPDialTimeout)
	defer cancel()

	remote, _, err := p.dialOutbound(dialCtx, p.config.GetTargetAddr())
	if err != nil {
		logger.Debug("PlainTCPProxy: dial failed for %s: %v", p.serverID, err)
		return
	}
	defer remote.Close()

	go func() {
		_, _ = io.Copy(remote, client)
		_ = remote.Close()
	}()
	_, _ = io.Copy(client, remote)
}

func (p *PlainTCPProxy) dialOutbound(ctx context.Context, address string) (net.Conn, string, error) {
	if p.config == nil || p.outboundMgr == nil || p.config.IsDirectConnection() {
		dialer := &net.Dialer{Timeout: plainTCPDialTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		return conn, "direct", err
	}

	exclude := make([]string, 0, 4)
	attempts := 3
	if p.config.IsMultiNodeSelection() {
		nodes := p.config.GetNodeList()
		if len(nodes) > 0 {
			attempts = len(nodes)
		}
	}

	for i := 0; i < attempts; i++ {
		selected, err := p.outboundMgr.SelectOutboundWithFailover(p.config.ProxyOutbound, p.config.GetLoadBalance(), p.config.GetLoadBalanceSort(), exclude)
		if err != nil {
			return nil, "", err
		}
		dialer, err := p.dialerPool.Get(selected)
		if err != nil {
			exclude = append(exclude, selected.Name)
			continue
		}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			exclude = append(exclude, selected.Name)
			continue
		}
		return conn, selected.Name, nil
	}
	return nil, "", fmt.Errorf("all proxy outbounds failed")
}
