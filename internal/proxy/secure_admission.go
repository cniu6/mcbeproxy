package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	mt "github.com/metacubex/tls"
)

// 每入口使用固定大小的准入状态，不记录来源地址表，防止失败请求耗尽内存。
// 限速按新传输连接计，不影响已认证玩家的逐包流量。
type secureAdmission struct {
	mu      sync.Mutex
	maximum int
	timeout time.Duration
	pending int
	tokens  float64
	updated time.Time
	closed  bool
	raw     map[*secureAdmissionConn]struct{}
}

func newSecureAdmission(maximum int, timeout time.Duration) *secureAdmission {
	return &secureAdmission{maximum: maximum, timeout: timeout, tokens: 32, updated: time.Now(), raw: make(map[*secureAdmissionConn]struct{})}
}
func (g *secureAdmission) takeLocked() bool {
	now := time.Now()
	g.tokens += now.Sub(g.updated).Seconds() * 16
	if g.tokens > 32 {
		g.tokens = 32
	}
	g.updated = now
	if g.closed || g.tokens < 1 {
		return false
	}
	g.tokens--
	return true
}
func (g *secureAdmission) tlsConfig(hello *mt.ClientHelloInfo) (*mt.Config, error) {
	g.mu.Lock()
	if g.pending >= g.maximum || !g.takeLocked() {
		g.mu.Unlock()
		return nil, errors.New("入口握手过于频繁或并发已满")
	}
	g.pending++
	g.mu.Unlock()
	context.AfterFunc(hello.Context(), func() { g.mu.Lock(); g.pending--; g.mu.Unlock() })
	return nil, nil
}
func (g *secureAdmission) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &secureAdmissionListener{Listener: l, gate: g}, nil
}
func (g *secureAdmission) Close() {
	g.mu.Lock()
	g.closed = true
	all := make([]*secureAdmissionConn, 0, len(g.raw))
	for c := range g.raw {
		all = append(all, c)
	}
	g.mu.Unlock()
	for _, c := range all {
		c.Close()
	}
}

type secureAdmissionListener struct {
	net.Listener
	gate *secureAdmission
}

func (l *secureAdmissionListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		g := l.gate
		g.mu.Lock()
		if len(g.raw) >= g.maximum || !g.takeLocked() {
			g.mu.Unlock()
			raw.Close()
			continue
		}
		c := &secureAdmissionConn{Conn: raw, gate: g}
		g.raw[c] = struct{}{}
		c.timer = time.AfterFunc(g.timeout, func() { c.Close() })
		g.mu.Unlock()
		return c, nil
	}
}

type secureAdmissionConn struct {
	net.Conn
	gate  *secureAdmission
	timer *time.Timer
	once  sync.Once
}

// Mieru 服务端首次返回加密响应时认证已完成；之前的硬超时不能被库的长读期限覆盖。
func (c *secureAdmissionConn) Write(b []byte) (int, error) { c.timer.Stop(); return c.Conn.Write(b) }
func (c *secureAdmissionConn) Close() error {
	var err error
	c.once.Do(func() {
		c.timer.Stop()
		c.gate.mu.Lock()
		delete(c.gate.raw, c)
		c.gate.mu.Unlock()
		err = c.Conn.Close()
	})
	return err
}
