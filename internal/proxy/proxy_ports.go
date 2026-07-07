// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/singboxcore"
)

const (
	defaultProxyDialTimeout        = 10 * time.Second
	defaultProxyHandshakeTimeout   = 15 * time.Second
	proxyPortStopWaitTimeout       = 5 * time.Second
	maxSocks4FieldLength           = 4096
	sharedUDPRelayQueueSize        = 256
	sharedUDPRelayMaxWriteFailures = 3
	sharedUDPRelayDropLogEvery       = int64(1024)
	sharedUDPRelayMaxResponseHeader = 262 // RSV + FRAG + ATYP + 255-byte domain + port
	sharedUDPRelayMaxDatagramSize  = 65535
)

// ProxyPortManager manages local proxy port listeners.
type ProxyPortManager struct {
	configMgr      *config.ProxyPortConfigManager
	outboundMgr    OutboundManager
	singboxFactory singboxcore.Factory
	mu             sync.Mutex
	listeners      map[string]*proxyPortListener
	dialerPool     *proxyPortDialerPool
}

func NewProxyPortManager(configMgr *config.ProxyPortConfigManager, outboundMgr OutboundManager) *ProxyPortManager {
	return NewProxyPortManagerWithSingboxFactory(configMgr, outboundMgr, nil)
}

func NewProxyPortManagerWithSingboxFactory(configMgr *config.ProxyPortConfigManager, outboundMgr OutboundManager, factory singboxcore.Factory) *ProxyPortManager {
	if factory == nil {
		factory = NewSingboxCoreFactory()
	}
	// Wrap with ChainFactory so chain proxy outbounds work for TCP/HTTP proxy ports
	chainFactory := NewChainFactory(factory, outboundMgr)
	return &ProxyPortManager{
		configMgr:      configMgr,
		outboundMgr:    outboundMgr,
		singboxFactory: chainFactory,
		listeners:      make(map[string]*proxyPortListener),
		dialerPool:     newProxyPortDialerPool(chainFactory),
	}
}

// Start starts all enabled proxy port listeners when feature is enabled.
func (m *ProxyPortManager) Start(enabled bool) error {
	if !enabled || m.configMgr == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	ports := m.configMgr.GetAllPorts()
	for _, cfg := range ports {
		if cfg == nil || !cfg.Enabled {
			continue
		}
		if _, exists := m.listeners[cfg.ID]; exists {
			continue
		}
		listener := newProxyPortListener(cfg, m.outboundMgr, m.dialerPool)
		if err := listener.Start(); err != nil {
			logger.Error("ProxyPort: failed to start %s (%s): %v", cfg.ID, cfg.ListenAddr, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		m.listeners[cfg.ID] = listener
		logger.Info("ProxyPort: started %s (%s, %s)", cfg.ID, cfg.ListenAddr, cfg.Type)
	}

	return firstErr
}

// Stop stops all proxy port listeners and waits for active connections to finish.
func (m *ProxyPortManager) Stop() {
	m.stopListeners(true, true)
}

// Reload reconciles proxy port listeners with the latest config. Unchanged
// listeners are kept alive so active TCP clients and SOCKS5 UDP relays are not
// interrupted by unrelated proxy-port CRUD/file-watcher reloads.
func (m *ProxyPortManager) Reload(enabled bool) error {
	if !enabled || m.configMgr == nil {
		m.stopListeners(false, false)
		return nil
	}

	ports := m.configMgr.GetAllPorts()
	desired := make(map[string]*config.ProxyPortConfig, len(ports))
	for _, cfg := range ports {
		if cfg == nil || !cfg.Enabled {
			continue
		}
		desired[cfg.ID] = cfg.Clone()
	}

	m.mu.Lock()
	for id, listener := range m.listeners {
		cfg, ok := desired[id]
		if !ok || !proxyPortRuntimeConfigEqual(listener.cfg, cfg) {
			listener.StopWithWait(false)
			delete(m.listeners, id)
		}
	}
	m.mu.Unlock()

	return m.Start(enabled)
}

func proxyPortRuntimeConfigEqual(a, b *config.ProxyPortConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	ac := a.Clone()
	bc := b.Clone()
	ac.ApplyDefaults()
	bc.ApplyDefaults()
	return ac.ID == bc.ID &&
		ac.ListenAddr == bc.ListenAddr &&
		ac.Type == bc.Type &&
		ac.Enabled == bc.Enabled &&
		ac.Username == bc.Username &&
		ac.Password == bc.Password &&
		ac.ProxyOutbound == bc.ProxyOutbound &&
		ac.LoadBalance == bc.LoadBalance &&
		ac.LoadBalanceSort == bc.LoadBalanceSort &&
		reflect.DeepEqual(ac.AllowList, bc.AllowList)
}

func (m *ProxyPortManager) stopListeners(wait bool, closeDialers bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, listener := range m.listeners {
		listener.StopWithWait(wait)
		delete(m.listeners, id)
	}
	if closeDialers {
		m.dialerPool.CloseAll()
	}
}

func (m *ProxyPortManager) GetActiveConnectionCount() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	total := 0
	for _, listener := range m.listeners {
		total += listener.ActiveConnections()
	}
	return total
}

func (m *ProxyPortManager) GetActiveConnectionCountForPort(id string) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, ok := m.listeners[id]
	if !ok || listener == nil {
		return 0
	}
	return listener.ActiveConnections()
}

type proxyPortDialerPool struct {
	mu      sync.Mutex
	factory singboxcore.Factory
	dialers map[string]singboxcore.Dialer
}

func newProxyPortDialerPool(factory singboxcore.Factory) *proxyPortDialerPool {
	if factory == nil {
		factory = NewSingboxCoreFactory()
	}
	return &proxyPortDialerPool{
		factory: factory,
		dialers: make(map[string]singboxcore.Dialer),
	}
}

func (p *proxyPortDialerPool) Get(cfg *config.ProxyOutbound) (singboxcore.Dialer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("outbound config is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	cacheKey := proxyOutboundDialerCacheKey(cfg)
	if d, ok := p.dialers[cacheKey]; ok {
		return d, nil
	}
	dialer, err := p.factory.CreateDialer(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	p.dialers[cacheKey] = dialer
	return dialer, nil
}

func (p *proxyPortDialerPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, d := range p.dialers {
		_ = d.Close()
		delete(p.dialers, name)
	}
}

func proxyOutboundDialerCacheKey(cfg *config.ProxyOutbound) string {
	if cfg == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s|%s|%s|%d|%s|%s|%s|%d|%d|%s|%s|%d|%d|%d|%d|%s|%t|%s|%t|%s|%t|%s|%s|%s|%s|%s|%s|%s|%s",
		cfg.Name,
		cfg.Type,
		cfg.Server,
		cfg.Port,
		cfg.Username,
		cfg.Method,
		cfg.Password,
		cfg.UUID,
		cfg.Security,
		cfg.AlterID,
		cfg.Flow,
		cfg.Obfs,
		cfg.ObfsPassword,
		cfg.HopInterval,
		cfg.UpMbps,
		cfg.PortHopping,
		cfg.CertFingerprint,
		cfg.DownMbps,
		cfg.IdleSessionCheckInterval,
		cfg.IdleSessionTimeout,
		cfg.MinIdleSession,
		cfg.ALPN,
		cfg.TLS,
		cfg.SNI,
		cfg.Insecure,
		cfg.Fingerprint,
		cfg.Reality,
		cfg.RealityPublicKey,
		cfg.RealityShortID,
		cfg.Network,
		cfg.WSPath,
		cfg.WSHost,
		cfg.XHTTPMode,
		cfg.GRPCServiceName,
		cfg.GRPCAuthority,
	)
}

type proxyPortListener struct {
	cfg            *config.ProxyPortConfig
	outboundMgr    OutboundManager
	dialerPool     *proxyPortDialerPool
	listener       net.Listener
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	allowList      []*net.IPNet
	activeConns    atomic.Int64
	activeConnsMu  sync.Mutex
	activeNetConns map[net.Conn]struct{}
	sharedRelay    *sharedUDPRelay
	relayMu        sync.Mutex
}

func newProxyPortListener(cfg *config.ProxyPortConfig, outboundMgr OutboundManager, dialerPool *proxyPortDialerPool) *proxyPortListener {
	return &proxyPortListener{
		cfg:         cfg.Clone(),
		outboundMgr: outboundMgr,
		dialerPool:  dialerPool,
	}
}

func (l *proxyPortListener) ActiveConnections() int {
	if l == nil {
		return 0
	}
	return int(l.activeConns.Load())
}

func (l *proxyPortListener) Start() error {
	if err := l.cfg.Validate(); err != nil {
		return err
	}
	allowList, err := parseAllowList(l.cfg.AllowList)
	if err != nil {
		return err
	}
	l.allowList = allowList

	ln, err := net.Listen("tcp", l.cfg.ListenAddr)
	if err != nil {
		return err
	}
	l.listener = ln
	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.activeConnsMu.Lock()
	l.activeNetConns = make(map[net.Conn]struct{})
	l.activeConnsMu.Unlock()

	l.wg.Add(1)
	go l.acceptLoop()
	return nil
}

func (l *proxyPortListener) StopWithWait(wait bool) {
	if l.cancel != nil {
		l.cancel()
	}
	if l.listener != nil {
		_ = l.listener.Close()
	}
	l.closeActiveConns()
	l.relayMu.Lock()
	if l.sharedRelay != nil {
		l.sharedRelay.close()
		l.sharedRelay = nil
	}
	l.relayMu.Unlock()
	l.closeActiveConns()
	if wait {
		l.waitStopped(proxyPortStopWaitTimeout)
	}
}

func (l *proxyPortListener) trackConn(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	if l.ctx != nil && l.ctx.Err() != nil {
		_ = conn.Close()
		return false
	}
	l.activeConnsMu.Lock()
	if l.activeNetConns == nil {
		l.activeNetConns = make(map[net.Conn]struct{})
	}
	l.activeNetConns[conn] = struct{}{}
	l.activeConnsMu.Unlock()
	return true
}

func (l *proxyPortListener) untrackConn(conn net.Conn) {
	if conn == nil {
		return
	}
	l.activeConnsMu.Lock()
	delete(l.activeNetConns, conn)
	l.activeConnsMu.Unlock()
}

func (l *proxyPortListener) closeTrackedConn(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Close()
	l.untrackConn(conn)
}

func (l *proxyPortListener) closeActiveConns() {
	l.activeConnsMu.Lock()
	conns := make([]net.Conn, 0, len(l.activeNetConns))
	for conn := range l.activeNetConns {
		conns = append(conns, conn)
	}
	l.activeConnsMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (l *proxyPortListener) waitStopped(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(timeout):
		l.closeActiveConns()
		logger.Warn("ProxyPort: stop timed out after %s for %s; active connections may still be closing", timeout, l.cfg.ListenAddr)
	}
}

func (l *proxyPortListener) Stop() {
	l.StopWithWait(true)
}

func (l *proxyPortListener) acceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if l.ctx != nil && l.ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			logger.Debug("ProxyPort: accept error (%s): %v", l.cfg.ListenAddr, err)
			return
		}

		l.wg.Add(1)
		go func(c net.Conn) {
			defer l.wg.Done()
			if !l.trackConn(c) {
				return
			}
			defer l.untrackConn(c)
			l.activeConns.Add(1)
			defer l.activeConns.Add(-1)
			setProxyHandshakeDeadline(c)
			l.handleConn(c)
		}(conn)
	}
}

func (l *proxyPortListener) handleConn(conn net.Conn) {
	defer conn.Close()

	if !l.isAllowed(conn.RemoteAddr()) {
		return
	}

	reader := bufio.NewReader(conn)
	switch l.cfg.Type {
	case config.ProxyPortTypeHTTP:
		l.handleHTTP(conn, reader)
	case config.ProxyPortTypeSocks5:
		l.handleSocks5(conn, reader)
	case config.ProxyPortTypeSocks4:
		l.handleSocks4(conn, reader)
	case config.ProxyPortTypeMixed:
		l.handleMixed(conn, reader)
	default:
		return
	}
}

func (l *proxyPortListener) handleMixed(conn net.Conn, reader *bufio.Reader) {
	peek, err := reader.Peek(1)
	if err != nil {
		return
	}
	switch peek[0] {
	case 0x05:
		l.handleSocks5(conn, reader)
		return
	case 0x04:
		l.handleSocks4(conn, reader)
		return
	}
	// Only check for SSH banner on non-SOCKS connections.
	// Doing Peek(4) before the SOCKS5 dispatch above would block when a
	// no-auth SOCKS5 client sends a 3-byte greeting (0x05, 0x01, 0x00),
	// causing a deadlock: the server waits for a 4th byte while the client
	// waits for the method-selection response.
	if banner, berr := reader.Peek(4); berr == nil && string(banner) == "SSH-" {
		logger.Warn("ProxyPort: received raw SSH banner on mixed proxy port %s (%s); use SOCKS5/HTTP CONNECT or a plain TCP forward instead", l.cfg.ID, l.cfg.ListenAddr)
		return
	}
	l.handleHTTP(conn, reader)
}

func (l *proxyPortListener) handleHTTP(conn net.Conn, reader *bufio.Reader) {
	for {
		setProxyHandshakeDeadline(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		clearProxyConnDeadline(conn)
		if l.requiresAuth() && !l.checkHTTPAuth(req) {
			writeHTTPAuthRequired(conn)
			return
		}

		if strings.EqualFold(req.Method, http.MethodConnect) {
			l.handleHTTPConnect(conn, reader, req)
			return
		}

		target := req.Host
		if target == "" && req.URL != nil {
			target = req.URL.Host
		}
		if target == "" {
			writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
			return
		}
		if !strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "80")
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultProxyDialTimeout)
		remote, _, err := l.dialOutbound(ctx, target)
		cancel()
		if err != nil {
			writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway")
			return
		}
		if !l.trackConn(remote) {
			writeHTTPError(conn, http.StatusServiceUnavailable, "Service Unavailable")
			return
		}

		req.RequestURI = ""
		if req.URL != nil {
			req.URL.Scheme = ""
			req.URL.Host = ""
		}
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")

		if err := req.Write(remote); err != nil {
			l.closeTrackedConn(remote)
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(remote), req)
		if err != nil {
			l.closeTrackedConn(remote)
			return
		}
		if err := func() error {
			defer resp.Body.Close()
			return resp.Write(conn)
		}(); err != nil {
			l.closeTrackedConn(remote)
			return
		}
		l.closeTrackedConn(remote)

		if req.Close || resp.Close {
			return
		}
	}
}

func (l *proxyPortListener) handleHTTPConnect(conn net.Conn, reader *bufio.Reader, req *http.Request) {
	target := req.Host
	if target == "" {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
		return
	}
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultProxyDialTimeout)
	remote, _, err := l.dialOutbound(ctx, target)
	cancel()
	if err != nil {
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway")
		return
	}
	if !l.trackConn(remote) {
		writeHTTPError(conn, http.StatusServiceUnavailable, "Service Unavailable")
		return
	}
	clearProxyConnDeadline(conn)

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	defer l.closeTrackedConn(remote)
	relayStream(conn, reader, remote)
}

func (l *proxyPortListener) handleSocks5(conn net.Conn, reader *bufio.Reader) {
	if err := l.handleSocks5Handshake(conn, reader); err != nil {
		return
	}
	cmd, target, err := readSocks5RequestEx(reader)
	if err != nil {
		writeSocks5Reply(conn, 0x01)
		return
	}

	switch cmd {
	case 0x01: // CONNECT
		ctx, cancel := context.WithTimeout(context.Background(), defaultProxyDialTimeout)
		remote, _, err := l.dialOutbound(ctx, target)
		cancel()
		if err != nil {
			writeSocks5Reply(conn, 0x05)
			return
		}
		if !l.trackConn(remote) {
			writeSocks5Reply(conn, 0x01)
			return
		}
		clearProxyConnDeadline(conn)
		writeSocks5Reply(conn, 0x00)
		defer l.closeTrackedConn(remote)
		relayStream(conn, reader, remote)
	case 0x03: // UDP ASSOCIATE
		l.handleSocks5UDPAssociate(conn)
	default:
		writeSocks5Reply(conn, 0x07) // Command not supported
	}
}

func (l *proxyPortListener) handleSocks5Handshake(conn net.Conn, reader *bufio.Reader) error {
	ver, err := reader.ReadByte()
	if err != nil || ver != 0x05 {
		return fmt.Errorf("invalid socks5 version")
	}
	nMethods, err := reader.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, int(nMethods))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}

	authRequired := l.requiresAuth()
	chosen := byte(0x00)
	if authRequired {
		chosen = 0x02
	}

	if authRequired && !containsByte(methods, 0x02) {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return fmt.Errorf("no acceptable auth method")
	}
	if !authRequired && !containsByte(methods, 0x00) {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return fmt.Errorf("no acceptable auth method")
	}

	if _, err := conn.Write([]byte{0x05, chosen}); err != nil {
		return err
	}
	if chosen == 0x02 {
		if err := l.handleSocks5Auth(conn, reader); err != nil {
			return err
		}
	}
	return nil
}

func (l *proxyPortListener) handleSocks5Auth(conn net.Conn, reader *bufio.Reader) error {
	ver, err := reader.ReadByte()
	if err != nil || ver != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid auth version")
	}
	ulen, err := reader.ReadByte()
	if err != nil {
		return err
	}
	uname := make([]byte, int(ulen))
	if _, err := io.ReadFull(reader, uname); err != nil {
		return err
	}
	plen, err := reader.ReadByte()
	if err != nil {
		return err
	}
	pass := make([]byte, int(plen))
	if _, err := io.ReadFull(reader, pass); err != nil {
		return err
	}

	if !secureStringEqual(string(uname), l.cfg.Username) || !secureStringEqual(string(pass), l.cfg.Password) {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("auth failed")
	}
	_, _ = conn.Write([]byte{0x01, 0x00})
	return nil
}

// readSocks5RequestEx reads a SOCKS5 request and returns the command byte
// (0x01=CONNECT, 0x03=UDP ASSOCIATE) and the target address string.
func readSocks5RequestEx(reader *bufio.Reader) (byte, string, error) {
	ver, err := reader.ReadByte()
	if err != nil || ver != 0x05 {
		return 0, "", fmt.Errorf("invalid request version")
	}
	cmd, err := reader.ReadByte()
	if err != nil {
		return 0, "", err
	}
	if cmd != 0x01 && cmd != 0x03 {
		return cmd, "", fmt.Errorf("unsupported command %d", cmd)
	}
	_, _ = reader.ReadByte() // RSV
	atyp, err := reader.ReadByte()
	if err != nil {
		return cmd, "", err
	}

	host := ""
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return cmd, "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		l, err := reader.ReadByte()
		if err != nil {
			return cmd, "", err
		}
		buf := make([]byte, int(l))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return cmd, "", err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return cmd, "", err
		}
		host = net.IP(buf).String()
	default:
		return cmd, "", fmt.Errorf("invalid atyp")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return cmd, "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return cmd, net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// readSocks5Request reads a SOCKS5 CONNECT request and returns the target address.
// Kept for backward compatibility.
func readSocks5Request(reader *bufio.Reader) (string, error) {
	_, target, err := readSocks5RequestEx(reader)
	return target, err
}

func writeSocks5Reply(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (l *proxyPortListener) handleSocks4(conn net.Conn, reader *bufio.Reader) {
	ver, err := reader.ReadByte()
	if err != nil || ver != 0x04 {
		return
	}
	cmd, err := reader.ReadByte()
	if err != nil || cmd != 0x01 {
		writeSocks4Reply(conn, 0x5B, nil, 0)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return
	}
	ipBuf := make([]byte, 4)
	if _, err := io.ReadFull(reader, ipBuf); err != nil {
		return
	}
	if _, err := readUntilNull(reader, maxSocks4FieldLength); err != nil {
		writeSocks4Reply(conn, 0x5B, nil, 0)
		return
	}

	destIP := net.IP(ipBuf)
	host := destIP.String()
	if ipBuf[0] == 0 && ipBuf[1] == 0 && ipBuf[2] == 0 && ipBuf[3] != 0 {
		domain, err := readUntilNull(reader, maxSocks4FieldLength)
		if err != nil {
			writeSocks4Reply(conn, 0x5B, destIP, 0)
			return
		}
		if domain != "" {
			host = domain
		}
	}

	port := int(portBuf[0])<<8 | int(portBuf[1])
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	ctx, cancel := context.WithTimeout(context.Background(), defaultProxyDialTimeout)
	remote, _, err := l.dialOutbound(ctx, target)
	cancel()
	if err != nil {
		writeSocks4Reply(conn, 0x5B, destIP, port)
		return
	}
	if !l.trackConn(remote) {
		writeSocks4Reply(conn, 0x5B, destIP, port)
		return
	}
	clearProxyConnDeadline(conn)

	writeSocks4Reply(conn, 0x5A, destIP, port)
	defer l.closeTrackedConn(remote)
	relayStream(conn, reader, remote)
}

func writeSocks4Reply(conn net.Conn, status byte, ip net.IP, port int) {
	reply := make([]byte, 8)
	reply[0] = 0x00
	reply[1] = status
	reply[2] = byte(port >> 8)
	reply[3] = byte(port & 0xff)
	if ip4 := ip.To4(); ip4 != nil {
		copy(reply[4:], ip4)
	}
	_, _ = conn.Write(reply)
}

func readUntilNull(reader *bufio.Reader, maxLen int) (string, error) {
	if maxLen <= 0 {
		maxLen = maxSocks4FieldLength
	}
	var buf []byte
	for {
		if len(buf) >= maxLen {
			return "", fmt.Errorf("field too long")
		}
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0x00 {
			return string(buf), nil
		}
		buf = append(buf, b)
	}
}

func setProxyHandshakeDeadline(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(defaultProxyHandshakeTimeout))
}

func clearProxyConnDeadline(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
}

func (l *proxyPortListener) dialOutbound(ctx context.Context, address string) (net.Conn, string, error) {
	if l.cfg == nil {
		return nil, "", fmt.Errorf("proxy port configuration is nil")
	}
	if l.cfg.IsDirectConnection() {
		dialer := &net.Dialer{Timeout: defaultProxyDialTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		return conn, DirectNodeName, err
	}
	if l.outboundMgr == nil {
		return nil, "", fmt.Errorf("proxy outbound manager unavailable for proxy port %s", l.cfg.ID)
	}

	exclude := make([]string, 0, 4)
	attempts := proxySelectionAttemptLimit(l.cfg, l.outboundMgr)

	for i := 0; i < attempts; i++ {
		selected, err := l.outboundMgr.SelectOutboundWithFailoverForServer(proxyPortSelectorID(l.cfg.ID), l.cfg.ProxyOutbound, l.cfg.GetLoadBalance(), l.cfg.GetLoadBalanceSort(), exclude)
		if err != nil {
			return nil, "", err
		}
		// "direct" token within a multi-node list: do a plain TCP dial
		// instead of going through the outbound manager's dialer pool.
		// Failover still applies if the direct dial itself fails.
		if IsDirectSelection(selected) {
			dialer := &net.Dialer{Timeout: defaultProxyDialTimeout}
			conn, derr := dialer.DialContext(ctx, "tcp", address)
			if derr == nil {
				return conn, DirectNodeName, nil
			}
			exclude = append(exclude, DirectNodeName)
			continue
		}
		dialer, err := l.dialerPool.Get(selected)
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

func (l *proxyPortListener) isAllowed(addr net.Addr) bool {
	if len(l.allowList) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, netw := range l.allowList {
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

func parseAllowList(entries []string) ([]*net.IPNet, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	result := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid allow_list CIDR: %s", entry)
			}
			result = append(result, ipnet)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid allow_list IP: %s", entry)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		mask := net.CIDRMask(bits, bits)
		result = append(result, &net.IPNet{IP: ip, Mask: mask})
	}
	return result, nil
}

func (l *proxyPortListener) requiresAuth() bool {
	return l.cfg.Username != "" || l.cfg.Password != ""
}

func (l *proxyPortListener) checkHTTPAuth(req *http.Request) bool {
	header := req.Header.Get("Proxy-Authorization")
	if header == "" {
		return false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	pair := string(raw)
	idx := strings.Index(pair, ":")
	if idx < 0 {
		return false
	}
	user := pair[:idx]
	pass := pair[idx+1:]
	return secureStringEqual(user, l.cfg.Username) && secureStringEqual(pass, l.cfg.Password)
}

func writeHTTPAuthRequired(conn net.Conn) {
	_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
}

func writeHTTPError(conn net.Conn, code int, msg string) {
	_, _ = conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", code, msg)))
}

func containsByte(list []byte, v byte) bool {
	for _, b := range list {
		if b == v {
			return true
		}
	}
	return false
}

// sharedUDPRelay manages a single shared UDP relay socket for all SOCKS5 UDP
// ASSOCIATE clients on the same proxy port. This avoids 'bind: address already
// in use' when multiple concurrent clients try to use the same port, and
// ensures the firewall only needs to open one UDP port (the same as TCP).
//
// Each client is identified by its UDP source address. Datagrams from
// different clients are dispatched to their respective upstream connections.
// Stale upstreams are cleaned up by an idle timeout.
type sharedUDPRelay struct {
	conn        *net.UDPConn
	mu          sync.Mutex
	clients     map[string]*udpClientEntry // clientAddr.String() -> entry
	activeIPsMu sync.Mutex
	activeIPs   map[string]int // net.IP.String() -> reference count of active TCP control conns
	wg          sync.WaitGroup
	stopCh      chan struct{}
	closeOnce   sync.Once
	cfgID       string
}

// udpClientEntry holds per-client upstream connections.
type udpClientEntry struct {
	upstreams map[string]*upstreamConn // destAddr -> upstream
	mu        sync.Mutex
}

type udpRelayPacket struct {
	payload []byte
	dest    net.Addr
}

type udpRelayEnqueueResult struct {
	queued        bool
	droppedOldest bool
	dropCount     int64
	queueDepth    int
}

type sharedUDPUpstreamStats struct {
	EnqueuedPackets int64
	DroppedPackets  int64
	WritePackets    int64
	WriteErrors     int64
	QueueDepth      int
}

// upstreamConn represents a single upstream UDP connection for a destination.
type upstreamConn struct {
	mu       sync.Mutex
	pc       net.PacketConn
	lastSeen time.Time
	queue    chan udpRelayPacket
	done     chan struct{}
	once     sync.Once

	enqueuedPackets atomic.Int64
	droppedPackets  atomic.Int64
	writePackets    atomic.Int64
	writeErrors     atomic.Int64
}

func newUpstreamConn() *upstreamConn {
	return &upstreamConn{
		lastSeen: time.Now(),
		queue:    make(chan udpRelayPacket, sharedUDPRelayQueueSize),
		done:     make(chan struct{}),
	}
}

func (uc *upstreamConn) enqueue(packet udpRelayPacket) udpRelayEnqueueResult {
	select {
	case <-uc.done:
		return udpRelayEnqueueResult{}
	default:
	}
	select {
	case uc.queue <- packet:
		uc.enqueuedPackets.Add(1)
		return udpRelayEnqueueResult{queued: true, queueDepth: len(uc.queue)}
	default:
		// Keep the newest realtime game packet instead of letting backlog inflate latency.
		select {
		case <-uc.queue:
		default:
		}
		dropCount := uc.droppedPackets.Add(1)
		select {
		case uc.queue <- packet:
			uc.enqueuedPackets.Add(1)
			return udpRelayEnqueueResult{queued: true, droppedOldest: true, dropCount: dropCount, queueDepth: len(uc.queue)}
		case <-uc.done:
			return udpRelayEnqueueResult{droppedOldest: true, dropCount: dropCount, queueDepth: len(uc.queue)}
		default:
			return udpRelayEnqueueResult{droppedOldest: true, dropCount: dropCount, queueDepth: len(uc.queue)}
		}
	}
}

func (uc *upstreamConn) stats() sharedUDPUpstreamStats {
	queueDepth := 0
	if uc.queue != nil {
		queueDepth = len(uc.queue)
	}
	return sharedUDPUpstreamStats{
		EnqueuedPackets: uc.enqueuedPackets.Load(),
		DroppedPackets:  uc.droppedPackets.Load(),
		WritePackets:    uc.writePackets.Load(),
		WriteErrors:     uc.writeErrors.Load(),
		QueueDepth:      queueDepth,
	}
}

func (uc *upstreamConn) close() {
	uc.once.Do(func() {
		if uc.done != nil {
			close(uc.done)
		}
		uc.mu.Lock()
		pc := uc.pc
		uc.mu.Unlock()
		if pc != nil {
			_ = pc.SetReadDeadline(time.Now())
			_ = pc.Close()
		}
	})
}

// getOrCreateSharedUDPRelay lazily creates the shared UDP relay socket bound
// to the same port as the TCP listener (firewall-friendly), falling back to a
// random port if the port is busy.
func (l *proxyPortListener) getOrCreateSharedUDPRelay() (*sharedUDPRelay, error) {
	l.relayMu.Lock()
	defer l.relayMu.Unlock()
	if l.sharedRelay != nil {
		return l.sharedRelay, nil
	}

	relayAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if l.listener != nil {
		if _, portStr, err := net.SplitHostPort(l.listener.Addr().String()); err == nil {
			if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
				relayAddr.Port = port
			}
		}
	}

	conn, err := net.ListenUDP("udp", relayAddr)
	if err != nil && relayAddr.Port > 0 {
		logger.Warn("SOCKS5 UDP: failed to bind relay to TCP port %d, using random port: %v (proxy_port=%s)",
			relayAddr.Port, err, l.cfg.ID)
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err != nil {
		return nil, err
	}

	_ = conn.SetReadBuffer(2 * 1024 * 1024)
	_ = conn.SetWriteBuffer(2 * 1024 * 1024)

	r := &sharedUDPRelay{
		conn:      conn,
		clients:   make(map[string]*udpClientEntry),
		activeIPs: make(map[string]int),
		stopCh:    make(chan struct{}),
		cfgID:     l.cfg.ID,
	}

	r.wg.Add(1)
	go r.readLoop(l)

	l.sharedRelay = r
	return r, nil
}

// registerClientIP marks a TCP control connection's remote IP as active,
// allowing UDP datagrams from that IP to be accepted by the shared relay.
func (r *sharedUDPRelay) registerClientIP(ip net.IP) {
	r.activeIPsMu.Lock()
	r.activeIPs[ip.String()]++
	r.activeIPsMu.Unlock()
}

// unregisterClientIP decrements the reference count for a TCP control
// connection's remote IP. When the count reaches zero (no more active TCP
// control connections from that IP), the IP is removed from the active set.
//
// Upstream connections are NOT closed here. Previously, this function closed
// all upstreams matching the IP, but that caused a race condition: when a
// client rapidly reconnected (e.g. after cache eviction), the old connection's
// cleanup would close the new connection's upstreams. Stale upstreams are now
// cleaned up by the idle sweeper (30s ticker, 2min timeout) instead.
func (r *sharedUDPRelay) unregisterClientIP(ip net.IP) {
	r.activeIPsMu.Lock()
	r.activeIPs[ip.String()]--
	if r.activeIPs[ip.String()] <= 0 {
		delete(r.activeIPs, ip.String())
	}
	r.activeIPsMu.Unlock()
}

// isClientIPActive checks whether a UDP datagram from the given IP should be
// accepted (i.e., there is an active TCP control connection from that IP).
func (r *sharedUDPRelay) isClientIPActive(ip net.IP) bool {
	r.activeIPsMu.Lock()
	_, ok := r.activeIPs[ip.String()]
	r.activeIPsMu.Unlock()
	return ok
}

// hasRecentActivity checks whether any upstream connection from the given
// client IP has received UDP traffic within the given duration. This is
// used to keep TCP control connections alive as long as the client is
// actively sending UDP keepalives or game traffic, even if no TCP-level
// data is ever sent.
func (r *sharedUDPRelay) hasRecentActivity(ip net.IP, maxIdle time.Duration) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for clientKey, entry := range r.clients {
		if !sameClientIP(clientKey, ip) {
			continue
		}
		entry.mu.Lock()
		for _, uc := range entry.upstreams {
			if now.Sub(uc.lastSeen) < maxIdle {
				entry.mu.Unlock()
				return true
			}
		}
		entry.mu.Unlock()
	}
	return false
}

func sameClientIP(clientKey string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	host, _, err := net.SplitHostPort(clientKey)
	if err == nil {
		parsed := net.ParseIP(host)
		return parsed != nil && parsed.Equal(ip)
	}
	return strings.HasPrefix(clientKey, ip.String()+":")
}

func socks5UDPResponseAddr(destAddr string) net.Addr {
	host, portStr, err := net.SplitHostPort(destAddr)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}
	}
	return &HostnamePortAddr{Host: host, Port: port}
}

func appendSocks5UDPResponseHeader(dst []byte, addr net.Addr) ([]byte, bool) {
	if addr == nil {
		return dst, false
	}

	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr == nil || udpAddr.Port < 0 || udpAddr.Port > 65535 {
			return dst, false
		}
		if ip4 := udpAddr.IP.To4(); ip4 != nil {
			dst = append(dst, 0x00, 0x00, 0x00, 0x01)
			dst = append(dst, ip4...)
			dst = append(dst, byte(udpAddr.Port>>8), byte(udpAddr.Port))
			return dst, true
		}
		if ip16 := udpAddr.IP.To16(); ip16 != nil {
			dst = append(dst, 0x00, 0x00, 0x00, 0x04)
			dst = append(dst, ip16...)
			dst = append(dst, byte(udpAddr.Port>>8), byte(udpAddr.Port))
			return dst, true
		}
		return dst, false
	}

	host := ""
	port := 0
	if hostnameAddr, ok := addr.(*HostnamePortAddr); ok {
		host = hostnameAddr.Host
		port = hostnameAddr.Port
	} else {
		parsedHost, portStr, err := net.SplitHostPort(addr.String())
		if err != nil {
			return dst, false
		}
		parsedPort, err := strconv.Atoi(portStr)
		if err != nil {
			return dst, false
		}
		host = parsedHost
		port = parsedPort
	}
	if port < 0 || port > 65535 {
		return dst, false
	}
	if ip := net.ParseIP(host); ip != nil {
		return appendSocks5UDPResponseHeader(dst, &net.UDPAddr{IP: ip, Port: port})
	}
	if len(host) == 0 || len(host) > 255 {
		return dst, false
	}
	dst = append(dst, 0x00, 0x00, 0x00, 0x03, byte(len(host)))
	dst = append(dst, host...)
	dst = append(dst, byte(port>>8), byte(port))
	return dst, true
}

// dialUDPUpstream creates an upstream UDP connection for the given destination.
func (l *proxyPortListener) dialUDPUpstream(destAddr string) (net.PacketConn, error) {
	if l.cfg.IsDirectConnection() {
		host, portStr, err := net.SplitHostPort(destAddr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		ip, _, err := resolveOutboundServerIP(context.Background(), host)
		if err != nil {
			return nil, err
		}
		uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			return nil, err
		}
		_ = uc.SetReadBuffer(2 * 1024 * 1024)
		_ = uc.SetWriteBuffer(2 * 1024 * 1024)
		disableUDPConnResetNotifications(uc, "socks5-udp-upstream")
		return uc, nil
	}
	if l.outboundMgr == nil {
		return nil, fmt.Errorf("no outbound manager")
	}
	selected, err := l.outboundMgr.SelectOutboundWithFailoverForServer(
		proxyPortSelectorID(l.cfg.ID), l.cfg.ProxyOutbound, l.cfg.GetLoadBalance(), l.cfg.GetLoadBalanceSort(), nil)
	if err != nil {
		return nil, err
	}
	if IsDirectSelection(selected) {
		host, portStr, err := net.SplitHostPort(destAddr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		ip, _, err := resolveOutboundServerIP(context.Background(), host)
		if err != nil {
			return nil, err
		}
		uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			return nil, err
		}
		_ = uc.SetReadBuffer(2 * 1024 * 1024)
		_ = uc.SetWriteBuffer(2 * 1024 * 1024)
		disableUDPConnResetNotifications(uc, "socks5-udp-upstream")
		return uc, nil
	}
	dialCtx, dialCancel := context.WithTimeout(l.ctx, 15*time.Second)
	defer dialCancel()
	return l.outboundMgr.DialPacketConn(dialCtx, selected.Name, destAddr)
}

// readLoop reads UDP datagrams from the shared relay socket, parses the SOCKS5
// UDP header, and forwards payload to the upstream destination. Responses from
// upstream are relayed back to the client with a SOCKS5 UDP header prepended.
// Datagrams from different clients are dispatched to their respective upstream
// connections, keyed by client source address.
func (r *sharedUDPRelay) readLoop(l *proxyPortListener) {
	defer r.wg.Done()
	buf := make([]byte, 65535)

	// Idle cleanup ticker
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				r.mu.Lock()
				now := time.Now()
				for clientKey, entry := range r.clients {
					entry.mu.Lock()
					for ukey, uc := range entry.upstreams {
						if now.Sub(uc.lastSeen) > 120*time.Second {
							uc.close()
							delete(entry.upstreams, ukey)
						}
					}
					if len(entry.upstreams) == 0 {
						delete(r.clients, clientKey)
					}
					entry.mu.Unlock()
				}
				r.mu.Unlock()
			}
		}
	}()

	// Set a long read deadline so we don't block forever if the socket
	// enters an error state. Reset after timeout to check stopCh.
	r.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	for {
		n, clientAddr, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeoutError(err) {
				select {
				case <-r.stopCh:
					return
				default:
					r.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
					continue
				}
			}
			return
		}
		if n < 4 || buf[2] != 0x00 {
			continue
		}

		// Validate source IP: only accept UDP from IPs with active TCP control connections
		if !r.isClientIPActive(clientAddr.IP) {
			logger.Debug("SOCKS5 UDP relay: dropping datagram from unregistered IP %s (proxy_port=%s)", clientAddr.IP, r.cfgID)
			continue
		}

		// Parse SOCKS5 UDP header
		atyp := buf[3]
		off := 4
		var destHost string
		switch atyp {
		case 0x01:
			if n < off+4+2 {
				continue
			}
			destHost = strconv.Itoa(int(buf[off])) + "." +
				strconv.Itoa(int(buf[off+1])) + "." +
				strconv.Itoa(int(buf[off+2])) + "." +
				strconv.Itoa(int(buf[off+3]))
			off += 4
		case 0x03:
			if n < off+1 {
				continue
			}
			dlen := int(buf[off])
			off++
			if n < off+dlen+2 {
				continue
			}
			destHost = string(buf[off : off+dlen])
			off += dlen
		case 0x04:
			if n < off+16+2 {
				continue
			}
			destHost = net.IP(buf[off : off+16]).String()
			off += 16
		default:
			continue
		}
		if n < off+2 {
			continue
		}
		destPort := int(buf[off])<<8 | int(buf[off+1])
		off += 2
		payload := buf[off:n]
		destAddr := destHost + ":" + strconv.Itoa(destPort)

		clientKey := clientAddr.String()

		// For 0-length keepalive payloads, update lastSeen on existing
		// upstreams so the idle sweeper doesn't close them between pings.
		// Don't create new upstreams or forward empty datagrams.
		if len(payload) == 0 {
			r.mu.Lock()
			if entry, ok := r.clients[clientKey]; ok {
				r.mu.Unlock()
				entry.mu.Lock()
				if uc, ok := entry.upstreams[destAddr]; ok {
					uc.lastSeen = time.Now()
				}
				entry.mu.Unlock()
			} else {
				r.mu.Unlock()
			}
			continue
		}

		// Get or create client entry and enqueue work. The shared relay read loop
		// must never dial or write upstream synchronously; one slow upstream would
		// otherwise head-of-line block all clients sharing this UDP socket.
		entry := r.getOrCreateClientEntry(clientKey)
		uc := r.getOrCreateUpstream(l, entry, clientKey, destAddr, clientAddr)

		var destNetAddr net.Addr
		if ip := net.ParseIP(destHost); ip != nil {
			destNetAddr = &net.UDPAddr{IP: ip, Port: destPort}
		} else {
			destNetAddr = &HostnamePortAddr{Host: destHost, Port: destPort}
		}
		payloadCopy := append([]byte(nil), payload...)
		enqueueResult := uc.enqueue(udpRelayPacket{payload: payloadCopy, dest: destNetAddr})
		if enqueueResult.droppedOldest && (enqueueResult.dropCount == 1 || enqueueResult.dropCount%sharedUDPRelayDropLogEvery == 0) {
			logger.Warn("SOCKS5 UDP relay: upstream queue full, dropped oldest packet for %s (client=%s, proxy_port=%s, drops=%d, queue_depth=%d)",
				destAddr, clientKey, r.cfgID, enqueueResult.dropCount, enqueueResult.queueDepth)
		}
		if !enqueueResult.queued {
			logger.Debug("SOCKS5 UDP relay: dropping upstream packet for %s (client=%s, proxy_port=%s)", destAddr, clientKey, r.cfgID)
		}
	}
}

func (r *sharedUDPRelay) getOrCreateClientEntry(clientKey string) *udpClientEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, exists := r.clients[clientKey]
	if !exists {
		entry = &udpClientEntry{upstreams: make(map[string]*upstreamConn)}
		r.clients[clientKey] = entry
	}
	return entry
}

func (r *sharedUDPRelay) getOrCreateUpstream(l *proxyPortListener, entry *udpClientEntry, clientKey string, destAddr string, clientAddr *net.UDPAddr) *upstreamConn {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	uc, exists := entry.upstreams[destAddr]
	if exists {
		uc.lastSeen = time.Now()
		return uc
	}

	logger.Debug("SOCKS5 UDP relay: creating upstream for %s (client=%s, proxy_port=%s)", destAddr, clientKey, r.cfgID)
	uc = newUpstreamConn()
	entry.upstreams[destAddr] = uc
	clientCopy := *clientAddr
	r.wg.Add(1)
	go r.upstreamWorker(l, clientKey, destAddr, uc, &clientCopy)
	return uc
}

func (r *sharedUDPRelay) removeUpstream(clientKey string, destAddr string, target *upstreamConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.clients[clientKey]
	if !ok {
		return
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if current := entry.upstreams[destAddr]; current == target {
		delete(entry.upstreams, destAddr)
	}
	if len(entry.upstreams) == 0 {
		delete(r.clients, clientKey)
	}
}

func (r *sharedUDPRelay) upstreamWorker(l *proxyPortListener, clientKey string, destAddr string, uc *upstreamConn, clientAddr *net.UDPAddr) {
	defer r.wg.Done()
	pc, err := l.dialUDPUpstream(destAddr)
	if err != nil {
		logger.Warn("SOCKS5 UDP relay: failed to dial upstream for %s: %v (proxy_port=%s)", destAddr, err, r.cfgID)
		uc.close()
		r.removeUpstream(clientKey, destAddr, uc)
		return
	}

	uc.mu.Lock()
	select {
	case <-uc.done:
		uc.mu.Unlock()
		_ = pc.Close()
		return
	default:
		uc.pc = pc
	}
	uc.mu.Unlock()

	r.wg.Add(1)
	go r.forwardUDPResponses(pc, clientAddr, socks5UDPResponseAddr(destAddr), uc.done)

	consecutiveWriteFailures := 0
	for {
		select {
		case <-r.stopCh:
			uc.close()
			return
		case <-uc.done:
			return
		case packet := <-uc.queue:
			_ = pc.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := writePacketConn(pc, packet.payload, packet.dest)
			if err != nil || n != len(packet.payload) {
				uc.writeErrors.Add(1)
				consecutiveWriteFailures++
				if consecutiveWriteFailures >= sharedUDPRelayMaxWriteFailures {
					stats := uc.stats()
					logger.Warn("SOCKS5 UDP relay: closing unhealthy upstream for %s after %d consecutive write failures (client=%s, proxy_port=%s, writes=%d, write_errors=%d, drops=%d, queue_depth=%d, last_error=%v)",
						destAddr, consecutiveWriteFailures, clientKey, r.cfgID, stats.WritePackets, stats.WriteErrors, stats.DroppedPackets, stats.QueueDepth, err)
					uc.close()
					r.removeUpstream(clientKey, destAddr, uc)
					return
				}
				continue
			}
			uc.writePackets.Add(1)
			consecutiveWriteFailures = 0
		}
	}
}

func (r *sharedUDPRelay) forwardUDPResponses(pc net.PacketConn, clientAddr *net.UDPAddr, fallbackAddr net.Addr, done <-chan struct{}) {
	defer r.wg.Done()
	respBuf := make([]byte, sharedUDPRelayMaxResponseHeader+sharedUDPRelayMaxDatagramSize)
	// Set read deadline once; reset only after timeout. This eliminates 1
	// syscall per response packet. 30s timeout tolerates MCBE silence bursts.
	_ = pc.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		n, responseAddr, err := pc.ReadFrom(respBuf[sharedUDPRelayMaxResponseHeader:])
		if err != nil {
			if isTimeoutError(err) {
				select {
				case <-r.stopCh:
					return
				case <-done:
					return
				default:
				}
				_ = pc.SetReadDeadline(time.Now().Add(30 * time.Second))
				continue
			}
			return
		}

		select {
		case <-r.stopCh:
			return
		case <-done:
			return
		default:
		}

		header, ok := appendSocks5UDPResponseHeader(respBuf[:0], responseAddr)
		if !ok {
			header, ok = appendSocks5UDPResponseHeader(respBuf[:0], fallbackAddr)
		}
		if !ok {
			logger.Debug("SOCKS5 UDP relay: dropping response with unknown source address %v (proxy_port=%s)", responseAddr, r.cfgID)
			continue
		}
		if len(header)+n > sharedUDPRelayMaxDatagramSize {
			logger.Debug("SOCKS5 UDP relay: dropping oversized response from %v (payload=%d header=%d proxy_port=%s)", responseAddr, n, len(header), r.cfgID)
			continue
		}
		packetStart := sharedUDPRelayMaxResponseHeader - len(header)
		copy(respBuf[packetStart:sharedUDPRelayMaxResponseHeader], header)

		// Set a short write deadline so a slow client doesn't block response
		// forwarding and cause upstream buffer overflow.
		_ = r.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = r.conn.WriteToUDP(respBuf[packetStart:sharedUDPRelayMaxResponseHeader+n], clientAddr)
	}
}

// close closes the shared relay socket and all client upstream connections.
func (r *sharedUDPRelay) close() {
	r.closeOnce.Do(func() {
		close(r.stopCh)
		r.conn.Close()
		r.mu.Lock()
		for _, entry := range r.clients {
			entry.mu.Lock()
			for _, uc := range entry.upstreams {
				uc.close()
			}
			entry.mu.Unlock()
		}
		r.clients = nil
		r.mu.Unlock()
		r.wg.Wait()
	})
}

// handleSocks5UDPAssociate handles the SOCKS5 UDP ASSOCIATE command.
// All clients on the same proxy port share a single UDP relay socket,
// bound to the same port as the TCP listener when possible, so cloud VPS
// firewalls only need to open one port for both TCP+UDP.
func (l *proxyPortListener) handleSocks5UDPAssociate(conn net.Conn) {
	relay, err := l.getOrCreateSharedUDPRelay()
	if err != nil {
		logger.Error("SOCKS5 UDP ASSOCIATE: failed to create relay socket: %v (proxy_port=%s)", err, l.cfg.ID)
		writeSocks5Reply(conn, 0x01)
		return
	}

	// Extract client IP from TCP control connection for UDP source validation
	var clientIP net.IP
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP
	} else {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		clientIP = net.ParseIP(host)
	}

	relayLocalAddr := relay.conn.LocalAddr().(*net.UDPAddr)

	// Reply with the relay address (0.0.0.0:port)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0}
	reply = append(reply, byte(relayLocalAddr.Port>>8), byte(relayLocalAddr.Port&0xFF))
	if _, err := conn.Write(reply); err != nil {
		return
	}
	clearProxyConnDeadline(conn)

	// Register this client IP so the shared relay accepts its UDP datagrams
	if clientIP != nil {
		relay.registerClientIP(clientIP)
	}

	logger.Info("SOCKS5 UDP ASSOCIATE: relay=0.0.0.0:%d for client=%s (proxy_port=%s)",
		relayLocalAddr.Port, conn.RemoteAddr(), l.cfg.ID)

	// Keep the control connection open until client disconnects.
	// The shared relay socket stays open across clients.
	// Enable TCP keepalive so NAT/middlebox timeouts don't silently kill
	// the control connection while the UDP relay is still active.
	enableTCPKeepalive(conn, 10*time.Second)

	// Keep the control connection open as long as the client is actively
	// sending UDP traffic (keepalive or game data). The client never sends
	// TCP-level data after the SOCKS5 handshake, so conn.Read only returns
	// on EOF (client disconnect) or timeout. Instead of a fixed deadline,
	// we check UDP activity on each timeout: if the client has sent UDP
	// traffic within the last 5 minutes, reset the deadline and keep
	// waiting. This makes the TCP connection persistent for active clients
	// (UDP keepalive at 15s interval keeps it alive indefinitely) while
	// still cleaning up dead clients within 5 minutes.
	//
	// TCP keepalive (10s interval, enabled above) detects network-level
	// disconnections (server restart, NAT timeout) within ~30s.
	buf := make([]byte, 128)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_, err := conn.Read(buf)
		if err == nil {
			continue // Unexpected TCP data — ignore
		}
		if !isTimeoutError(err) {
			break // EOF or non-timeout error — client disconnected
		}
		// Read timeout — check if client still has recent UDP activity
		if clientIP != nil && relay.hasRecentActivity(clientIP, 5*time.Minute) {
			// Client still active via UDP — keep TCP connection alive
			continue
		}
		// No UDP traffic for 5 minutes — client is gone
		break
	}

	// Client disconnected — unregister and clean up per-client upstreams
	if clientIP != nil {
		relay.unregisterClientIP(clientIP)
	}

	logger.Debug("SOCKS5 UDP ASSOCIATE: control connection closed for client=%s (proxy_port=%s)",
		conn.RemoteAddr(), l.cfg.ID)
}

func secureStringEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
