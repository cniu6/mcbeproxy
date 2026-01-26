// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

const (
	defaultProxyDialTimeout = 10 * time.Second
)

// ProxyPortManager manages local proxy port listeners.
type ProxyPortManager struct {
	configMgr   *config.ProxyPortConfigManager
	outboundMgr OutboundManager
	mu          sync.Mutex
	listeners   map[string]*proxyPortListener
	dialerPool  *proxyPortDialerPool
}

func NewProxyPortManager(configMgr *config.ProxyPortConfigManager, outboundMgr OutboundManager) *ProxyPortManager {
	return &ProxyPortManager{
		configMgr:   configMgr,
		outboundMgr: outboundMgr,
		listeners:   make(map[string]*proxyPortListener),
		dialerPool:  newProxyPortDialerPool(),
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

// Reload stops listeners without waiting for active connections and restarts them.
// This keeps API updates responsive while still reloading config.
func (m *ProxyPortManager) Reload(enabled bool) error {
	m.stopListeners(false, false)
	return m.Start(enabled)
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

type proxyPortDialerPool struct {
	mu      sync.Mutex
	dialers map[string]*SingboxDialer
}

func newProxyPortDialerPool() *proxyPortDialerPool {
	return &proxyPortDialerPool{
		dialers: make(map[string]*SingboxDialer),
	}
}

func (p *proxyPortDialerPool) Get(cfg *config.ProxyOutbound) (*SingboxDialer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("outbound config is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if d, ok := p.dialers[cfg.Name]; ok {
		return d, nil
	}
	dialer, err := CreateSingboxDialer(cfg)
	if err != nil {
		return nil, err
	}
	p.dialers[cfg.Name] = dialer
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

type proxyPortListener struct {
	cfg         *config.ProxyPortConfig
	outboundMgr OutboundManager
	dialerPool  *proxyPortDialerPool
	listener    net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	allowList   []*net.IPNet
}

func newProxyPortListener(cfg *config.ProxyPortConfig, outboundMgr OutboundManager, dialerPool *proxyPortDialerPool) *proxyPortListener {
	return &proxyPortListener{
		cfg:         cfg.Clone(),
		outboundMgr: outboundMgr,
		dialerPool:  dialerPool,
	}
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
	if wait {
		l.wg.Wait()
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
	case 0x04:
		l.handleSocks4(conn, reader)
	default:
		l.handleHTTP(conn, reader)
	}
}

func (l *proxyPortListener) handleHTTP(conn net.Conn, reader *bufio.Reader) {
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
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

		req.RequestURI = ""
		if req.URL != nil {
			req.URL.Scheme = ""
			req.URL.Host = ""
		}
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")

		if err := req.Write(remote); err != nil {
			remote.Close()
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(remote), req)
		if err != nil {
			remote.Close()
			return
		}
		if err := resp.Write(conn); err != nil {
			remote.Close()
			return
		}
		remote.Close()

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

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		_, _ = io.Copy(remote, reader)
		remote.Close()
	}()
	_, _ = io.Copy(conn, remote)
	remote.Close()
}

func (l *proxyPortListener) handleSocks5(conn net.Conn, reader *bufio.Reader) {
	if err := l.handleSocks5Handshake(conn, reader); err != nil {
		return
	}
	target, err := readSocks5Request(reader)
	if err != nil {
		writeSocks5Reply(conn, 0x01)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultProxyDialTimeout)
	remote, _, err := l.dialOutbound(ctx, target)
	cancel()
	if err != nil {
		writeSocks5Reply(conn, 0x05)
		return
	}
	writeSocks5Reply(conn, 0x00)

	go func() {
		_, _ = io.Copy(remote, reader)
		remote.Close()
	}()
	_, _ = io.Copy(conn, remote)
	remote.Close()
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

	if string(uname) != l.cfg.Username || string(pass) != l.cfg.Password {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("auth failed")
	}
	_, _ = conn.Write([]byte{0x01, 0x00})
	return nil
}

func readSocks5Request(reader *bufio.Reader) (string, error) {
	ver, err := reader.ReadByte()
	if err != nil || ver != 0x05 {
		return "", fmt.Errorf("invalid request version")
	}
	cmd, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	if cmd != 0x01 {
		return "", fmt.Errorf("unsupported command")
	}
	_, _ = reader.ReadByte() // RSV
	atyp, err := reader.ReadByte()
	if err != nil {
		return "", err
	}

	host := ""
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		l, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, int(l))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", fmt.Errorf("invalid atyp")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return "", err
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func writeSocks5Reply(conn net.Conn, rep byte) {
	// VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
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
	_, _ = readUntilNull(reader) // user id

	destIP := net.IP(ipBuf)
	host := destIP.String()
	if ipBuf[0] == 0 && ipBuf[1] == 0 && ipBuf[2] == 0 && ipBuf[3] != 0 {
		domain, _ := readUntilNull(reader)
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

	writeSocks4Reply(conn, 0x5A, destIP, port)

	go func() {
		_, _ = io.Copy(remote, reader)
		remote.Close()
	}()
	_, _ = io.Copy(conn, remote)
	remote.Close()
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

func readUntilNull(reader *bufio.Reader) (string, error) {
	var buf []byte
	for {
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

func (l *proxyPortListener) dialOutbound(ctx context.Context, address string) (net.Conn, string, error) {
	if l.cfg.IsDirectConnection() || l.outboundMgr == nil {
		dialer := &net.Dialer{Timeout: defaultProxyDialTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		return conn, "direct", err
	}

	exclude := make([]string, 0, 4)
	attempts := 3
	if l.cfg.IsMultiNodeSelection() {
		nodes := l.cfg.GetNodeList()
		if len(nodes) > 0 {
			attempts = len(nodes)
		}
	}

	for i := 0; i < attempts; i++ {
		selected, err := l.outboundMgr.SelectOutboundWithFailover(l.cfg.ProxyOutbound, l.cfg.GetLoadBalance(), l.cfg.GetLoadBalanceSort(), exclude)
		if err != nil {
			return nil, "", err
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
	return user == l.cfg.Username && pass == l.cfg.Password
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
