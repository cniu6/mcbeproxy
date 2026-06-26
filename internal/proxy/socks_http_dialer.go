// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	socks5Version       = 0x05
	socks5AuthNone      = 0x00
	socks5AuthUserPass  = 0x02
	socks5AuthNoAccept  = 0xFF
	socks5CmdConnect    = 0x01
	socks5CmdUDPAssoc   = 0x03
	socks5ReplySucceed  = 0x00
	socks5UserAuthVer   = 0x01
	socks5UserAuthOKVal = 0x00
)

// socks5Negotiate performs the SOCKS5 greeting and (optional) username/password
// authentication sub-negotiation on an already-established control connection.
func socks5Negotiate(conn net.Conn, username, password string) error {
	useAuth := username != ""

	greeting := []byte{socks5Version, 0x01, socks5AuthNone}
	if useAuth {
		greeting = []byte{socks5Version, 0x02, socks5AuthNone, socks5AuthUserPass}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5: failed to send greeting: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5: failed to read method selection: %w", err)
	}
	if reply[0] != socks5Version {
		return fmt.Errorf("socks5: unexpected version %d in method selection", reply[0])
	}

	switch reply[1] {
	case socks5AuthNone:
		return nil
	case socks5AuthUserPass:
		if !useAuth {
			return errors.New("socks5: server requires username/password authentication but none configured")
		}
		return socks5UserPassAuth(conn, username, password)
	case socks5AuthNoAccept:
		return errors.New("socks5: server rejected all offered authentication methods")
	default:
		return fmt.Errorf("socks5: server selected unsupported auth method %d", reply[1])
	}
}

func socks5UserPassAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("socks5: username/password too long (max 255 bytes)")
	}
	buf := make([]byte, 0, 3+len(username)+len(password))
	buf = append(buf, socks5UserAuthVer, byte(len(username)))
	buf = append(buf, []byte(username)...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, []byte(password)...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5: failed to send auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: failed to read auth response: %w", err)
	}
	if resp[1] != socks5UserAuthOKVal {
		return errors.New("socks5: username/password authentication failed")
	}
	return nil
}

// socks5SendRequest sends a SOCKS5 request (CONNECT or UDP ASSOCIATE) and parses
// the reply, returning the bound address reported by the server.
func socks5SendRequest(conn net.Conn, cmd byte, dest M.Socksaddr) (M.Socksaddr, error) {
	req := []byte{socks5Version, cmd, 0x00}
	req = appendSocksaddr(req, dest)
	if _, err := conn.Write(req); err != nil {
		return M.Socksaddr{}, fmt.Errorf("socks5: failed to send request: %w", err)
	}

	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return M.Socksaddr{}, fmt.Errorf("socks5: failed to read reply header: %w", err)
	}
	if header[0] != socks5Version {
		return M.Socksaddr{}, fmt.Errorf("socks5: unexpected version %d in reply", header[0])
	}
	if header[1] != socks5ReplySucceed {
		return M.Socksaddr{}, fmt.Errorf("socks5: request failed with reply code %d", header[1])
	}
	return readSocksaddr(conn)
}

// readSocksaddr reads an ATYP/ADDR/PORT triple from r (SOCKS5 wire format).
func readSocksaddr(r io.Reader) (M.Socksaddr, error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return M.Socksaddr{}, err
	}
	var addr M.Socksaddr
	switch atyp[0] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return M.Socksaddr{}, err
		}
		addr.Addr = netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return M.Socksaddr{}, err
		}
		var a16 [16]byte
		copy(a16[:], b)
		addr.Addr = netip.AddrFrom16(a16)
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return M.Socksaddr{}, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return M.Socksaddr{}, err
		}
		addr.Fqdn = string(b)
	default:
		return M.Socksaddr{}, fmt.Errorf("socks5: unknown address type %d", atyp[0])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return M.Socksaddr{}, err
	}
	addr.Port = binary.BigEndian.Uint16(port)
	return addr, nil
}

// dialSOCKS5TCP establishes a TCP connection to dest through a SOCKS5 proxy.
func (d *SingboxDialer) dialSOCKS5TCP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: failed to connect to proxy: %w", err)
	}
	if d.config.TLS {
		tlsConn, terr := dialTLSWithFingerprint(ctx, conn, d.config)
		if terr != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: TLS handshake failed: %w", terr)
		}
		conn = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := socks5Negotiate(conn, d.config.Username, d.config.Password); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := socks5SendRequest(conn, socks5CmdConnect, dest); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// dialHTTPTCP establishes a TCP connection to dest through an HTTP CONNECT proxy.
func (d *SingboxDialer) dialHTTPTCP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("http proxy: failed to connect to proxy: %w", err)
	}
	if d.config.TLS {
		tlsConn, terr := dialTLSWithFingerprint(ctx, conn, d.config)
		if terr != nil {
			conn.Close()
			return nil, fmt.Errorf("http proxy: TLS handshake failed: %w", terr)
		}
		conn = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := httpConnect(conn, dest, d.config.Username, d.config.Password); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// httpConnect performs an HTTP CONNECT handshake to tunnel a TCP connection.
func httpConnect(conn net.Conn, dest M.Socksaddr, username, password string) error {
	target := dest.String()
	req, err := http.NewRequest(http.MethodConnect, "http://"+target, nil)
	if err != nil {
		return fmt.Errorf("http proxy: failed to build CONNECT request: %w", err)
	}
	req.Host = target
	if username != "" {
		req.SetBasicAuth(username, password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("http proxy: failed to send CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("http proxy: failed to read CONNECT response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http proxy: CONNECT failed with status %s", resp.Status)
	}
	if br.Buffered() > 0 {
		return errors.New("http proxy: proxy sent unexpected data after CONNECT response")
	}
	return nil
}

// dialSOCKS5UDP sets up a SOCKS5 UDP ASSOCIATE relay for dest and returns a
// PacketConn that encapsulates datagrams with the SOCKS5 UDP request header.
func (s *SingboxOutbound) dialSOCKS5UDP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.PacketConn, error) {
	ctrl, err := s.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: failed to connect to proxy: %w", err)
	}
	if s.config.TLS {
		tlsConn, terr := dialTLSWithFingerprint(ctx, ctrl, s.config)
		if terr != nil {
			ctrl.Close()
			return nil, fmt.Errorf("socks5: TLS handshake failed: %w", terr)
		}
		ctrl = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = ctrl.SetDeadline(deadline)
	}
	if err := socks5Negotiate(ctrl, s.config.Username, s.config.Password); err != nil {
		ctrl.Close()
		return nil, err
	}
	// Per RFC 1928 the DST.ADDR/DST.PORT of a UDP ASSOCIATE request indicate the
	// address the client will send datagrams from; 0.0.0.0:0 means "unknown".
	bnd, err := socks5SendRequest(ctrl, socks5CmdUDPAssoc, M.Socksaddr{Addr: netip.IPv4Unspecified(), Port: 0})
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	_ = ctrl.SetDeadline(time.Time{})

	relayAddr, err := socks5RelayUDPAddr(ctrl, bnd)
	if err != nil {
		ctrl.Close()
		return nil, err
	}

	// Resolve FQDN to IP before creating the PacketConn. Many SOCKS5 servers
	// (especially Xray/V2Ray-based) only support IP-address (ATYP=0x01/0x04)
	// in UDP datagrams and silently drop datagrams with domain ATYP=0x03.
	// Resolving locally via the filtered resolver avoids fake-IP TUN pollution.
	resolvedDest := dest
	if dest.IsFqdn() {
		lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ip, _, resolveErr := resolveOutboundServerIP(lookupCtx, dest.Fqdn)
		cancel()
		if resolveErr != nil {
			ctrl.Close()
			return nil, fmt.Errorf("socks5: failed to resolve target %s: %w", dest.Fqdn, resolveErr)
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			ctrl.Close()
			return nil, fmt.Errorf("socks5: failed to convert resolved IP %s for target %s", ip, dest.Fqdn)
		}
		addr = addr.Unmap()
		resolvedDest = M.SocksaddrFromNetIP(netip.AddrPortFrom(addr, dest.Port))
		logger.Debug("SOCKS5 UDP: resolved %s -> %s for IP-based UDP relay", dest.Fqdn, resolvedDest.Addr.String())
	}

	logger.Info("SOCKS5 UDP ASSOCIATE: server=%s bnd=%s relay=%s",
		ctrl.RemoteAddr(), bnd, relayAddr)

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("socks5: failed to open UDP socket: %w", err)
	}
	_ = udpConn.SetReadBuffer(2 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(2 * 1024 * 1024)

	logger.Debug("SOCKS5 UDP ASSOCIATE: relay=%s localUDP=%s dest=%s\n",
		relayAddr, udpConn.LocalAddr(), resolvedDest)

	return &socks5UDPPacketConn{
		udpConn:     udpConn,
		ctrlConn:    ctrl,
		relayAddr:   relayAddr,
		destination: resolvedDest,
	}, nil
}

// socks5RelayUDPAddr resolves the UDP relay endpoint from the ASSOCIATE reply,
// falling back to the proxy server's IP when the server returns an unspecified
// bound address (a common server behaviour).
func socks5RelayUDPAddr(ctrl net.Conn, bnd M.Socksaddr) (*net.UDPAddr, error) {
	port := int(bnd.Port)
	if port == 0 {
		return nil, errors.New("socks5: server returned zero UDP relay port")
	}
	if bnd.Addr.IsValid() && !bnd.Addr.IsUnspecified() {
		return &net.UDPAddr{IP: bnd.Addr.AsSlice(), Port: port}, nil
	}
	host, _, err := net.SplitHostPort(ctrl.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("socks5: failed to derive relay address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("socks5: invalid proxy address %q for UDP relay", host)
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

// socks5UDPPacketConn implements net.PacketConn over a SOCKS5 UDP association.
// All datagrams are sent to a single baked destination, matching the contract of
// the other UDP outbound PacketConns in this package.
type socks5UDPPacketConn struct {
	udpConn     *net.UDPConn
	ctrlConn    net.Conn
	relayAddr   *net.UDPAddr
	destination M.Socksaddr
}

func (c *socks5UDPPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	header := []byte{0x00, 0x00, 0x00}
	header = appendSocksaddr(header, c.destination)
	datagram := make([]byte, 0, len(header)+len(p))
	datagram = append(datagram, header...)
	datagram = append(datagram, p...)
	_, err := c.udpConn.WriteToUDP(datagram, c.relayAddr)
	if err != nil {
		logger.Debug("SOCKS5 UDP write failed: relay=%s err=%v", c.relayAddr, err)
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+512)
	for {
		n, err := c.udpConn.Read(buf)
		if err != nil {
			if !isTimeoutError(err) {
				logger.Debug("SOCKS5 UDP read failed: local=%s relay=%s err=%v",
					c.udpConn.LocalAddr(), c.relayAddr, err)
			}
			return 0, nil, err
		}
		if n < 3 {
			continue
		}
		// Skip RSV(2) + FRAG(1); drop fragmented datagrams (unsupported).
		if buf[2] != 0x00 {
			continue
		}
		dataOffset, perr := socks5UDPHeaderLen(buf[3:n])
		if perr != nil {
			continue
		}
		data := buf[3+dataOffset : n]
		copied := copy(p, data)
		return copied, c.destination.UDPAddr(), nil
	}
}

// socks5UDPHeaderLen returns the length of the ATYP/ADDR/PORT portion of a SOCKS5
// UDP datagram body (i.e. the bytes following RSV+FRAG, before the payload).
func socks5UDPHeaderLen(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	switch b[0] {
	case 0x01:
		if len(b) < 1+4+2 {
			return 0, io.ErrUnexpectedEOF
		}
		return 1 + 4 + 2, nil
	case 0x04:
		if len(b) < 1+16+2 {
			return 0, io.ErrUnexpectedEOF
		}
		return 1 + 16 + 2, nil
	case 0x03:
		if len(b) < 2 {
			return 0, io.ErrUnexpectedEOF
		}
		dlen := int(b[1])
		if len(b) < 1+1+dlen+2 {
			return 0, io.ErrUnexpectedEOF
		}
		return 1 + 1 + dlen + 2, nil
	default:
		return 0, fmt.Errorf("socks5: unknown address type %d in UDP header", b[0])
	}
}

func (c *socks5UDPPacketConn) LocalAddr() net.Addr { return c.udpConn.LocalAddr() }

func (c *socks5UDPPacketConn) SetDeadline(t time.Time) error { return c.udpConn.SetDeadline(t) }

func (c *socks5UDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *socks5UDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

func (c *socks5UDPPacketConn) Close() error {
	err := c.udpConn.Close()
	if c.ctrlConn != nil {
		_ = c.ctrlConn.Close()
	}
	return err
}

var _ net.PacketConn = (*socks5UDPPacketConn)(nil)

// initSOCKS5 initializes a SOCKS5 outbound. No persistent state is required; the
// association is established per ListenPacket call.
func (s *SingboxOutbound) initSOCKS5(_ *config.ProxyOutbound) error { return nil }

// initHTTP initializes an HTTP proxy outbound. HTTP proxies only support TCP
// (via CONNECT); UDP relay is handled by rejecting it in ListenPacket.
func (s *SingboxOutbound) initHTTP(_ *config.ProxyOutbound) error { return nil }
