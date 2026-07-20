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
	"sync"
	"sync/atomic"
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

// createSOCKS5Association establishes a fresh SOCKS5 UDP ASSOCIATE and returns
// the TCP control connection, UDP relay socket, relay address, and resolved
// destination. This is used both for initial connection and for reconnection
// when the TCP control connection is closed by the remote.
func (s *SingboxOutbound) createSOCKS5Association(ctx context.Context, serverAddr, dest M.Socksaddr) (net.Conn, net.PacketConn, net.Addr, M.Socksaddr, error) {
	ctrl, err := s.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, nil, nil, M.Socksaddr{}, fmt.Errorf("socks5: failed to connect to proxy: %w", err)
	}
	if s.config.TLS {
		tlsConn, terr := dialTLSWithFingerprint(ctx, ctrl, s.config)
		if terr != nil {
			ctrl.Close()
			return nil, nil, nil, M.Socksaddr{}, fmt.Errorf("socks5: TLS handshake failed: %w", terr)
		}
		ctrl = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = ctrl.SetDeadline(deadline)
	}
	if err := socks5Negotiate(ctrl, s.config.Username, s.config.Password); err != nil {
		ctrl.Close()
		return nil, nil, nil, M.Socksaddr{}, err
	}
	bnd, err := socks5SendRequest(ctrl, socks5CmdUDPAssoc, M.Socksaddr{Addr: netip.IPv4Unspecified(), Port: 0})
	if err != nil {
		ctrl.Close()
		return nil, nil, nil, M.Socksaddr{}, err
	}
	_ = ctrl.SetDeadline(time.Time{})
	enableTCPKeepalive(ctrl, 5*time.Second)

	relayAddr, err := socks5RelayUDPAddr(ctrl, serverAddr, bnd)
	if err != nil {
		ctrl.Close()
		return nil, nil, nil, M.Socksaddr{}, err
	}

	resolvedDest := dest
	if dest.IsFqdn() {
		lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ip, _, resolveErr := resolveOutboundServerIP(lookupCtx, dest.Fqdn)
		cancel()
		if resolveErr != nil {
			ctrl.Close()
			return nil, nil, nil, M.Socksaddr{}, fmt.Errorf("socks5: failed to resolve target %s: %w", dest.Fqdn, resolveErr)
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			ctrl.Close()
			return nil, nil, nil, M.Socksaddr{}, fmt.Errorf("socks5: failed to convert resolved IP %s for target %s", ip, dest.Fqdn)
		}
		addr = addr.Unmap()
		resolvedDest = M.SocksaddrFromNetIP(netip.AddrPortFrom(addr, dest.Port))
	}

	logger.Info("SOCKS5 UDP ASSOCIATE: server=%s bnd=%s relay=%s",
		ctrl.RemoteAddr(), bnd, relayAddr)

	// UDP 中继 socket 选择策略（链式场景两种末跳服务器行为都真实存在，
	// 必须自适应，不能写死其中一种）：
	//
	// a) 有些末跳 SOCKS5 允许 UDP 源 IP 与 TCP 控制面不同（关联靠首包 UDP
	//    源地址注册）——本机直连 relay 可用。直连能避免对上一跳（如
	//    127.0.0.1:1080 这类单 ASSOCIATE 加速器）再做一层 UDP ASSOCIATE、
	//    挤掉其它玩家回程（表现为 up>0 down=0）。
	// b) 有些末跳 SOCKS5 只接受与控制连接同源 IP 的 UDP 包。链式下控制连接
	//    从上一跳出口进来，本机直连发过去会被静默丢弃——永远 i/o timeout、
	//    一个字节都收不到。这种节点必须把 UDP 也通过链隧道发。
	//
	// 因此链式场景下：先建直连 socket 并用一发 RakNet unconnected ping 实测
	// relay 是否回包（本程序的 UDP 目标恒为 MCBE 服务器，必回 pong）；不通
	// 则改走链隧道。结果按「末跳服务器地址」缓存（见 socks5DirectRelayMemo），
	// 后续 ASSOCIATE 不再重复探测。非链式（单跳）SOCKS5 保持原直连行为不变。
	var udpConn net.PacketConn
	relayIsLoopback := relayAddr.IP != nil && (relayAddr.IP.IsLoopback() || relayAddr.IP.IsUnspecified())
	if socks5DirectRelayAllowLoopback {
		relayIsLoopback = false
	}
	chainDialer, isChainHop := s.dialer.(*chainNxDialer)
	canChainTunnel := isChainHop && chainDialer.udpOutbound != nil

	memoKey := serverAddr.String()
	directKnown, directWorks := false, true
	if canChainTunnel {
		directWorks, directKnown = loadSOCKS5DirectRelayMemo(memoKey)
		if !directKnown {
			directWorks = true // 未知：先试直连并实测
		}
	}

	if !relayIsLoopback && directWorks {
		directConn, derr := net.DialUDP("udp", nil, relayAddr)
		if derr == nil {
			direct := &connectedPacketConn{UDPConn: directConn, peer: relayAddr}
			_ = directConn.SetReadBuffer(2 * 1024 * 1024)
			_ = directConn.SetWriteBuffer(2 * 1024 * 1024)
			if canChainTunnel && !directKnown {
				if probeSOCKS5DirectRelay(direct, resolvedDest) {
					storeSOCKS5DirectRelayMemo(memoKey, true)
					udpConn = direct
					logger.Info("SOCKS5 UDP ASSOCIATE: direct relay probe OK, using direct UDP to relay=%s (server=%s)", relayAddr, memoKey)
				} else {
					storeSOCKS5DirectRelayMemo(memoKey, false)
					_ = direct.Close()
					logger.Info("SOCKS5 UDP ASSOCIATE: direct relay probe got no reply from relay=%s (server=%s likely requires chain-source UDP), tunneling UDP via chain", relayAddr, memoKey)
				}
			} else {
				udpConn = direct
				logger.Info("SOCKS5 UDP ASSOCIATE: using direct UDP to relay=%s (TCP control stays on dialer chain)", relayAddr)
			}
		} else {
			logger.Debug("SOCKS5 UDP ASSOCIATE: direct UDP to relay=%s failed (%v), will try chain ListenPacket", relayAddr, derr)
		}
	}
	if udpConn == nil && canChainTunnel {
		relayDest := M.ParseSocksaddr(relayAddr.String())
		pc, lerr := chainDialer.udpOutbound.ListenPacket(ctx, relayDest.String())
		if lerr == nil {
			udpConn = pc
			logger.Info("SOCKS5 UDP ASSOCIATE: relay socket via chain dialer: relay=%s localUDP=%s", relayAddr, udpConn.LocalAddr())
		} else {
			logger.Debug("SOCKS5 UDP ASSOCIATE: chain dialer ListenPacket failed (%v), falling back to direct UDP", lerr)
		}
	}
	if udpConn == nil {
		directConn, derr := net.DialUDP("udp", nil, relayAddr)
		if derr != nil {
			ctrl.Close()
			return nil, nil, nil, M.Socksaddr{}, fmt.Errorf("socks5: failed to open UDP socket: %w", derr)
		}
		udpConn = &connectedPacketConn{UDPConn: directConn, peer: relayAddr}
		_ = directConn.SetReadBuffer(2 * 1024 * 1024)
		_ = directConn.SetWriteBuffer(2 * 1024 * 1024)
	}

	logger.Debug("SOCKS5 UDP ASSOCIATE: relay=%s localUDP=%s dest=%s\n",
		relayAddr, udpConn.LocalAddr(), resolvedDest)

	return ctrl, udpConn, relayAddr, resolvedDest, nil
}

// socks5DirectRelayMemo 记录「链式末跳 SOCKS5 服务器是否接受本机直连 relay
// 的 UDP 包」的探测结果，key 为末跳服务器地址（host:port）。带 TTL：节点侧
// 配置/防火墙可能变化，过期后下一次 ASSOCIATE 会重新实测。
var socks5DirectRelayMemo sync.Map // map[string]socks5DirectRelayMemoEntry

// socks5DirectRelayAllowLoopback 仅测试用：允许把回环地址的 relay 当作可
// 直连目标。生产中 relay 是回环/未指定地址时直连没有意义，必须走链隧道。
var socks5DirectRelayAllowLoopback = false

const socks5DirectRelayMemoTTL = 10 * time.Minute

type socks5DirectRelayMemoEntry struct {
	directWorks bool
	expiresAt   time.Time
}

func loadSOCKS5DirectRelayMemo(serverAddr string) (directWorks bool, known bool) {
	v, ok := socks5DirectRelayMemo.Load(serverAddr)
	if !ok {
		return false, false
	}
	entry := v.(socks5DirectRelayMemoEntry)
	if time.Now().After(entry.expiresAt) {
		socks5DirectRelayMemo.Delete(serverAddr)
		return false, false
	}
	return entry.directWorks, true
}

func storeSOCKS5DirectRelayMemo(serverAddr string, directWorks bool) {
	socks5DirectRelayMemo.Store(serverAddr, socks5DirectRelayMemoEntry{
		directWorks: directWorks,
		expiresAt:   time.Now().Add(socks5DirectRelayMemoTTL),
	})
}

// probeSOCKS5DirectRelay 实测「本机直连 relay」这条 UDP 路是否真的通：通过
// relay 向最终目标（MCBE 服务器）发 RakNet unconnected ping，只要 relay 转
// 回任何一个 UDP 包（pong）就算通。收不到任何回包（多为末跳服务器只认与
// 控制连接同源 IP 的 UDP，直连包被静默丢弃）则判定不通。
//
// 用真实目标做探测而不是第三方地址（如 8.8.8.8:53），因为部分游戏代理节点
// 会过滤非游戏端口；MCBE 服务器对 unconnected ping 必回 pong。若目标服务器
// 恰好宕机会被误判为不通——此时改走链隧道同样连不上目标，不会更糟，且结果
// 带 TTL、之后会重测。总预算约 1 秒（两次发包，各等 ~500ms）。
func probeSOCKS5DirectRelay(relayConn net.PacketConn, dest M.Socksaddr) bool {
	defer func() {
		_ = relayConn.SetDeadline(time.Time{})
	}()

	// RakNet unconnected ping: 0x01 + timestamp(8B BE) + MAGIC(16B) + GUID(8B)
	ping := make([]byte, 0, 33)
	ping = append(ping, raknetUnconnectedPing)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	ping = append(ping, ts[:]...)
	ping = append(ping, raknetMagic...)
	var guid [8]byte
	binary.BigEndian.PutUint64(guid[:], uint64(time.Now().UnixNano()))
	ping = append(ping, guid[:]...)

	// SOCKS5 UDP 封装：RSV(2) + FRAG(1) + ATYP/ADDR/PORT + payload
	datagram := append([]byte{0x00, 0x00, 0x00}, appendSocksaddr(nil, dest)...)
	datagram = append(datagram, ping...)

	buf := make([]byte, 1500)
	for attempt := 0; attempt < 2; attempt++ {
		_ = relayConn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := relayConn.WriteTo(datagram, nil); err != nil {
			return false
		}
		_ = relayConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		for {
			n, _, err := relayConn.ReadFrom(buf)
			if err != nil {
				break // 超时/出错：进入下一次尝试
			}
			if n > 0 {
				// relay 回了任何包就证明直连路是通的（不必解析 pong 内容）。
				// 把 socket 缓冲里可能剩下的回包排干，避免脏数据流入正式会话。
				_ = relayConn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
				for {
					if _, _, derr := relayConn.ReadFrom(buf); derr != nil {
						break
					}
				}
				return true
			}
		}
	}
	return false
}

// dialSOCKS5UDP sets up a SOCKS5 UDP ASSOCIATE relay for dest and returns a
// PacketConn that encapsulates datagrams with the SOCKS5 UDP request header.
func (s *SingboxOutbound) dialSOCKS5UDP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.PacketConn, error) {
	ctrl, udpConn, relayAddr, resolvedDest, err := s.createSOCKS5Association(ctx, serverAddr, dest)
	if err != nil {
		return nil, err
	}

	// Proactive reconnect creates new SOCKS5 UDP ASSOCIATEs that can
	// invalidate other connections' UDP relay mappings at the same SOCKS5
	// server, causing silent packet loss. Chain UDP cache owns stale-conn
	// replacement, so cached SOCKS5 associations must be marked dead instead
	// of reconnecting in place; otherwise a dead cached entry can become alive
	// again and be reused with changed control/UDP state.
	//
	// disableReactiveReconnect 只应对「会被 chain UDP cache 共享/复用」的连接
	// 生效（s.disableSOCKS5ReactiveReconnect，仅链式代理各跳会设为 true）。对
	// 独立出站（非链式，每个 RawUDP 客户端各自独占一条 PacketConn，不共享）而
	// 言，原地重连是安全的，也是它唯一的自愈手段——不能一律禁用，否则上游控制
	// 连接一断就直接把玩家踢下线，高并发下会明显增加掉线率。
	s5pc := &socks5UDPPacketConn{
		destination:               resolvedDest,
		stopCh:                    make(chan struct{}),
		disableProactiveReconnect: true,
		disableReactiveReconnect:  s.disableSOCKS5ReactiveReconnect,
		reconnectFn: func() (net.Conn, net.PacketConn, net.Addr, error) {
			reconnectCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			newCtrl, newUdp, newRelay, _, rerr := s.createSOCKS5Association(reconnectCtx, serverAddr, dest)
			return newCtrl, newUdp, newRelay, rerr
		},
	}
	s5pc.state.Store(&connState{
		udpConn:   udpConn,
		ctrlConn:  ctrl,
		relayAddr: relayAddr,
	})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Debug("SOCKS5 UDP monitorCtrlConn panic: %v", r)
			}
		}()
		s5pc.monitorCtrlConn()
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Debug("SOCKS5 UDP udpKeepalive panic: %v", r)
			}
		}()
		s5pc.udpKeepalive()
	}()

	return s5pc, nil
}

// proactiveReconnectInterval is how often we proactively rebuild the SOCKS5 UDP
// ASSOCIATE to prevent latency buildup from stale associations. Many SOCKS5
// servers accumulate state or degrade routing quality over time; rotating the
// association every 2 minutes keeps latency stable. This is shorter than the
// typical server idle timeout (3-5 min), so proactive reconnect also prevents
// disruptive reactive reconnects.
const proactiveReconnectInterval = 2 * time.Minute

// monitorCtrlConn does two things:
//  1. Proactively reconnects every proactiveReconnectInterval using
//     make-before-break: create new association first, then atomically swap,
//     then close old — gap is nanoseconds.
//  2. Reactively reconnects when the server closes the TCP control connection
//     (break-before-make, since old conn is already dead).
//
// This keeps latency stable over long sessions and survives server-side idle
// timeouts transparently.
func (c *socks5UDPPacketConn) monitorCtrlConn() {
	buf := make([]byte, 128)
	backoff := 1 * time.Second
	maxBackoff := 10 * time.Second
	proactiveTimer := time.NewTimer(proactiveReconnectInterval)
	defer proactiveTimer.Stop()

	for {
		if c.closed.Load() {
			return
		}
		st := c.state.Load()
		if st == nil {
			return
		}

		// Set a short read deadline so we can check the proactive timer.
		_ = st.ctrlConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := st.ctrlConn.Read(buf)

		// Check proactive timer first (non-blocking).
		select {
		case <-proactiveTimer.C:
			if !c.disableProactiveReconnect && !c.closed.Load() {
				c.doProactiveReconnect(st)
				proactiveTimer.Reset(proactiveReconnectInterval)
			}
			continue
		case <-c.stopCh:
			return
		default:
		}

		if err == nil {
			continue
		}
		if c.closed.Load() {
			return
		}
		if isTimeoutError(err) {
			continue
		}

		// TCP control connection closed by remote. For cached SOCKS5 UDP
		// associations, do not reconnect in place: the cache needs to observe
		// the old entry as dead and create a fresh PacketConn on next use.
		if c.disableReactiveReconnect {
			logger.Info("SOCKS5 UDP: TCP control connection closed, marking association dead: err=%v", err)
			c.markRemoteClosed(st)
			return
		}
		logger.Info("SOCKS5 UDP: TCP control connection closed, attempting reconnect: err=%v", err)
		c.doReactiveReconnect(st, &backoff, maxBackoff)
		proactiveTimer.Reset(proactiveReconnectInterval)
	}
}

// doProactiveReconnect performs a make-before-break reconnect: create the new
// association while the old one is still alive, then atomically swap and close
// old. This minimizes the gap to just the atomic pointer store (~nanoseconds).
func (c *socks5UDPPacketConn) doProactiveReconnect(oldState *connState) {
	newCtrl, newUdp, newRelay, err := c.reconnectFn()
	if err != nil {
		logger.Debug("SOCKS5 UDP: proactive reconnect failed, keeping old conn: err=%v", err)
		return
	}
	c.reconnecting.Store(true)
	newState := &connState{
		udpConn:   newUdp,
		ctrlConn:  newCtrl,
		relayAddr: newRelay,
	}
	c.applyConfiguredBuffers(newState)
	c.state.Store(newState)
	oldState.udpConn.Close()
	oldState.ctrlConn.Close()
	c.reconnecting.Store(false)
	logger.Info("SOCKS5 UDP: proactive reconnect succeeded (make-before-break)")
}

func (c *socks5UDPPacketConn) markRemoteClosed(st *connState) {
	c.remoteClosed.Store(true)
	c.reconnecting.Store(false)
	if st != nil {
		st.udpConn.Close()
		st.ctrlConn.Close()
	}
}

// doReactiveReconnect handles the case where the server already closed the TCP
// control connection. Old conn is dead, so we use break-before-make with
// exponential backoff retry.
func (c *socks5UDPPacketConn) doReactiveReconnect(st *connState, backoff *time.Duration, maxBackoff time.Duration) {
	c.reconnecting.Store(true)
	st.udpConn.Close()
	st.ctrlConn.Close()

	for !c.closed.Load() {
		newCtrl, newUdp, newRelay, err := c.reconnectFn()
		if err == nil {
			newState := &connState{
				udpConn:   newUdp,
				ctrlConn:  newCtrl,
				relayAddr: newRelay,
			}
			c.applyConfiguredBuffers(newState)
			c.state.Store(newState)
			c.reconnecting.Store(false)
			logger.Info("SOCKS5 UDP: reactive reconnect succeeded, resuming")
			*backoff = 1 * time.Second
			return
		}
		logger.Debug("SOCKS5 UDP: reactive reconnect failed: err=%v backoff=%v", err, *backoff)
		select {
		case <-c.stopCh:
			c.reconnecting.Store(false)
			return
		case <-time.After(*backoff):
		}
		*backoff *= 2
		if *backoff > maxBackoff {
			*backoff = maxBackoff
		}
	}
	c.reconnecting.Store(false)
	c.remoteClosed.Store(true)
	logger.Info("SOCKS5 UDP: reactive reconnect abandoned (closed)")
}

// IsRemoteClosed returns true if the TCP control connection has been closed
// by the remote server. This allows external caching layers (e.g.
// chainUDPOutbound) to detect dead cached connections before reuse.
func (c *socks5UDPPacketConn) IsRemoteClosed() bool {
	return c.remoteClosed.Load()
}

// udpKeepalive sends a minimal SOCKS5 UDP datagram every 25 seconds to keep
// the server-side UDP mapping alive. Many SOCKS5 servers (Xray, V2Ray, Clash)
// expire UDP mappings after 30-60s of inactivity; without keepalive, a player
// who doesn't send traffic for 30s (loading screen, AFK) will silently lose
// their UDP relay and all downstream traffic until the next outgoing packet
// re-triggers a mapping — but the server may have already closed the TCP
// control connection by then.
//
// The keepalive datagram is a 0-length payload to the destination, which
// most servers will process (updating the mapping expiry) without forwarding.
// If the server doesn't support 0-length, the worst case is an ICMP port-
// unreachable from the target (harmless, handled by recoverable error logic).
func (c *socks5UDPPacketConn) udpKeepalive() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	consecutiveFailures := 0
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			if c.closed.Load() || c.remoteClosed.Load() {
				return
			}
			if c.reconnecting.Load() {
				continue
			}
			st := c.state.Load()
			if st == nil {
				return
			}
			datagramPtr := socks5UDPWritePool.Get().(*[]byte)
			datagram := (*datagramPtr)[:0]
			datagram = append(datagram, 0x00, 0x00, 0x00)
			datagram = appendSocksaddr(datagram, c.destination)
			c.writeMu.Lock()
			_ = st.udpConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err := st.udpConn.WriteTo(datagram, st.relayAddr)
			c.writeMu.Unlock()
			*datagramPtr = datagram
			socks5UDPWritePool.Put(datagramPtr)
			if err != nil {
				if c.closed.Load() || c.reconnecting.Load() {
					return
				}
				consecutiveFailures++
				logger.Debug("SOCKS5 UDP keepalive failed: relay=%s err=%v consecutive=%d",
					st.relayAddr, err, consecutiveFailures)
				if consecutiveFailures >= 3 {
					logger.Info("SOCKS5 UDP keepalive: closing dead relay after %d consecutive failures: relay=%s",
						consecutiveFailures, st.relayAddr)
					c.remoteClosed.Store(true)
					st.udpConn.Close()
					st.ctrlConn.Close()
					return
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

// socks5RelayUDPAddr resolves the UDP relay endpoint from the ASSOCIATE reply,
// falling back to the proxy server's IP when the server returns an unspecified
// bound address (a common server behaviour).
func socks5RelayUDPAddr(ctrl net.Conn, serverAddr M.Socksaddr, bnd M.Socksaddr) (*net.UDPAddr, error) {
	port := int(bnd.Port)
	if port == 0 {
		return nil, errors.New("socks5: server returned zero UDP relay port")
	}
	if bnd.Addr.IsValid() && !bnd.Addr.IsUnspecified() {
		return &net.UDPAddr{IP: bnd.Addr.AsSlice(), Port: port}, nil
	}
	// Use serverAddr first — correct for chained connections where
	// ctrl.RemoteAddr() is the immediate TCP peer (e.g. a local relay),
	// not the SOCKS5 server that owns the UDP relay.
	if serverAddr.Addr.IsValid() && !serverAddr.Addr.IsUnspecified() {
		return &net.UDPAddr{IP: serverAddr.Addr.AsSlice(), Port: port}, nil
	}
	if serverAddr.Fqdn != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverAddr.Fqdn, port))
		if err == nil {
			return udpAddr, nil
		}
	}
	// Fallback to ctrl.RemoteAddr() for direct connections.
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

// connectedPacketConn wraps a connected *net.UDPConn to implement net.PacketConn.
// Connected UDP sockets can't use WriteTo (returns "use of WriteTo with
// pre-connected connection"), so we delegate to Write which sends to the
// connected peer. ReadFrom delegates to Read and returns the peer address.
type connectedPacketConn struct {
	*net.UDPConn
	peer net.Addr
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.UDPConn.Write(p)
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.UDPConn.Read(p)
	return n, c.peer, err
}

var _ net.PacketConn = (*connectedPacketConn)(nil)

// socks5UDPPacketConn implements net.PacketConn over a SOCKS5 UDP association.
// All datagrams are sent to a single baked destination, matching the contract of
// the other UDP outbound PacketConns in this package.
type connState struct {
	udpConn   net.PacketConn
	ctrlConn  net.Conn
	relayAddr net.Addr
}

type socks5UDPPacketConn struct {
	state                     atomic.Pointer[connState] // swapped atomically during reconnect
	destination               M.Socksaddr
	closeOnce                 sync.Once
	closed                    atomic.Bool // set by Close() to suppress monitor log
	remoteClosed              atomic.Bool // set when reconnect fails permanently
	reconnecting              atomic.Bool // set while monitor is rebuilding the association
	writeMu                   sync.Mutex  // protects SetWriteDeadline + WriteTo from concurrent keepalive
	stopCh                    chan struct{}
	reconnectFn               func() (net.Conn, net.PacketConn, net.Addr, error)
	disableProactiveReconnect bool // set for chain SOCKS5 to avoid multi-ASSOCIATE interference
	disableReactiveReconnect  bool // set for cached SOCKS5 so dead entries are replaced by the cache
	readBufferSize            atomic.Int64
	writeBufferSize           atomic.Int64
}

func (c *socks5UDPPacketConn) applyConfiguredBuffers(st *connState) {
	if c == nil || st == nil || st.udpConn == nil {
		return
	}
	if readSize := int(c.readBufferSize.Load()); readSize > 0 {
		if setter, ok := st.udpConn.(interface{ SetReadBuffer(int) error }); ok {
			_ = setter.SetReadBuffer(readSize)
		}
	}
	if writeSize := int(c.writeBufferSize.Load()); writeSize > 0 {
		if setter, ok := st.udpConn.(interface{ SetWriteBuffer(int) error }); ok {
			_ = setter.SetWriteBuffer(writeSize)
		}
	}
}

var socks5UDPWritePool = sync.Pool{
	New: func() interface{} { b := make([]byte, 0, 1024); return &b },
}

func (c *socks5UDPPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.remoteClosed.Load() {
		return 0, errors.New("socks5: UDP relay closed")
	}
	// Wait for reconnect to complete (up to 15s).
	for i := 0; i < 300 && c.reconnecting.Load() && !c.closed.Load() && !c.remoteClosed.Load(); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if c.closed.Load() {
		return 0, errors.New("socks5: connection closed")
	}
	if c.remoteClosed.Load() {
		return 0, errors.New("socks5: UDP relay closed")
	}
	st := c.state.Load()
	if st == nil {
		return 0, errors.New("socks5: no connection")
	}
	datagramPtr := socks5UDPWritePool.Get().(*[]byte)
	datagram := (*datagramPtr)[:0]
	defer func() {
		*datagramPtr = datagram
		socks5UDPWritePool.Put(datagramPtr)
	}()
	datagram = append(datagram, 0x00, 0x00, 0x00)
	datagram = appendSocksaddr(datagram, c.destination)
	datagram = append(datagram, p...)
	c.writeMu.Lock()
	_ = st.udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := st.udpConn.WriteTo(datagram, st.relayAddr)
	c.writeMu.Unlock()
	if err != nil {
		if c.reconnecting.Load() {
			// Write failed because old conn was closed during reconnect — retry once.
			return c.WriteTo(p, nil)
		}
		logger.Debug("SOCKS5 UDP write failed: relay=%s err=%v", st.relayAddr, err)
		return 0, err
	}
	return len(p), nil
}

func (c *socks5UDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := socks5UDPBufPool.Get().([]byte)
	defer socks5UDPBufPool.Put(buf)

	for {
		if c.closed.Load() {
			return 0, nil, errors.New("socks5: connection closed")
		}
		if c.remoteClosed.Load() {
			return 0, nil, errors.New("socks5: UDP relay closed")
		}
		st := c.state.Load()
		if st == nil {
			return 0, nil, errors.New("socks5: no connection")
		}
		n, _, err := st.udpConn.ReadFrom(buf)
		if err != nil {
			if c.closed.Load() {
				return 0, nil, err
			}
			if c.reconnecting.Load() {
				// Old conn was closed during reconnect — wait and retry.
				for i := 0; i < 300 && c.reconnecting.Load() && !c.closed.Load() && !c.remoteClosed.Load(); i++ {
					time.Sleep(50 * time.Millisecond)
				}
				continue
			}
			if !isTimeoutError(err) {
				logger.Debug("SOCKS5 UDP read failed: relay=%s err=%v",
					st.relayAddr, err)
			}
			return 0, nil, err
		}
		if n < 3 {
			continue
		}
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

var socks5UDPBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, 65535) },
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

func (c *socks5UDPPacketConn) LocalAddr() net.Addr {
	if st := c.state.Load(); st != nil {
		return st.udpConn.LocalAddr()
	}
	return nil
}

// SetDeadline only sets the read deadline; the write deadline is managed
// internally by WriteTo and udpKeepalive under writeMu.
func (c *socks5UDPPacketConn) SetDeadline(t time.Time) error {
	if st := c.state.Load(); st != nil {
		return st.udpConn.SetReadDeadline(t)
	}
	return errors.New("socks5: no connection")
}

func (c *socks5UDPPacketConn) SetReadDeadline(t time.Time) error {
	if st := c.state.Load(); st != nil {
		return st.udpConn.SetReadDeadline(t)
	}
	return errors.New("socks5: no connection")
}

func (c *socks5UDPPacketConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return nil
	}
	c.readBufferSize.Store(int64(bytes))
	st := c.state.Load()
	if st == nil || st.udpConn == nil {
		return errors.New("socks5: no connection")
	}
	setter, ok := st.udpConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.New("socks5: udp conn does not support SetReadBuffer")
	}
	return setter.SetReadBuffer(bytes)
}

func (c *socks5UDPPacketConn) SetWriteBuffer(bytes int) error {
	if bytes <= 0 {
		return nil
	}
	c.writeBufferSize.Store(int64(bytes))
	st := c.state.Load()
	if st == nil || st.udpConn == nil {
		return errors.New("socks5: no connection")
	}
	setter, ok := st.udpConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return errors.New("socks5: udp conn does not support SetWriteBuffer")
	}
	return setter.SetWriteBuffer(bytes)
}

// SetWriteDeadline is a no-op on socks5UDPPacketConn. The write deadline is
// managed internally by WriteTo (and udpKeepalive) under writeMu, so external
// callers (e.g. RawUDPProxy, chainConnWrapper) setting it would race with the
// internal keepalive's SetWriteDeadline on the same underlying *net.UDPConn.
// In a chain, the outer instance's SetWriteDeadline would propagate to the
// inner instance's raw socket WITHOUT the inner writeMu, creating a race that
// can cause the keepalive's short (2s) deadline to overwrite the write's (5s)
// deadline, leading to false write timeouts and session disconnects.
func (c *socks5UDPPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *socks5UDPPacketConn) Close() error {
	c.closed.Store(true)
	c.closeOnce.Do(func() {
		if c.stopCh != nil {
			close(c.stopCh)
		}
		if st := c.state.Load(); st != nil {
			st.udpConn.Close()
			st.ctrlConn.Close()
		}
	})
	return nil
}

var _ net.PacketConn = (*socks5UDPPacketConn)(nil)
var _ udpSocketBufferConfigurer = (*socks5UDPPacketConn)(nil)

// enableTCPKeepalive enables TCP keepalive on the underlying TCP connection,
// even if wrapped by TLS. This is critical for SOCKS5 UDP ASSOCIATE: without
// keepalive, a silently dropped TCP control connection (server restart, NAT
// timeout, etc.) is never detected, and the UDP relay appears alive while
// silently dropping all traffic.
func enableTCPKeepalive(conn net.Conn, interval time.Duration) {
	var tcpConn *net.TCPConn
	switch c := conn.(type) {
	case *net.TCPConn:
		tcpConn = c
	case interface{ NetConn() net.Conn }: // crypto/tls.Conn
		inner := c.NetConn()
		if tc, ok := inner.(*net.TCPConn); ok {
			tcpConn = tc
		}
	}
	if tcpConn != nil {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(interval)
	}
}

// initSOCKS5 initializes a SOCKS5 outbound. No persistent state is required; the
// association is established per ListenPacket call.
func (s *SingboxOutbound) initSOCKS5(_ *config.ProxyOutbound) error { return nil }

// initHTTP initializes an HTTP proxy outbound. HTTP proxies only support TCP
// (via CONNECT); UDP relay is handled by rejecting it in ListenPacket.
func (s *SingboxOutbound) initHTTP(_ *config.ProxyOutbound) error { return nil }
