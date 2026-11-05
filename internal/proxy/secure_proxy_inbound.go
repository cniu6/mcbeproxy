package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	mcommon "github.com/enfein/mieru/v3/apis/common"
	mm "github.com/enfein/mieru/v3/apis/model"
	ms "github.com/enfein/mieru/v3/apis/server"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mq "github.com/metacubex/quic-go"
	mh "github.com/metacubex/sing-quic/hysteria2"
	ma "github.com/metacubex/sing/common/auth"
	mb "github.com/metacubex/sing/common/buf"
	ml "github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	mt "github.com/metacubex/tls"
	"google.golang.org/protobuf/proto"
	"mcpeserverproxy/internal/config"
)

var ErrSecureProxyBusy = errors.New("入口有活动连接，请等待空闲或显式停用后修改")

// 安全协议只负责认证与承载，用户权限、出口选择仍由原代理端口拥有。
type securePortRuntime struct {
	owner      *proxyPortListener
	identities *SecureIdentityStore
	mu         sync.Mutex
	stopped    bool
	active     int
	udp        int
	tracked    map[io.Closer]struct{}
	wg         sync.WaitGroup
	hy         *mh.Service[string]
	mieru      ms.Server
	socket     net.PacketConn
	admission  *secureAdmission
}

func (r *securePortRuntime) Start() error {
	cfg := r.owner.cfg
	limits := cfg.Secure.Limits
	r.tracked = make(map[io.Closer]struct{})
	r.admission = newSecureAdmission(limits.MaxConnections, time.Duration(limits.HandshakeSeconds)*time.Second)
	if cfg.Type == config.ProxyPortTypeHysteria2 {
		pair, _, err := r.identities.Load(cfg.Secure.IdentityID)
		if err != nil {
			return err
		}
		cert := mt.Certificate{Certificate: pair.Certificate, PrivateKey: pair.PrivateKey, Leaf: pair.Leaf}
		service, err := mh.NewService[string](mh.ServiceOptions{Context: r.owner.ctx, Logger: ml.NOP(), TLSConfig: &mt.Config{Certificates: []mt.Certificate{cert}, MinVersion: tls.VersionTLS13, GetConfigForClient: r.admission.tlsConfig}, QUICConfig: &mq.Config{HandshakeIdleTimeout: time.Duration(limits.HandshakeSeconds) * time.Second, MaxIncomingStreams: int64(limits.MaxConnections)}, Handler: r, UdpMTU: 1200, UDPTimeout: time.Duration(limits.IdleSeconds) * time.Second, IgnoreClientBandwidth: true})
		if err != nil {
			return err
		}
		users, passwords := r.credentials()
		service.UpdateUsers(users, passwords)
		socket, err := net.ListenPacket("udp", cfg.ListenAddr)
		if err != nil {
			return err
		}
		if err := service.Start(socket); err != nil {
			socket.Close()
			return err
		}
		r.hy, r.socket = service, socket
		return nil
	}
	host, ps, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(ps)
	users, _ := r.credentials()
	pbUsers := make([]*pb.User, 0, len(users))
	for _, u := range users {
		pbUsers = append(pbUsers, &pb.User{Name: proto.String(u), Password: proto.String(r.password(u))})
	}
	server := ms.NewServer()
	if err := server.Store(&ms.ServerConfig{StreamListenerFactory: r.admission, Config: &pb.ServerConfig{ListenIPAddress: proto.String(host), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: pb.TransportProtocol_TCP.Enum()}}, Users: pbUsers}}); err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return err
	}
	r.mieru = server
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, request, err := server.Accept()
			if err != nil {
				if r.owner.ctx.Err() != nil {
					return
				}
				continue
			}
			udp := request.Command == 3
			if request.Command != 1 && !udp {
				c.Close()
				continue
			}
			if err := r.begin(c, udp); err != nil {
				c.Close()
				continue
			}
			go func() {
				defer r.end(c, udp)
				defer c.Close()
				user := c.(mcommon.UserContext).UserName()
				id, err := r.identity(user, c.RemoteAddr(), udp)
				if err != nil {
					_ = mm.WriteSocks5Response(c, 2, mm.AddrSpec{IP: net.IPv4zero})
					return
				}
				defer id.release()
				if udp {
					if mm.WriteSocks5Response(c, 0, mm.AddrSpec{IP: net.IPv4zero}) == nil {
						r.forwardUDP(id, mcommon.NewUDPAssociateWrapper(mcommon.NewPacketOverStreamTunnel(c)))
					}
					return
				}
				ctx, cancel := context.WithTimeout(r.owner.ctx, time.Duration(limits.HandshakeSeconds)*time.Second)
				defer cancel()
				up, err := r.dial(ctx, id, request.DstAddr.String())
				if err != nil {
					_ = mm.WriteSocks5Response(c, 5, mm.AddrSpec{IP: net.IPv4zero})
					return
				}
				if !r.track(up) {
					return
				}
				defer r.untrack(up)
				if mm.WriteSocks5Response(c, 0, mm.AddrSpec{IP: net.IPv4zero}) == nil {
					r.copyTCP(id, c, up)
				}
			}()
		}
	}()
	return nil
}
func (r *securePortRuntime) credentials() ([]string, []string) {
	cfg := r.owner.cfg
	users := []string{cfg.Username}
	passwords := []string{cfg.Username + ":" + cfg.Password}
	for _, u := range cfg.Users {
		if !u.Disabled {
			users = append(users, u.Username)
			passwords = append(passwords, u.Username+":"+u.Password)
		}
	}
	return users, passwords
}
func (r *securePortRuntime) password(user string) string {
	cfg := r.owner.cfg
	if user == cfg.Username {
		return cfg.Password
	}
	for _, u := range cfg.Users {
		if u.Username == user {
			return u.Password
		}
	}
	return ""
}
func (r *securePortRuntime) identity(user string, source net.Addr, udp bool) (*proxyPortIdentity, error) {
	if !r.owner.isAllowed(source) {
		return nil, errors.New("来源地址被入口规则拒绝")
	}
	id, err := r.owner.authTable().authenticate(user, r.password(user), source)
	if err != nil {
		return nil, err
	}
	if udp && id.disableUDP {
		id.reject("UDP disabled")
		return nil, errors.New("用户禁止UDP")
	}
	if err := id.acquire(); err != nil {
		return nil, err
	}
	return id, nil
}
func (r *securePortRuntime) dial(ctx context.Context, id *proxyPortIdentity, target string) (net.Conn, error) {
	route, blocked := routeFor(id, target)
	if blocked {
		return nil, errors.New("目标被路由规则拒绝")
	}
	c, _, err := r.owner.dialRoute(ctx, route, target)
	return c, err
}
func (r *securePortRuntime) begin(c io.Closer, udp bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.owner.cfg.Secure.Limits
	if r.stopped {
		return net.ErrClosed
	}
	if r.active >= l.MaxConnections || udp && r.udp >= l.MaxUDPAssociations {
		return errors.New("入口连接已达上限")
	}
	r.active++
	if udp {
		r.udp++
	}
	r.tracked[c] = struct{}{}
	r.wg.Add(1)
	return nil
}
func (r *securePortRuntime) end(c io.Closer, udp bool) {
	r.untrack(c)
	r.mu.Lock()
	r.active--
	if udp {
		r.udp--
	}
	r.mu.Unlock()
	r.wg.Done()
}
func (r *securePortRuntime) track(c io.Closer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		c.Close()
		return false
	}
	r.tracked[c] = struct{}{}
	return true
}
func (r *securePortRuntime) untrack(c io.Closer) {
	c.Close()
	r.mu.Lock()
	delete(r.tracked, c)
	r.mu.Unlock()
}
func (r *securePortRuntime) ActiveConnections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

// 预检之后仍在这里关闸，避免新流恰好进入导致保存误杀活动连接。
func (r *securePortRuntime) freezeIfIdle() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != 0 {
		return ErrSecureProxyBusy
	}
	r.stopped = true
	return nil
}
func (r *securePortRuntime) Stop(wait bool) {
	r.mu.Lock()
	r.stopped = true
	all := make([]io.Closer, 0, len(r.tracked))
	for c := range r.tracked {
		all = append(all, c)
	}
	r.mu.Unlock()
	if r.admission != nil {
		r.admission.Close()
	}
	if r.hy != nil {
		_ = r.hy.Close()
	}
	if r.socket != nil {
		_ = r.socket.Close()
	}
	if r.mieru != nil {
		_ = r.mieru.Stop()
	}
	for _, c := range all {
		c.Close()
	}
	if wait {
		r.wg.Wait()
	}
}
func (r *securePortRuntime) NewConnection(ctx context.Context, c net.Conn, meta M.Metadata) error {
	if err := r.begin(c, false); err != nil {
		c.Close()
		return err
	}
	defer r.end(c, false)
	user, ok := ma.UserFromContext[string](ctx)
	if !ok {
		return errors.New("缺少认证用户")
	}
	id, err := r.identity(user, meta.Source, false)
	if err != nil {
		N.ReportHandshakeFailure(c, err)
		return err
	}
	defer id.release()
	dialCtx, cancel := context.WithTimeout(r.owner.ctx, time.Duration(r.owner.cfg.Secure.Limits.HandshakeSeconds)*time.Second)
	defer cancel()
	up, err := r.dial(dialCtx, id, meta.Destination.String())
	if err != nil {
		N.ReportHandshakeFailure(c, err)
		return err
	}
	if !r.track(up) {
		return net.ErrClosed
	}
	defer r.untrack(up)
	if err := N.ReportHandshakeSuccess(c); err != nil {
		return err
	}
	r.copyTCP(id, c, up)
	return nil
}
func (r *securePortRuntime) NewPacketConnection(ctx context.Context, c N.PacketConn, meta M.Metadata) error {
	if err := r.begin(c, true); err != nil {
		c.Close()
		return err
	}
	defer r.end(c, true)
	user, ok := ma.UserFromContext[string](ctx)
	if !ok {
		return errors.New("缺少认证用户")
	}
	id, err := r.identity(user, meta.Source, true)
	if err != nil {
		return err
	}
	defer id.release()
	r.forwardUDP(id, &secureSingPacket{PacketConn: c})
	return nil
}
func (r *securePortRuntime) copyTCP(id *proxyPortIdentity, a, b net.Conn) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-r.owner.ctx.Done():
				a.Close()
				b.Close()
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, last.Load())) >= time.Duration(r.owner.cfg.Secure.Limits.IdleSeconds)*time.Second {
					a.Close()
					b.Close()
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn, up bool) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				written, we := dst.Write(buf[:n])
				if up {
					id.addBytes(int64(written), 0)
				} else {
					id.addBytes(0, int64(written))
				}
				if we != nil {
					a.Close()
					b.Close()
					return
				}
			}
			if err != nil {
				if h, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = h.CloseWrite()
				} else {
					dst.Close()
				}
				return
			}
		}
	}
	go copyOne(b, a, true)
	go copyOne(a, b, false)
	wg.Wait()
	close(done)
}

// 每个认证关联持有自己的目标连接；只在首次访问时选择出口，不逐包改源端口。
func (r *securePortRuntime) forwardUDP(id *proxyPortIdentity, client net.PacketConn) {
	type target struct {
		pc        net.PacketConn
		addr      net.Addr
		connected bool
	}
	targets := make(map[string]target)
	var wg sync.WaitGroup
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer func() {
		close(done)
		client.Close()
		for _, v := range targets {
			v.pc.Close()
		}
		wg.Wait()
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-r.owner.ctx.Done():
				client.Close()
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, last.Load())) >= time.Duration(r.owner.cfg.Secure.Limits.IdleSeconds)*time.Second {
					client.Close()
					return
				}
			}
		}
	}()
	var writes sync.Mutex
	buf := make([]byte, 65535)
	for {
		n, address, err := client.ReadFrom(buf)
		if err != nil {
			return
		}
		if n > 65507 || address == nil {
			continue
		}
		key := address.String()
		if _, blocked := routeFor(id, key); blocked {
			continue
		}
		v, ok := targets[key]
		if !ok {
			if len(targets) >= 64 {
				continue
			}
			pc, err := r.owner.dialUDPFor(id, key)
			if err != nil {
				continue
			}
			if !r.track(pc) {
				return
			}
			_, connected := pc.(*net.UDPConn)
			v = target{pc: pc, addr: address, connected: connected}
			targets[key] = v
			wg.Add(1)
			go func(v target) {
				defer wg.Done()
				defer r.untrack(v.pc)
				reply := make([]byte, 65535)
				for {
					n, _, err := v.pc.ReadFrom(reply)
					if err != nil {
						return
					}
					last.Store(time.Now().UnixNano())
					writes.Lock()
					_ = client.SetWriteDeadline(time.Now().Add(time.Second))
					written, err := client.WriteTo(reply[:n], v.addr)
					writes.Unlock()
					id.addBytes(0, int64(written))
					if err != nil {
						if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
							return
						}
					}
				}
			}(v)
		}
		last.Store(time.Now().UnixNano())
		_ = v.pc.SetWriteDeadline(time.Now().Add(time.Second))
		var written int
		if v.connected {
			written, err = v.pc.(*net.UDPConn).Write(buf[:n])
		} else {
			written, err = v.pc.WriteTo(buf[:n], v.addr)
		}
		id.addBytes(int64(written), 0)
		// 超时/逐包拥塞只丢本包，不能关闭认证会话或迁移关联。
		if err != nil {
			continue
		}
	}
}

type secureSingPacket struct{ N.PacketConn }

func (c *secureSingPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	buffer := mb.NewSize(65535)
	defer buffer.Release()
	addr, err := c.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	if buffer.Len() > len(b) {
		return 0, nil, io.ErrShortBuffer
	}
	if addr.IsIP() {
		return copy(b, buffer.Bytes()), addr.UDPAddr(), nil
	}
	return copy(b, buffer.Bytes()), addr, nil
}
func (c *secureSingPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	buffer := mb.NewSize(len(b))
	_, _ = buffer.Write(b)
	if err := c.WritePacket(buffer, M.SocksaddrFromNet(a)); err != nil {
		return 0, err
	}
	return len(b), nil
}
