package singboxcore

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"mcpeserverproxy/internal/config"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	slog "github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type VLESSUDPPoCOptions struct {
	DialContext DialContextFunc
}

type vlessUDPPoCFactory struct {
	options VLESSUDPPoCOptions
}

func NewVLESSUDPPoCFactory(options VLESSUDPPoCOptions) Factory {
	return &vlessUDPPoCFactory{options: normalizeVLESSUDPPoCOptions(options)}
}

func (f *vlessUDPPoCFactory) CreateUDPOutbound(_ context.Context, cfg *config.ProxyOutbound) (UDPOutbound, error) {
	return NewVLESSUDPOutbound(cfg, f.options)
}

func (f *vlessUDPPoCFactory) CreateDialer(context.Context, *config.ProxyOutbound) (Dialer, error) {
	return nil, ErrNotImplemented
}

type vlessUDPOutbound struct {
	config      *config.ProxyOutbound
	dialContext DialContextFunc
}

func NewVLESSUDPOutbound(cfg *config.ProxyOutbound, options VLESSUDPPoCOptions) (UDPOutbound, error) {
	if cfg == nil {
		return nil, fmt.Errorf("vless udp poc requires outbound config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(strings.ToLower(cfg.Type)) != config.ProtocolVLESS {
		return nil, fmt.Errorf("%w: vless udp poc only supports %s, got %s", ErrNotImplemented, config.ProtocolVLESS, cfg.Type)
	}
	if cfg.TLS || cfg.Reality {
		return nil, fmt.Errorf("%w: vless udp poc only supports plain tcp transport", ErrNotImplemented)
	}
	network := strings.ToLower(strings.TrimSpace(cfg.Network))
	if network != "" && network != "tcp" {
		return nil, fmt.Errorf("%w: vless udp poc only supports tcp network, got %s", ErrNotImplemented, cfg.Network)
	}
	if strings.TrimSpace(cfg.Flow) != "" {
		return nil, fmt.Errorf("%w: vless udp poc does not support flow %q", ErrNotImplemented, cfg.Flow)
	}
	if strings.TrimSpace(cfg.WSPath) != "" || strings.TrimSpace(cfg.WSHost) != "" || strings.TrimSpace(cfg.GRPCServiceName) != "" {
		return nil, fmt.Errorf("%w: vless udp poc does not support ws/grpc transport", ErrNotImplemented)
	}
	options = normalizeVLESSUDPPoCOptions(options)
	return &vlessUDPOutbound{config: cfg.Clone(), dialContext: options.DialContext}, nil
}

func (o *vlessUDPOutbound) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if o == nil || o.config == nil {
		return nil, fmt.Errorf("vless udp poc outbound is not initialized")
	}
	dest, err := parseSocksaddr(destination)
	if err != nil {
		return nil, err
	}
	serverAddress := net.JoinHostPort(o.config.Server, strconv.Itoa(o.config.Port))
	conn, err := o.dialContext(ctx, "tcp", serverAddress)
	if err != nil {
		return nil, fmt.Errorf("vless udp poc dial failed: %w", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	client, err := vless.NewClient(o.config.UUID, "", slog.NOP())
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vless udp poc client init failed: %w", err)
	}
	packetConn, err := client.DialEarlyXUDPPacketConn(conn, dest)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("vless udp poc xudp setup failed: %w", err)
	}
	return &bakedVLESSPacketConn{packetConn: packetConn, destination: dest}, nil
}

func (o *vlessUDPOutbound) Close() error {
	return nil
}

func normalizeVLESSUDPPoCOptions(options VLESSUDPPoCOptions) VLESSUDPPoCOptions {
	if options.DialContext == nil {
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		options.DialContext = dialer.DialContext
	}
	return options
}

func parseSocksaddr(destination string) (M.Socksaddr, error) {
	host, portStr, err := net.SplitHostPort(destination)
	if err != nil {
		return M.Socksaddr{}, fmt.Errorf("invalid destination format: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return M.Socksaddr{}, fmt.Errorf("invalid destination port: %w", err)
	}
	if port < 0 || port > 65535 {
		return M.Socksaddr{}, fmt.Errorf("invalid destination port: %d", port)
	}
	if ip := net.ParseIP(host); ip != nil {
		return M.SocksaddrFrom(M.AddrFromIP(ip), uint16(port)), nil
	}
	return M.ParseSocksaddrHostPort(host, uint16(port)), nil
}

type bakedVLESSPacketConn struct {
	packetConn  vmess.PacketConn
	destination M.Socksaddr
}

func (c *bakedVLESSPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.NewPacket()
	defer buffer.Release()
	dest, err := c.packetConn.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, buffer.Bytes())
	return n, dest.UDPAddr(), nil
}

func (c *bakedVLESSPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	const headerReserve = 64
	const tailReserve = 64
	totalSize := headerReserve + len(p) + tailReserve
	buffer := buf.NewSize(totalSize)
	buffer.Resize(headerReserve, 0)
	_, err = buffer.Write(p)
	if err != nil {
		buffer.Release()
		return 0, fmt.Errorf("failed to write payload buffer: %w", err)
	}
	err = c.packetConn.WritePacket(buffer, c.destination)
	if err != nil {
		buffer.Release()
		return 0, err
	}
	return len(p), nil
}

func (c *bakedVLESSPacketConn) Close() error {
	return c.packetConn.Close()
}

func (c *bakedVLESSPacketConn) LocalAddr() net.Addr {
	return c.packetConn.LocalAddr()
}

func (c *bakedVLESSPacketConn) SetDeadline(t time.Time) error {
	return c.packetConn.SetDeadline(t)
}

func (c *bakedVLESSPacketConn) SetReadDeadline(t time.Time) error {
	return c.packetConn.SetReadDeadline(t)
}

func (c *bakedVLESSPacketConn) SetWriteDeadline(t time.Time) error {
	return c.packetConn.SetWriteDeadline(t)
}
