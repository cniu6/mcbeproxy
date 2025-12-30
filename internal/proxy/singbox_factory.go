// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"

	hy2 "github.com/apernet/hysteria/core/v2/client"
	hy2obfs "github.com/apernet/hysteria/extras/v2/obfs"
	utls "github.com/metacubex/utls"
	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	slog "github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	anytls "github.com/anytls/sing-anytls"
)

// SingboxOutbound wraps a sing protocol client for UDP connections.
type SingboxOutbound struct {
	config          *config.ProxyOutbound
	dialer          N.Dialer
	ssMethod        ssMethod
	ssKey           []byte                                // Shadowsocks master key
	ssKeyLen        int                                   // Key/salt length
	ssCipher        func(key []byte) (cipher.AEAD, error) // Cipher constructor
	hy2Client       hy2.Client
	hy2Mu           sync.Mutex // Protects hy2Client for reconnection
	anytlsClient    *anytls.Client
	anytlsUOTClient *uot.Client
	// Hysteria2 uses per-destination UDP connections
	// Each destination gets its own HyUDPConn to avoid demultiplexing issues
}

// ssMethod is an interface for Shadowsocks methods that support UDP.
type ssMethod interface {
	DialPacketConn(conn net.Conn) N.NetPacketConn
}

// ErrUnsupportedProtocol is returned when the protocol type is not supported.
var ErrUnsupportedProtocol = errors.New("unsupported protocol type")

// ErrOutboundCreationFailed is returned when outbound creation fails.
var ErrOutboundCreationFailed = errors.New("failed to create sing-box outbound")

// directDialer implements N.Dialer for direct connections.
type directDialer struct {
	timeout time.Duration
}

func (d *directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: d.timeout,
	}
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *directDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

var _ N.Dialer = (*directDialer)(nil)

type anytlsProxyDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func (d anytlsProxyDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d anytlsProxyDialer) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("anytls dialer does not support ListenPacket")
}

var _ N.Dialer = (anytlsProxyDialer)(nil)

// CreateSingboxOutbound creates a sing-box outbound adapter from a ProxyOutbound config.
// Requirements: 1.2, 3.1, 3.2
func CreateSingboxOutbound(cfg *config.ProxyOutbound) (*SingboxOutbound, error) {
	if cfg == nil {
		return nil, errors.New("proxy outbound configuration cannot be nil")
	}

	outbound := &SingboxOutbound{
		config: cfg,
		dialer: &directDialer{timeout: 30 * time.Second},
	}

	var err error
	switch cfg.Type {
	case config.ProtocolShadowsocks:
		err = outbound.initShadowsocks(cfg)
	case config.ProtocolVMess:
		err = outbound.initVMess(cfg)
	case config.ProtocolTrojan:
		err = outbound.initTrojan(cfg)
	case config.ProtocolVLESS:
		err = outbound.initVLESS(cfg)
	case config.ProtocolHysteria2:
		err = outbound.initHysteria2(cfg)
	case config.ProtocolAnyTLS:
		err = outbound.initAnyTLS(cfg)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, cfg.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOutboundCreationFailed, err)
	}

	return outbound, nil
}

// initShadowsocks initializes a Shadowsocks method.
func (s *SingboxOutbound) initShadowsocks(cfg *config.ProxyOutbound) error {
	method := cfg.Method
	password := cfg.Password

	// Check if it's a 2022 method
	if is2022Method(method) {
		m, err := shadowaead_2022.NewWithPassword(method, password, nil)
		if err != nil {
			return fmt.Errorf("failed to create shadowsocks 2022 method: %w", err)
		}
		s.ssMethod = m
		// 2022 methods use different key derivation, not supported for native UDP yet
		return nil
	}

	// Standard AEAD methods
	m, err := shadowaead.New(method, nil, password)
	if err != nil {
		return fmt.Errorf("failed to create shadowsocks method: %w", err)
	}
	s.ssMethod = m

	// Store key and cipher info for native UDP
	switch method {
	case "aes-128-gcm":
		s.ssKeyLen = 16
		s.ssCipher = func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	case "aes-192-gcm":
		s.ssKeyLen = 24
		s.ssCipher = func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	case "aes-256-gcm":
		s.ssKeyLen = 32
		s.ssCipher = func(key []byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}
	case "chacha20-ietf-poly1305":
		s.ssKeyLen = 32
		s.ssCipher = chacha20poly1305.New
	case "xchacha20-ietf-poly1305":
		s.ssKeyLen = 32
		s.ssCipher = chacha20poly1305.NewX
	default:
		return fmt.Errorf("unsupported shadowsocks method: %s", method)
	}

	// Derive master key from password
	s.ssKey = shadowsocks.Key([]byte(password), s.ssKeyLen)

	return nil
}

// is2022Method checks if the method is a Shadowsocks 2022 method.
func is2022Method(method string) bool {
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	default:
		return false
	}
}

// initVMess initializes a VMess client.
func (s *SingboxOutbound) initVMess(_ *config.ProxyOutbound) error {
	// VMess initialization is done at connection time
	return nil
}

// initTrojan initializes a Trojan client.
func (s *SingboxOutbound) initTrojan(_ *config.ProxyOutbound) error {
	// Trojan uses password-based authentication over TLS
	// The actual connection is established in ListenPacket
	return nil
}

// initVLESS initializes a VLESS client.
func (s *SingboxOutbound) initVLESS(_ *config.ProxyOutbound) error {
	// VLESS uses UUID-based authentication
	// The actual connection is established in ListenPacket
	return nil
}

// hy2ObfsConnFactory wraps a ConnFactory with obfuscation.
type hy2ObfsConnFactory struct {
	obfs hy2obfs.Obfuscator
}

func (f *hy2ObfsConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	if f.obfs != nil {
		return hy2obfs.WrapPacketConn(conn, f.obfs), nil
	}
	return conn, nil
}

// parsePortRange parses a port range string like "20000-55000" into start and end ports.
func parsePortRange(portRange string) (start, end int, err error) {
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format: %s (expected start-end)", portRange)
	}

	start, err = net.LookupPort("udp", strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port: %w", err)
	}

	end, err = net.LookupPort("udp", strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port: %w", err)
	}

	if start > end {
		return 0, 0, fmt.Errorf("start port %d is greater than end port %d", start, end)
	}

	return start, end, nil
}

// hy2PortHoppingConnFactory implements port hopping for Hysteria2.
// It creates UDP connections that hop between ports at specified intervals.
type hy2PortHoppingConnFactory struct {
	serverIP    net.IP
	portStart   int
	portEnd     int
	hopInterval time.Duration
	obfs        hy2obfs.Obfuscator
}

// New creates a new port-hopping UDP connection.
func (f *hy2PortHoppingConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	// Create base UDP connection
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	// Wrap with obfuscation if configured
	var baseConn net.PacketConn = conn
	if f.obfs != nil {
		baseConn = hy2obfs.WrapPacketConn(conn, f.obfs)
	}

	// If port hopping is enabled, wrap with port hopping
	if f.portStart > 0 && f.portEnd > 0 && f.portStart < f.portEnd {
		return &portHoppingPacketConn{
			PacketConn:  baseConn,
			serverIP:    f.serverIP,
			portStart:   f.portStart,
			portEnd:     f.portEnd,
			hopInterval: f.hopInterval,
			currentPort: f.selectRandomPort(),
			lastHop:     time.Now(),
		}, nil
	}

	return baseConn, nil
}

// selectRandomPort selects a random port from the range.
func (f *hy2PortHoppingConnFactory) selectRandomPort() int {
	portRange := f.portEnd - f.portStart + 1
	return f.portStart + int(time.Now().UnixNano()%int64(portRange))
}

// portHoppingPacketConn wraps a PacketConn with port hopping capability.
type portHoppingPacketConn struct {
	net.PacketConn
	serverIP    net.IP
	portStart   int
	portEnd     int
	hopInterval time.Duration
	currentPort int
	lastHop     time.Time
	mu          sync.Mutex
}

// WriteTo writes data with port hopping.
func (c *portHoppingPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	// Check if we need to hop to a new port
	if time.Since(c.lastHop) >= c.hopInterval {
		oldPort := c.currentPort
		portRange := c.portEnd - c.portStart + 1
		c.currentPort = c.portStart + int(time.Now().UnixNano()%int64(portRange))
		c.lastHop = time.Now()
		logger.Debug("Hysteria2 port hop: %d -> %d", oldPort, c.currentPort)
	}
	targetAddr := &net.UDPAddr{IP: c.serverIP, Port: c.currentPort}
	c.mu.Unlock()

	return c.PacketConn.WriteTo(p, targetAddr)
}

// initHysteria2 initializes a Hysteria2 client with full port hopping and TLS support.
func (s *SingboxOutbound) initHysteria2(cfg *config.ProxyOutbound) error {
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)

	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return fmt.Errorf("invalid server address: %w", err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Resolve host - prefer IPv4
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("no IP addresses found for host")
	}

	var serverIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			serverIP = ip
			break
		}
	}
	if serverIP == nil {
		serverIP = ips[0]
	}

	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}

	// Parse multi-port range for port hopping
	var portStart, portEnd int
	if cfg.PortHopping != "" && strings.Contains(cfg.PortHopping, "-") {
		portStart, portEnd, err = parsePortRange(cfg.PortHopping)
		if err != nil {
			return fmt.Errorf("invalid port range: %w", err)
		}
		logger.Info("Hysteria2: port hopping enabled, range %d-%d", portStart, portEnd)
	}

	// Port hopping interval (default 10 seconds)
	hopInterval := 10 * time.Second
	if cfg.HopInterval > 0 {
		hopInterval = time.Duration(cfg.HopInterval) * time.Second
	}

	// Parse obfuscation
	var obfs hy2obfs.Obfuscator
	if cfg.Obfs == "salamander" && cfg.ObfsPassword != "" {
		obfs, err = hy2obfs.NewSalamanderObfuscator([]byte(cfg.ObfsPassword))
		if err != nil {
			return fmt.Errorf("failed to create obfuscator: %w", err)
		}
		logger.Info("Hysteria2: salamander obfuscation enabled")
	}

	// Parse ALPN
	var alpnProtocols []string
	if cfg.ALPN != "" {
		alpnProtocols = strings.Split(cfg.ALPN, ",")
		for i := range alpnProtocols {
			alpnProtocols[i] = strings.TrimSpace(alpnProtocols[i])
		}
	} else {
		alpnProtocols = []string{"h3"} // Default ALPN for Hysteria2
	}

	// Bandwidth configuration
	upMbps := 100 // Default 100 Mbps
	downMbps := 100
	if cfg.UpMbps > 0 {
		upMbps = cfg.UpMbps
	}
	if cfg.DownMbps > 0 {
		downMbps = cfg.DownMbps
	}

	logger.Info("Hysteria2: init client %s:%d (IP: %s), SNI=%s, insecure=%v, ALPN=%v, bandwidth=%d/%d Mbps",
		cfg.Server, cfg.Port, serverIP, sni, cfg.Insecure, alpnProtocols, upMbps, downMbps)

	// Store config for reconnection
	s.config = cfg

	// Create connection factory with port hopping support
	connFactory := &hy2PortHoppingConnFactory{
		serverIP:    serverIP,
		portStart:   portStart,
		portEnd:     portEnd,
		hopInterval: hopInterval,
		obfs:        obfs,
	}

	// Parse certificate fingerprint for pinning
	var certFingerprint []byte
	if cfg.CertFingerprint != "" {
		certFingerprint, err = hex.DecodeString(strings.ReplaceAll(cfg.CertFingerprint, ":", ""))
		if err != nil {
			return fmt.Errorf("invalid certificate fingerprint: %w", err)
		}
		if len(certFingerprint) != 32 {
			return fmt.Errorf("certificate fingerprint must be SHA256 (32 bytes), got %d bytes", len(certFingerprint))
		}
		logger.Info("Hysteria2: certificate pinning enabled")
	}

	// Create reconnectable client
	hy2Client, err := hy2.NewReconnectableClient(
		func() (*hy2.Config, error) {
			// Select initial port - use port hopping range if configured
			selectedPort := port
			if portStart > 0 && portEnd > 0 {
				portRange := portEnd - portStart + 1
				selectedPort = portStart + int(time.Now().UnixNano()%int64(portRange))
				logger.Debug("Hysteria2: initial port %d from range %d-%d", selectedPort, portStart, portEnd)
			}

			hy2Config := &hy2.Config{
				ServerAddr:  &net.UDPAddr{IP: serverIP, Port: selectedPort},
				Auth:        cfg.Password,
				ConnFactory: connFactory,
				TLSConfig: hy2.TLSConfig{
					ServerName:         sni,
					InsecureSkipVerify: cfg.Insecure,
				},
				QUICConfig: hy2.QUICConfig{
					InitialStreamReceiveWindow:     4 * 1024 * 1024,
					MaxStreamReceiveWindow:         8 * 1024 * 1024,
					InitialConnectionReceiveWindow: 8 * 1024 * 1024,
					MaxConnectionReceiveWindow:     16 * 1024 * 1024,
					MaxIdleTimeout:                 90 * time.Second, // Increased from 60s to reduce reconnection frequency
					KeepAlivePeriod:                30 * time.Second, // Increased from 15s to reduce CPU usage
					DisablePathMTUDiscovery:        cfg.DisableMTU,
				},
				BandwidthConfig: hy2.BandwidthConfig{
					MaxTx: uint64(upMbps) * 1024 * 1024 / 8,   // Convert Mbps to bytes/s
					MaxRx: uint64(downMbps) * 1024 * 1024 / 8, // Convert Mbps to bytes/s
				},
			}

			// Certificate fingerprint pinning via VerifyPeerCertificate
			if len(certFingerprint) > 0 {
				hy2Config.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return errors.New("no certificate provided by server")
					}
					// Calculate SHA256 fingerprint of the first certificate
					hash := sha256.Sum256(rawCerts[0])
					if !bytes.Equal(hash[:], certFingerprint) {
						return fmt.Errorf("certificate fingerprint mismatch: expected %x, got %x",
							certFingerprint, hash[:])
					}
					logger.Debug("Hysteria2: certificate fingerprint verified")
					return nil
				}
			}

			return hy2Config, nil
		},
		func(c hy2.Client, info *hy2.HandshakeInfo, count int) {
			if info != nil {
				logger.Info("Hysteria2: connected (attempt %d), UDP=%v, Tx=%d bps",
					count, info.UDPEnabled, info.Tx)
				if !info.UDPEnabled {
					logger.Error("Hysteria2: Server UDP relay DISABLED! Check server config.")
				}
			}
		},
		true, // lazy connection
	)
	if err != nil {
		return fmt.Errorf("failed to create hysteria2 client: %w", err)
	}

	s.hy2Client = hy2Client
	return nil
}

// initAnyTLS initializes an AnyTLS client with TLS support.
func (s *SingboxOutbound) initAnyTLS(cfg *config.ProxyOutbound) error {
	if !cfg.TLS {
		return errors.New("anytls requires tls enabled")
	}

	serverAddr := M.ParseSocksaddrHostPort(cfg.Server, uint16(cfg.Port))

	dialOut := func(ctx context.Context) (net.Conn, error) {
		conn, err := s.dialer.DialContext(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		tlsConn, err := dialTLSWithFingerprint(ctx, conn, cfg)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: cfg.Password,
		DialOut:  dialOut,
		Logger:   slog.NOP(),
	})
	if err != nil {
		return err
	}

	s.anytlsClient = client
	s.anytlsUOTClient = &uot.Client{
		Dialer:  anytlsProxyDialer(client.CreateProxy),
		Version: uot.Version,
	}
	return nil
}

// ListenPacket creates a UDP PacketConn through the sing-box outbound.
// The destination should be in the format "host:port".
// Requirements: 3.1, 3.3, 3.4
func (s *SingboxOutbound) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	if s.config == nil {
		return nil, errors.New("outbound configuration is nil")
	}

	// Parse destination
	dest, err := parseDestination(destination)
	if err != nil {
		return nil, fmt.Errorf("failed to parse destination: %w", err)
	}

	// Get server address
	serverAddr := M.ParseSocksaddrHostPort(s.config.Server, uint16(s.config.Port))

	switch s.config.Type {
	case config.ProtocolShadowsocks:
		return s.dialShadowsocksUDP(ctx, serverAddr, dest)
	case config.ProtocolVMess:
		return s.dialVMessUDP(ctx, serverAddr, dest)
	case config.ProtocolTrojan:
		return s.dialTrojanUDP(ctx, serverAddr, dest)
	case config.ProtocolVLESS:
		return s.dialVLESSUDP(ctx, serverAddr, dest)
	case config.ProtocolHysteria2:
		return s.dialHysteria2UDP(ctx, serverAddr, dest)
	case config.ProtocolAnyTLS:
		return s.dialAnyTLSUDP(ctx, serverAddr, dest)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, s.config.Type)
	}
}

// dialShadowsocksUDP creates a UDP connection through Shadowsocks using native UDP.
func (s *SingboxOutbound) dialShadowsocksUDP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.PacketConn, error) {
	// Use native UDP only
	if s.ssKey == nil || s.ssCipher == nil {
		return nil, errors.New("shadowsocks native UDP not initialized (2022 methods not supported)")
	}

	// Resolve server address
	serverUDPAddr, err := net.ResolveUDPAddr("udp", serverAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	// Create UDP socket
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	logger.Debug("Shadowsocks: native UDP to %s for destination %s", serverUDPAddr, dest)

	return &ssNativeUDPPacketConn{
		UDPConn:     udpConn,
		serverAddr:  serverUDPAddr,
		destination: dest,
		key:         s.ssKey,
		keySaltLen:  s.ssKeyLen,
		constructor: s.ssCipher,
	}, nil
}

// dialVMessUDP creates a UDP connection through VMess using sing-vmess library.
func (s *SingboxOutbound) dialVMessUDP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.PacketConn, error) {
	// Create TCP connection to server
	conn, err := s.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}

	// Apply TLS if configured
	if s.config.TLS {
		tlsConn, err := dialTLSWithFingerprint(ctx, conn, s.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	// Apply WebSocket transport if configured
	if s.config.Network == "ws" {
		wsConn, err := upgradeToWebSocket(conn, s.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("WebSocket upgrade failed: %w", err)
		}
		conn = wsConn
	}

	// Create VMess client using sing-vmess library
	security := s.config.Security
	if security == "" || security == "auto" {
		security = "aes-128-gcm"
	}
	client, err := vmess.NewClient(s.config.UUID, security, s.config.AlterID)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create vmess client: %w", err)
	}

	// Use DialEarlyPacketConn for UDP - this properly handles VMess UDP protocol
	packetConn := client.DialEarlyPacketConn(conn, dest)

	return &vmessPacketConn{
		packetConn:  packetConn,
		destination: dest,
	}, nil
}

// dialTLSWithFingerprint establishes a TLS connection with optional uTLS fingerprint support.
func dialTLSWithFingerprint(ctx context.Context, conn net.Conn, cfg *config.ProxyOutbound) (net.Conn, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}

	// If fingerprint is specified, use uTLS for better compatibility
	if cfg.Fingerprint != "" {
		fingerprint := getUTLSFingerprint(cfg.Fingerprint)
		utlsConfig := &utls.Config{
			ServerName:         sni,
			InsecureSkipVerify: cfg.Insecure,
		}
		utlsConn := utls.UClient(conn, utlsConfig, fingerprint)
		if err := utlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		logger.Debug("TLS: connected with uTLS fingerprint %s to %s", cfg.Fingerprint, sni)
		return utlsConn, nil
	}

	// Standard TLS
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: cfg.Insecure,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	logger.Debug("TLS: connected to %s", sni)
	return tlsConn, nil
}

// dialTrojanUDP creates a UDP connection through Trojan.
func (s *SingboxOutbound) dialTrojanUDP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.PacketConn, error) {
	// Trojan UDP uses TCP connection, optionally with TLS
	conn, err := s.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	var finalConn net.Conn = conn

	// Apply TLS only if enabled (security != none)
	if s.config.TLS {
		tlsConn, err := dialTLSWithFingerprint(ctx, conn, s.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		finalConn = tlsConn
	}

	// Send Trojan handshake for UDP
	if err := writeTrojanHandshake(finalConn, s.config.Password, dest, true); err != nil {
		finalConn.Close()
		return nil, fmt.Errorf("trojan handshake failed: %w", err)
	}

	return &trojanPacketConn{
		Conn:        finalConn,
		r:           bufio.NewReaderSize(finalConn, 32*1024),
		destination: dest,
	}, nil
}

// dialAnyTLSUDP creates a UDP connection through AnyTLS.
// AnyTLS transports UDP via UoT (UDP over TCP).
func (s *SingboxOutbound) dialAnyTLSUDP(ctx context.Context, _, dest M.Socksaddr) (net.PacketConn, error) {
	if s.anytlsUOTClient == nil {
		return nil, errors.New("anytls client not initialized")
	}
	return s.anytlsUOTClient.ListenPacket(ctx, dest)
}

// dialVLESSUDP creates a UDP connection through VLESS using sing-vmess/vless library.
func (s *SingboxOutbound) dialVLESSUDP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.PacketConn, error) {
	// VLESS UDP uses TCP connection
	conn, err := s.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Determine if we're using Vision flow
	isVisionFlow := strings.Contains(strings.ToLower(s.config.Flow), "vision")

	// Apply TLS/Reality
	if s.config.Reality {
		realityConn, err := dialRealityTLS(ctx, conn, s.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("Reality handshake failed: %w", err)
		}
		conn = realityConn
	} else if s.config.TLS {
		// For Vision flow, we need to use uTLS with specific handling
		if isVisionFlow && s.config.Fingerprint != "" {
			tlsConn, err := dialVisionTLS(ctx, conn, s.config)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("Vision TLS handshake failed: %w", err)
			}
			conn = tlsConn
		} else {
			tlsConn, err := dialTLSWithFingerprint(ctx, conn, s.config)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}
			conn = tlsConn
		}
	}

	// Determine flow to use
	// For Vision nodes, UDP still needs the Vision flow so that the underlying
	// connection is wrapped with the XTLS Vision transport (XUDP runs on top of it).
	flow := ""
	if isVisionFlow {
		flow = s.config.Flow
	}

	// Create VLESS client using sing-vmess/vless library
	client, err := vless.NewClient(s.config.UUID, flow, slog.NOP())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create vless client: %w", err)
	}

	// Use DialEarlyXUDPPacketConn for UDP - this properly handles VLESS XUDP protocol
	packetConn, err := client.DialEarlyXUDPPacketConn(conn, dest)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create vless xudp packet conn: %w", err)
	}

	logger.Debug("VLESS: UDP connection established to %s via %s", dest.String(), serverAddr.String())

	// Use vmessPacketConn wrapper since VLESS XUDP returns vmess.PacketConn
	return &vmessPacketConn{
		packetConn:  packetConn,
		destination: dest,
	}, nil
}

// dialVisionTLS establishes a TLS connection for VLESS Vision flow.
// Vision requires uTLS for fingerprint simulation.
func dialVisionTLS(ctx context.Context, conn net.Conn, cfg *config.ProxyOutbound) (net.Conn, error) {
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}

	fingerprint := getUTLSFingerprint(cfg.Fingerprint)

	utlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: cfg.Insecure,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	utlsConn := utls.UClient(conn, utlsConfig, fingerprint)

	if err := utlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}

	logger.Debug("VLESS Vision: TLS connected to %s with fingerprint %s", sni, cfg.Fingerprint)
	return utlsConn, nil
}

// dialRealityTLS establishes a TLS connection with Reality authentication.
// Reality embeds authentication data in the TLS ClientHello sessionId field.
// Based on XTLS/Xray-core Reality client implementation.
func dialRealityTLS(ctx context.Context, conn net.Conn, cfg *config.ProxyOutbound) (net.Conn, error) {
	// Decode server's public key (base64 URL-safe without padding)
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(cfg.RealityPublicKey)
	if err != nil {
		// Try standard base64
		publicKeyBytes, err = base64.RawStdEncoding.DecodeString(cfg.RealityPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode reality public key: %w", err)
		}
	}
	if len(publicKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid reality public key length: %d (expected 32)", len(publicKeyBytes))
	}

	// Decode short ID (hex string, optional)
	var shortID []byte
	if cfg.RealityShortID != "" {
		shortID, err = hex.DecodeString(cfg.RealityShortID)
		if err != nil {
			return nil, fmt.Errorf("failed to decode reality short id: %w", err)
		}
		// Xray allows 0..16 hex chars (i.e. 0..8 bytes), keep it lenient but bounded.
		if len(shortID) > 16 {
			return nil, fmt.Errorf("invalid reality short id length: %d bytes (max 16)", len(shortID))
		}
	}

	// Get SNI
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Server
	}

	// Get fingerprint
	fingerprint := getUTLSFingerprint(cfg.Fingerprint)

	// Create uTLS config
	utlsConfig := &utls.Config{
		ServerName:             sni,
		InsecureSkipVerify:     true, // Reality doesn't verify server cert
		SessionTicketsDisabled: true,
	}

	utlsConn := utls.UClient(conn, utlsConfig, fingerprint)

	// Build handshake state first so we can access ClientHello fields & TLS 1.3 keyshare.
	if err := utlsConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("failed to build handshake state: %w", err)
	}

	hello := utlsConn.HandshakeState.Hello

	// Construct plaintext session ID (first 16 bytes are authenticated & encrypted).
	hello.SessionId = make([]byte, 32)
	if len(hello.Raw) < 39+len(hello.SessionId) {
		return nil, fmt.Errorf("unexpected client hello length: %d", len(hello.Raw))
	}
	copy(hello.Raw[39:], hello.SessionId) // fixed SessionId location in ClientHello

	// Version bytes are used for optional server-side min/max client version checks.
	// Use a plausible Xray-like version to maximize compatibility.
	const (
		realityVersionX = 1
		realityVersionY = 8
		realityVersionZ = 0
	)
	hello.SessionId[0] = realityVersionX
	hello.SessionId[1] = realityVersionY
	hello.SessionId[2] = realityVersionZ
	hello.SessionId[3] = 0 // reserved
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	if len(shortID) > 0 {
		copy(hello.SessionId[8:], shortID)
	}

	// Compute auth key based on TLS 1.3 ECDHE keyshare and server's public key.
	publicKey, err := ecdh.X25519().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reality public key: %w", err)
	}

	ecdhe := utlsConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = utlsConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errors.New("current fingerprint does not support TLS 1.3, reality handshake cannot establish")
	}

	authKey, err := ecdhe.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute reality shared key: %w", err)
	}
	if len(authKey) == 0 {
		return nil, errors.New("failed to compute reality shared key")
	}

	// HKDF(authKey, hello.Random[:20], "REALITY") -> authKey (in place)
	if _, err := io.ReadFull(hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return nil, fmt.Errorf("failed to derive reality auth key: %w", err)
	}

	// Encrypt first 16 bytes of plaintext session ID into 32-byte ciphertext.
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create reality cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create reality AEAD: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(hello.Random) < 20+nonceSize {
		return nil, fmt.Errorf("unexpected client hello random length: %d", len(hello.Random))
	}
	nonce := hello.Random[20 : 20+nonceSize]
	sealed := aead.Seal(hello.SessionId[:0], nonce, hello.SessionId[:16], hello.Raw)
	if len(sealed) != 32 {
		return nil, fmt.Errorf("unexpected reality session id length: %d", len(sealed))
	}
	copy(hello.SessionId, sealed)
	copy(hello.Raw[39:], hello.SessionId)

	// Perform TLS handshake.
	if err := utlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("Reality TLS handshake failed: %w", err)
	}

	// Verify REALITY "temporary trusted certificate" signature.
	state := utlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		utlsConn.Close()
		return nil, errors.New("reality: no peer certificates")
	}
	peerCert := state.PeerCertificates[0]
	pubKey, ok := peerCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		utlsConn.Close()
		return nil, errors.New("reality: server returned non-reality certificate (check pbk/sid/sni/fp)")
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pubKey)
	if !bytes.Equal(h.Sum(nil), peerCert.Signature) {
		utlsConn.Close()
		return nil, errors.New("reality: invalid certificate signature (check pbk/sid/sni/fp)")
	}

	logger.Debug("Reality: verified certificate for %s, fingerprint=%s, shortId=%s", sni, cfg.Fingerprint, cfg.RealityShortID)
	return utlsConn, nil
}

// getUTLSFingerprint returns the uTLS ClientHelloID for the given fingerprint name.
func getUTLSFingerprint(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "chrome", "":
		return utls.HelloChrome_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "edge":
		return utls.HelloEdge_Auto
	case "360":
		return utls.Hello360_Auto
	case "qq":
		return utls.HelloQQ_Auto
	case "random":
		return utls.HelloRandomized
	case "randomized":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

// dialHysteria2UDP creates a UDP connection through Hysteria2.
// It handles connection failures by attempting to reconnect.
func (s *SingboxOutbound) dialHysteria2UDP(ctx context.Context, _, dest M.Socksaddr) (net.PacketConn, error) {
	s.hy2Mu.Lock()
	defer s.hy2Mu.Unlock()

	if s.hy2Client == nil {
		return nil, errors.New("hysteria2 client not initialized")
	}

	logger.Debug("Hysteria2: creating UDP session for %s", dest.String())

	// Create UDP session with timeout
	// Note: We call UDP() directly without a goroutine because:
	// 1. The Hysteria2 client should handle timeouts internally
	// 2. Creating a goroutine for each call can lead to goroutine leaks if the call blocks
	// 3. The context timeout will be respected by the underlying QUIC connection

	// Use a longer timeout for UDP session creation
	udpTimeout := 15 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < udpTimeout {
			udpTimeout = remaining
		}
	}

	// Try up to 2 times (initial + 1 retry after reconnect)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		currentClient := s.hy2Client
		if currentClient == nil {
			return nil, errors.New("hysteria2 client not initialized")
		}

		// Check context before attempting
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("hysteria2 UDP cancelled: %w", ctx.Err())
		default:
		}

		attemptCtx, cancel := context.WithTimeout(ctx, udpTimeout)
		type udpResult struct {
			conn hy2.HyUDPConn
			err  error
		}
		resultCh := make(chan udpResult, 1)
		go func() {
			conn, err := currentClient.UDP()
			if conn != nil {
				select {
				case <-attemptCtx.Done():
					conn.Close()
					return
				case resultCh <- udpResult{conn: conn, err: err}:
					return
				}
			}
			select {
			case <-attemptCtx.Done():
				return
			case resultCh <- udpResult{conn: conn, err: err}:
				return
			}
		}()

		select {
		case <-attemptCtx.Done():
			cancel()
			logger.Warn("Hysteria2: UDP session creation timeout for %s (attempt %d)", dest.String(), attempt+1)
			lastErr = fmt.Errorf("hysteria2 UDP timeout after %v", udpTimeout)
			if attempt == 0 {
				if currentClient != nil {
					_ = currentClient.Close()
				}
				s.hy2Client = nil
				if err := s.initHysteria2(s.config); err != nil {
					return nil, fmt.Errorf("failed to recreate hysteria2 client: %w", err)
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return nil, lastErr
		case result := <-resultCh:
			cancel()
			if result.err != nil {
				errStr := result.err.Error()
				logger.Debug("Hysteria2: UDP session error: %s (attempt %d)", errStr, attempt+1)
				lastErr = result.err

				// Check for specific errors that indicate we should not retry
				if strings.Contains(errStr, "UDP not enabled") {
					logger.Error("Hysteria2: Server UDP relay disabled!")
					return nil, fmt.Errorf("hysteria2 UDP failed: %w", result.err)
				}

				// For "connection closed" errors, the ReconnectableClient should auto-reconnect
				// on the next call, so we can retry once
				if attempt == 0 && (strings.Contains(errStr, "connection closed") ||
					strings.Contains(errStr, "closed") ||
					strings.Contains(errStr, "EOF")) {
					logger.Info("Hysteria2: connection issue detected, retrying... (attempt %d)", attempt+1)
					time.Sleep(500 * time.Millisecond)
					continue
				}

				return nil, fmt.Errorf("hysteria2 UDP failed: %w", result.err)
			}

			logger.Debug("Hysteria2: UDP session created successfully for %s", dest.String())
			return &hysteria2PacketConn{
				conn:        result.conn,
				destination: dest,
				outbound:    s,
			}, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("hysteria2 UDP failed after retries: %w", lastErr)
	}
	return nil, errors.New("hysteria2 UDP failed after retries")
}

// Close closes the sing-box outbound.
func (s *SingboxOutbound) Close() error {
	s.hy2Mu.Lock()
	defer s.hy2Mu.Unlock()
	if s.hy2Client != nil {
		s.hy2Client.Close()
		s.hy2Client = nil
	}
	if s.anytlsClient != nil {
		s.anytlsClient.Close()
		s.anytlsClient = nil
		s.anytlsUOTClient = nil
	}
	return nil
}

// Tag returns the outbound tag/name.
func (s *SingboxOutbound) Tag() string {
	if s.config == nil {
		return ""
	}
	return s.config.Type + "-" + s.config.Name
}

// parseDestination parses a destination string into a sing Socksaddr.
func parseDestination(destination string) (M.Socksaddr, error) {
	host, portStr, err := net.SplitHostPort(destination)
	if err != nil {
		return M.Socksaddr{}, fmt.Errorf("invalid destination format: %w", err)
	}

	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return M.Socksaddr{}, fmt.Errorf("invalid port: %w", err)
	}

	// Try to parse as IP address first
	if ip, err := netip.ParseAddr(host); err == nil {
		return M.SocksaddrFromNetIP(netip.AddrPortFrom(ip, uint16(port))), nil
	}

	// Treat as domain name
	return M.Socksaddr{
		Fqdn: host,
		Port: uint16(port),
	}, nil
}

// singboxPacketConn wraps a sing-box NetPacketConn to implement net.PacketConn.
type singboxPacketConn struct {
	N.NetPacketConn
	serverAddr  M.Socksaddr
	destination M.Socksaddr
}

// ReadFrom reads a packet from the connection.
func (c *singboxPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.NetPacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	return n, addr, nil
}

// WriteTo writes a packet to the connection.
func (c *singboxPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.NetPacketConn.WriteTo(p, addr)
}

// LocalAddr returns the local network address.
func (c *singboxPacketConn) LocalAddr() net.Addr {
	return c.NetPacketConn.LocalAddr()
}

// Close closes the connection.
func (c *singboxPacketConn) Close() error {
	return c.NetPacketConn.Close()
}

// tcpPacketConn wraps a TCP connection as a PacketConn for protocols that tunnel UDP over TCP.
type tcpPacketConn struct {
	net.Conn
	destination M.Socksaddr
}

// ReadFrom reads a packet from the connection.
func (c *tcpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		return 0, nil, err
	}
	return n, c.destination.UDPAddr(), nil
}

// WriteTo writes a packet to the connection.
func (c *tcpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.Conn.Write(p)
}

// LocalAddr returns the local network address.
func (c *tcpPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// Close closes the connection.
func (c *tcpPacketConn) Close() error {
	return c.Conn.Close()
}

// ssNativeUDPPacketConn wraps a UDP connection for native Shadowsocks UDP protocol.
// Implements Shadowsocks AEAD encryption directly for UDP packets.
// Packet format: [salt][encrypted([destination][payload])]
type ssNativeUDPPacketConn struct {
	*net.UDPConn
	serverAddr  *net.UDPAddr
	destination M.Socksaddr
	key         []byte
	keySaltLen  int
	constructor func(key []byte) (cipher.AEAD, error)
}

const ssAEADOverhead = 16 // GCM/Poly1305 tag size

// ssKdf derives a subkey from the master key and salt using HKDF.
func ssKdf(key, salt []byte, keyLen int) []byte {
	subkey := make([]byte, keyLen)
	kdf := hkdf.New(sha1.New, key, salt, []byte("ss-subkey"))
	io.ReadFull(kdf, subkey)
	return subkey
}

// ReadFrom reads a Shadowsocks UDP packet from the connection.
func (c *ssNativeUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read raw encrypted packet from server - use buffer pool to reduce GC pressure
	rawBufPtr := GetLargeBuffer()
	rawBuf := *rawBufPtr
	defer PutLargeBuffer(rawBufPtr)

	n, _, err = c.UDPConn.ReadFromUDP(rawBuf)
	if err != nil {
		logger.Debug("Shadowsocks UDP read error: %v", err)
		return 0, nil, err
	}

	if n < c.keySaltLen+ssAEADOverhead {
		return 0, nil, errors.New("packet too short")
	}

	// Extract salt and derive subkey
	salt := rawBuf[:c.keySaltLen]
	subkey := ssKdf(c.key, salt, c.keySaltLen)

	// Create cipher
	aead, err := c.constructor(subkey)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt - nonce is typically 12 bytes, use stack allocation
	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, rawBuf[c.keySaltLen:n], nil)
	if err != nil {
		logger.Debug("Shadowsocks decrypt error: %v", err)
		return 0, nil, fmt.Errorf("decrypt failed: %w", err)
	}

	// Parse destination address from plaintext
	buffer := buf.As(plaintext)
	dest, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read destination: %w", err)
	}

	// Copy remaining payload
	n = copy(p, buffer.Bytes())
	logger.Debug("Shadowsocks: received %d bytes from %s", n, dest.String())
	return n, dest.UDPAddr(), nil
}

// WriteTo writes a Shadowsocks UDP packet to the connection.
func (c *ssNativeUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Calculate destination address length
	destLen := M.SocksaddrSerializer.AddrPortLen(c.destination)

	// Build plaintext: [destination][payload]
	plaintext := make([]byte, destLen+len(p))
	destBuf := buf.With(plaintext[:destLen])
	err = M.SocksaddrSerializer.WriteAddrPort(destBuf, c.destination)
	if err != nil {
		return 0, fmt.Errorf("failed to write destination: %w", err)
	}
	copy(plaintext[destLen:], p)

	// Generate random salt
	salt := make([]byte, c.keySaltLen)
	if _, err = crand.Read(salt); err != nil {
		return 0, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive subkey
	subkey := ssKdf(c.key, salt, c.keySaltLen)

	// Create cipher
	aead, err := c.constructor(subkey)
	if err != nil {
		return 0, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt
	nonce := make([]byte, aead.NonceSize())
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Build packet: [salt][ciphertext]
	packet := make([]byte, c.keySaltLen+len(ciphertext))
	copy(packet[:c.keySaltLen], salt)
	copy(packet[c.keySaltLen:], ciphertext)

	// Send to server
	_, err = c.UDPConn.WriteToUDP(packet, c.serverAddr)
	if err != nil {
		return 0, err
	}
	logger.Debug("Shadowsocks: sent %d bytes (encrypted %d) to %s", len(p), len(packet), c.serverAddr)
	return len(p), nil
}

// LocalAddr returns the local network address.
func (c *ssNativeUDPPacketConn) LocalAddr() net.Addr {
	return c.UDPConn.LocalAddr()
}

// SetDeadline sets the read and write deadlines.
func (c *ssNativeUDPPacketConn) SetDeadline(t time.Time) error {
	return c.UDPConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *ssNativeUDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.UDPConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *ssNativeUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.UDPConn.SetWriteDeadline(t)
}

// Close closes the connection.
func (c *ssNativeUDPPacketConn) Close() error {
	return c.UDPConn.Close()
}

// trojanPacketConn wraps a TCP connection for Trojan UDP protocol.
// Trojan UDP packet format: [ATYP][DST.ADDR][DST.PORT][Length][CRLF][Payload]
type trojanPacketConn struct {
	net.Conn
	r           *bufio.Reader
	destination M.Socksaddr
}

// ReadFrom reads a Trojan UDP packet from the connection.
func (c *trojanPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.r == nil {
		c.r = bufio.NewReaderSize(c.Conn, 32*1024)
	}

	// Read address type
	var header [1]byte
	if _, err = io.ReadFull(c.r, header[:]); err != nil {
		return 0, nil, err
	}

	atyp := header[0]
	var destAddr M.Socksaddr

	switch atyp {
	case 0x01: // IPv4
		var addrBuf [4]byte
		if _, err = io.ReadFull(c.r, addrBuf[:]); err != nil {
			return 0, nil, err
		}
		ip, _ := netip.AddrFromSlice(addrBuf[:])
		destAddr.Addr = ip
	case 0x03: // Domain
		var lenBuf [1]byte
		if _, err = io.ReadFull(c.r, lenBuf[:]); err != nil {
			return 0, nil, err
		}
		dLen := int(lenBuf[0])
		var domainBuf [255]byte
		if dLen > len(domainBuf) {
			return 0, nil, fmt.Errorf("invalid domain length: %d", dLen)
		}
		if _, err = io.ReadFull(c.r, domainBuf[:dLen]); err != nil {
			return 0, nil, err
		}
		destAddr.Fqdn = string(domainBuf[:dLen])
	case 0x04: // IPv6
		var addrBuf [16]byte
		if _, err = io.ReadFull(c.r, addrBuf[:]); err != nil {
			return 0, nil, err
		}
		ip, _ := netip.AddrFromSlice(addrBuf[:])
		destAddr.Addr = ip
	default:
		return 0, nil, fmt.Errorf("unknown address type: %d", atyp)
	}

	// Read port
	var portBuf [2]byte
	if _, err = io.ReadFull(c.r, portBuf[:]); err != nil {
		return 0, nil, err
	}
	destAddr.Port = uint16(portBuf[0])<<8 | uint16(portBuf[1])

	// Read length
	var lenBuf2 [2]byte
	if _, err = io.ReadFull(c.r, lenBuf2[:]); err != nil {
		return 0, nil, err
	}
	length := int(lenBuf2[0])<<8 | int(lenBuf2[1])

	// Read CRLF
	var crlfBuf [2]byte
	if _, err = io.ReadFull(c.r, crlfBuf[:]); err != nil {
		return 0, nil, err
	}

	// Read payload (must consume the full frame from the TCP stream)
	toCopy := length
	if toCopy > len(p) {
		toCopy = len(p)
	}
	if toCopy > 0 {
		if _, err = io.ReadFull(c.r, p[:toCopy]); err != nil {
			return 0, nil, err
		}
	}
	remaining := length - toCopy
	if remaining > 0 {
		if _, err = io.CopyN(io.Discard, c.r, int64(remaining)); err != nil {
			return 0, nil, err
		}
	}

	return toCopy, destAddr.UDPAddr(), nil
}

// WriteTo writes a Trojan UDP packet to the connection.
func (c *trojanPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Build Trojan UDP packet: [ATYP][DST.ADDR][DST.PORT][Length][CRLF][Payload]
	packet := make([]byte, 0, len(p)+64)

	// Add address
	packet = appendSocksaddr(packet, c.destination)

	// Add length (2 bytes, big-endian)
	packet = append(packet, byte(len(p)>>8), byte(len(p)))

	// Add CRLF
	packet = append(packet, '\r', '\n')

	// Add payload
	packet = append(packet, p...)

	_, err = c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// LocalAddr returns the local network address.
func (c *trojanPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// SetDeadline sets the read and write deadlines.
func (c *trojanPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *trojanPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *trojanPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// Close closes the connection.
func (c *trojanPacketConn) Close() error {
	return c.Conn.Close()
}

// vmessPacketConn wraps a VMess packet connection.
type vmessPacketConn struct {
	packetConn  vmess.PacketConn
	destination M.Socksaddr
}

// ReadFrom reads a packet from the connection.
func (c *vmessPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.NewPacket()
	defer buffer.Release()
	dest, err := c.packetConn.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n = copy(p, buffer.Bytes())
	return n, dest.UDPAddr(), nil
}

// WriteTo writes a packet to the connection.
func (c *vmessPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// VMess AEAD requires header and tail space for encryption overhead
	const headerReserve = 64
	const tailReserve = 64

	// Create buffer with total capacity
	totalSize := headerReserve + len(p) + tailReserve
	buffer := buf.NewSize(totalSize)

	// Resize(start, length) sets start position and end = start + length
	buffer.Resize(headerReserve, 0)

	// Write data - this advances end by len(p)
	_, err = buffer.Write(p)
	if err != nil {
		buffer.Release()
		return 0, fmt.Errorf("failed to write to buffer: %w", err)
	}

	err = c.packetConn.WritePacket(buffer, c.destination)
	if err != nil {
		buffer.Release()
		return 0, err
	}
	return len(p), nil
}

// LocalAddr returns the local network address.
func (c *vmessPacketConn) LocalAddr() net.Addr {
	return c.packetConn.LocalAddr()
}

// SetDeadline sets the read and write deadlines.
func (c *vmessPacketConn) SetDeadline(t time.Time) error {
	return c.packetConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *vmessPacketConn) SetReadDeadline(t time.Time) error {
	return c.packetConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *vmessPacketConn) SetWriteDeadline(t time.Time) error {
	return c.packetConn.SetWriteDeadline(t)
}

// Close closes the connection.
func (c *vmessPacketConn) Close() error {
	return c.packetConn.Close()
}

// writeTrojanHandshake writes the Trojan protocol handshake.
func writeTrojanHandshake(conn net.Conn, password string, dest M.Socksaddr, udp bool) error {
	// Trojan handshake format:
	// [56-byte hex(SHA224(password))][CRLF][CMD][ATYP][DST.ADDR][DST.PORT][CRLF]

	// Calculate password hash (SHA224 in hex = 56 bytes)
	hash := sha224Hex(password)

	// Build handshake
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte(hash)...)
	buf = append(buf, '\r', '\n')

	// Command: 0x01 = CONNECT, 0x03 = UDP ASSOCIATE
	if udp {
		buf = append(buf, 0x03)
	} else {
		buf = append(buf, 0x01)
	}

	// Address
	buf = appendSocksaddr(buf, dest)
	buf = append(buf, '\r', '\n')

	_, err := conn.Write(buf)
	return err
}

// writeVMessHandshake writes the VMess protocol handshake.
func writeVMessHandshake(conn net.Conn, uuidStr, security string, alterID int, dest M.Socksaddr, udp bool) error {
	// VMess handshake is complex and requires proper implementation
	// For now, we write a simplified version
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		return err
	}

	// VMess request header
	buf := make([]byte, 0, 128)

	// Version
	buf = append(buf, 0x01)

	// UUID
	buf = append(buf, uuid[:]...)

	// Additional ID count
	buf = append(buf, byte(alterID))

	// Command: 0x01 = TCP, 0x02 = UDP
	if udp {
		buf = append(buf, 0x02)
	} else {
		buf = append(buf, 0x01)
	}

	// Port (big-endian)
	buf = append(buf, byte(dest.Port>>8), byte(dest.Port))

	// Address type and address
	buf = appendSocksaddrWithoutPort(buf, dest)

	_, err = conn.Write(buf)
	return err
}

// writeVLESSHandshake writes the VLESS protocol handshake.
func writeVLESSHandshake(conn net.Conn, uuidStr string, dest M.Socksaddr, udp bool) error {
	// VLESS handshake format:
	// [1-byte version][16-byte UUID][1-byte addon length][addon][CMD][PORT][ATYP][ADDR]

	uuid, err := parseUUID(uuidStr)
	if err != nil {
		return err
	}

	buf := make([]byte, 0, 128)
	buf = append(buf, 0x00) // Version
	buf = append(buf, uuid[:]...)
	buf = append(buf, 0x00) // Addon length (no addon)

	// Command: 0x01 = TCP, 0x02 = UDP
	if udp {
		buf = append(buf, 0x02)
	} else {
		buf = append(buf, 0x01)
	}

	// Port (big-endian)
	buf = append(buf, byte(dest.Port>>8), byte(dest.Port))

	// Address
	buf = appendSocksaddrWithoutPort(buf, dest)

	_, err = conn.Write(buf)
	return err
}

// sha224Hex returns the SHA224 hash of a string in hex format.
func sha224Hex(s string) string {
	h := sha256.New224()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// parseUUID parses a UUID string into a 16-byte array.
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return uuid, errors.New("invalid UUID length")
	}
	_, err := hex.Decode(uuid[:], []byte(s))
	return uuid, err
}

// appendSocksaddr appends a SOCKS address to a buffer.
func appendSocksaddr(buf []byte, addr M.Socksaddr) []byte {
	if addr.IsFqdn() {
		buf = append(buf, 0x03) // Domain
		buf = append(buf, byte(len(addr.Fqdn)))
		buf = append(buf, []byte(addr.Fqdn)...)
	} else if addr.Addr.Is4() {
		buf = append(buf, 0x01) // IPv4
		ip4 := addr.Addr.As4()
		buf = append(buf, ip4[:]...)
	} else {
		buf = append(buf, 0x04) // IPv6
		ip6 := addr.Addr.As16()
		buf = append(buf, ip6[:]...)
	}
	buf = append(buf, byte(addr.Port>>8), byte(addr.Port))
	return buf
}

// appendSocksaddrWithoutPort appends a SOCKS address without port to a buffer.
func appendSocksaddrWithoutPort(buf []byte, addr M.Socksaddr) []byte {
	if addr.IsFqdn() {
		buf = append(buf, 0x02) // Domain (VLESS uses 0x02 for domain)
		buf = append(buf, byte(len(addr.Fqdn)))
		buf = append(buf, []byte(addr.Fqdn)...)
	} else if addr.Addr.Is4() {
		buf = append(buf, 0x01) // IPv4
		ip4 := addr.Addr.As4()
		buf = append(buf, ip4[:]...)
	} else {
		buf = append(buf, 0x03) // IPv6 (VLESS uses 0x03 for IPv6)
		ip6 := addr.Addr.As16()
		buf = append(buf, ip6[:]...)
	}
	return buf
}

// SingboxDialer wraps a sing-box outbound for TCP connections (used for HTTP).
type SingboxDialer struct {
	config       *config.ProxyOutbound
	dialer       N.Dialer
	hy2Client    hy2.Client // Cached Hysteria2 client for TCP connections
	hy2Mu        sync.Mutex
	hy2Closed    bool
	anytlsClient *anytls.Client // Cached AnyTLS client for TCP connections
}

// CreateSingboxDialer creates a TCP dialer that routes through the proxy.
func CreateSingboxDialer(cfg *config.ProxyOutbound) (*SingboxDialer, error) {
	if cfg == nil {
		return nil, errors.New("proxy outbound configuration cannot be nil")
	}

	return &SingboxDialer{
		config: cfg,
		dialer: &directDialer{timeout: 30 * time.Second},
	}, nil
}

// Close closes the dialer and releases resources.
func (d *SingboxDialer) Close() error {
	d.hy2Mu.Lock()
	defer d.hy2Mu.Unlock()
	d.hy2Closed = true
	if d.hy2Client != nil {
		d.hy2Client.Close()
		d.hy2Client = nil
	}
	if d.anytlsClient != nil {
		d.anytlsClient.Close()
		d.anytlsClient = nil
	}
	return nil
}

// getOrCreateHy2Client gets or creates a cached Hysteria2 client.
func (d *SingboxDialer) getOrCreateHy2Client() (hy2.Client, error) {
	d.hy2Mu.Lock()
	defer d.hy2Mu.Unlock()

	if d.hy2Closed {
		return nil, errors.New("dialer is closed")
	}

	if d.hy2Client != nil {
		return d.hy2Client, nil
	}

	// Create new Hysteria2 client
	outbound, err := CreateSingboxOutbound(d.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create hysteria2 outbound: %w", err)
	}

	if outbound.hy2Client == nil {
		return nil, errors.New("hysteria2 client not initialized")
	}

	d.hy2Client = outbound.hy2Client
	return d.hy2Client, nil
}

// getOrCreateAnyTLSClient gets or creates a cached AnyTLS client.
func (d *SingboxDialer) getOrCreateAnyTLSClient() (*anytls.Client, error) {
	d.hy2Mu.Lock()
	defer d.hy2Mu.Unlock()

	if d.hy2Closed {
		return nil, errors.New("dialer is closed")
	}

	if d.anytlsClient != nil {
		return d.anytlsClient, nil
	}

	if !d.config.TLS {
		return nil, errors.New("anytls requires tls enabled")
	}

	serverAddr := M.ParseSocksaddrHostPort(d.config.Server, uint16(d.config.Port))
	dialOut := func(ctx context.Context) (net.Conn, error) {
		conn, err := d.dialer.DialContext(ctx, "tcp", serverAddr)
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		tlsConn, err := dialTLSWithFingerprint(ctx, conn, d.config)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	client, err := anytls.NewClient(context.Background(), anytls.ClientConfig{
		Password: d.config.Password,
		DialOut:  dialOut,
		Logger:   slog.NOP(),
	})
	if err != nil {
		return nil, err
	}

	d.anytlsClient = client
	return d.anytlsClient, nil
}

// DialContext establishes a TCP connection through the proxy.
func (d *SingboxDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Parse destination
	dest, err := parseDestination(address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse destination: %w", err)
	}

	// Get server address
	serverAddr := M.ParseSocksaddrHostPort(d.config.Server, uint16(d.config.Port))

	switch d.config.Type {
	case config.ProtocolShadowsocks:
		return d.dialShadowsocksTCP(ctx, serverAddr, dest)
	case config.ProtocolVMess:
		return d.dialVMessTCP(ctx, serverAddr, dest)
	case config.ProtocolTrojan:
		return d.dialTrojanTCP(ctx, serverAddr, dest)
	case config.ProtocolVLESS:
		return d.dialVLESSTCP(ctx, serverAddr, dest)
	case config.ProtocolHysteria2:
		return d.dialHysteria2TCP(ctx, serverAddr, dest)
	case config.ProtocolAnyTLS:
		return d.dialAnyTLSTCP(ctx, serverAddr, dest)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, d.config.Type)
	}
}

// dialShadowsocksTCP creates a TCP connection through Shadowsocks.
func (d *SingboxDialer) dialShadowsocksTCP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.Conn, error) {
	// Create TCP connection to server
	conn, err := d.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}

	// For Shadowsocks TCP, we need to send the destination address first
	method := d.config.Method
	password := d.config.Password

	var ssMethod interface {
		DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error)
	}

	if is2022Method(method) {
		m, err := shadowaead_2022.NewWithPassword(method, password, nil)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to create shadowsocks 2022 method: %w", err)
		}
		ssMethod = m
	} else {
		m, err := shadowaead.New(method, nil, password)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to create shadowsocks method: %w", err)
		}
		ssMethod = m
	}

	// Wrap connection with Shadowsocks
	return ssMethod.DialConn(conn, dest)
}

// dialVMessTCP creates a TCP connection through VMess using sing-vmess library.
func (d *SingboxDialer) dialVMessTCP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.Conn, error) {
	// Create TCP connection to server
	conn, err := d.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}

	// Apply TLS if configured
	if d.config.TLS {
		tlsConn, err := dialTLSWithFingerprint(ctx, conn, d.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn = tlsConn
	}

	// Apply WebSocket transport if configured
	if d.config.Network == "ws" {
		wsConn, err := upgradeToWebSocket(conn, d.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("WebSocket upgrade failed: %w", err)
		}
		conn = wsConn
	}

	// Create VMess client
	security := d.config.Security
	if security == "" || security == "auto" {
		security = "aes-128-gcm"
	}
	client, err := vmess.NewClient(d.config.UUID, security, d.config.AlterID)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create vmess client: %w", err)
	}

	// Dial through VMess
	return client.DialConn(conn, dest)
}

// dialTrojanTCP creates a TCP connection through Trojan.
func (d *SingboxDialer) dialTrojanTCP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.Conn, error) {
	// Create TCP connection to server
	conn, err := d.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}

	var finalConn net.Conn = conn

	// Apply TLS only if enabled (security != none)
	if d.config.TLS {
		tlsConn, err := dialTLSWithFingerprint(ctx, conn, d.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		finalConn = tlsConn
	}

	// Send Trojan handshake for TCP
	if err := writeTrojanHandshake(finalConn, d.config.Password, dest, false); err != nil {
		finalConn.Close()
		return nil, fmt.Errorf("trojan handshake failed: %w", err)
	}

	return finalConn, nil
}

// dialVLESSTCP creates a TCP connection through VLESS using sing-vmess/vless library.
func (d *SingboxDialer) dialVLESSTCP(ctx context.Context, serverAddr, dest M.Socksaddr) (net.Conn, error) {
	// Create TCP connection to server
	conn, err := d.dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP connection: %w", err)
	}

	// Determine if we're using Vision flow
	isVisionFlow := strings.Contains(strings.ToLower(d.config.Flow), "vision")

	// Apply TLS/Reality
	if d.config.Reality {
		realityConn, err := dialRealityTLS(ctx, conn, d.config)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("Reality handshake failed: %w", err)
		}
		conn = realityConn
	} else if d.config.TLS {
		// For Vision flow, use special TLS handling
		if isVisionFlow && d.config.Fingerprint != "" {
			tlsConn, err := dialVisionTLS(ctx, conn, d.config)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("Vision TLS handshake failed: %w", err)
			}
			conn = tlsConn
		} else {
			tlsConn, err := dialTLSWithFingerprint(ctx, conn, d.config)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}
			conn = tlsConn
		}
	}

	// Determine flow to use
	// For TCP with Vision (including Reality+Vision), pass the flow to the client.
	// For non-Vision, use empty flow.
	flow := ""
	if isVisionFlow {
		flow = d.config.Flow // Pass vision flow for TCP
	}

	// Create VLESS client (pass nil logger)
	client, err := vless.NewClient(d.config.UUID, flow, slog.NOP())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create vless client: %w", err)
	}

	logger.Debug("VLESS: TCP connection to %s, flow=%s", dest.String(), flow)

	// Dial through VLESS
	return client.DialConn(conn, dest)
}

// dialHysteria2TCP creates a TCP connection through Hysteria2.
func (d *SingboxDialer) dialHysteria2TCP(_ context.Context, _, dest M.Socksaddr) (net.Conn, error) {
	// Get or create cached Hysteria2 client
	client, err := d.getOrCreateHy2Client()
	if err != nil {
		return nil, fmt.Errorf("failed to get hysteria2 client: %w", err)
	}

	// Create TCP connection through Hysteria2
	conn, err := client.TCP(dest.String())
	if err != nil {
		// If connection failed, try to recreate the client
		d.hy2Mu.Lock()
		if d.hy2Client != nil {
			d.hy2Client.Close()
			d.hy2Client = nil
		}
		d.hy2Mu.Unlock()

		// Retry with new client
		client, err = d.getOrCreateHy2Client()
		if err != nil {
			return nil, fmt.Errorf("failed to recreate hysteria2 client: %w", err)
		}

		conn, err = client.TCP(dest.String())
		if err != nil {
			return nil, fmt.Errorf("failed to create hysteria2 TCP connection: %w", err)
		}
	}

	return conn, nil
}

// dialAnyTLSTCP creates a TCP connection through AnyTLS.
func (d *SingboxDialer) dialAnyTLSTCP(ctx context.Context, _, dest M.Socksaddr) (net.Conn, error) {
	client, err := d.getOrCreateAnyTLSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get anytls client: %w", err)
	}
	return client.CreateProxy(ctx, dest)
}

// hysteria2PacketConn wraps a Hysteria2 UDP connection.
type hysteria2PacketConn struct {
	conn         hy2.HyUDPConn
	destination  M.Socksaddr
	outbound     *SingboxOutbound
	closed       bool
	readDeadline time.Time
	mu           sync.Mutex
	// Persistent receive goroutine to avoid goroutine leak
	recvCh     chan hy2RecvResult
	recvCtx    context.Context
	recvCancel context.CancelFunc
	recvOnce   sync.Once
}

// hy2RecvResult holds the result of a Hysteria2 receive operation.
type hy2RecvResult struct {
	data []byte
	addr string
	err  error
}

// startReceiver starts a persistent receiver goroutine that reads from the Hysteria2 connection.
// This avoids creating a new goroutine for each ReadFrom call, preventing goroutine leaks.
func (c *hysteria2PacketConn) startReceiver() {
	c.recvOnce.Do(func() {
		c.recvCtx, c.recvCancel = context.WithCancel(context.Background())
		c.recvCh = make(chan hy2RecvResult, 1)

		go func() {
			for {
				// Check if we should stop
				select {
				case <-c.recvCtx.Done():
					return
				default:
				}

				// Receive data from Hysteria2 connection
				data, addrStr, err := c.conn.Receive()

				// Try to send result, but don't block if channel is full or context is cancelled
				select {
				case <-c.recvCtx.Done():
					return
				case c.recvCh <- hy2RecvResult{data, addrStr, err}:
					// Successfully sent result
				}

				// If there was an error (including EOF), stop the receiver
				if err != nil {
					return
				}
			}
		}()
	})
}

// ReadFrom reads a packet from the Hysteria2 UDP connection.
func (c *hysteria2PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, nil, errors.New("connection closed")
	}
	deadline := c.readDeadline
	c.mu.Unlock()

	// Start the persistent receiver goroutine (only once)
	c.startReceiver()

	// Apply timeout if deadline is set, otherwise use a default timeout
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: fmt.Errorf("i/o timeout")}
		}
		timeout = time.After(d)
	} else {
		// Default timeout of 30 seconds if no deadline is set
		timeout = time.After(30 * time.Second)
	}

	select {
	case r := <-c.recvCh:
		if r.err != nil {
			errStr := r.err.Error()
			// EOF means the UDP session was closed
			if errStr == "EOF" || strings.Contains(errStr, "EOF") {
				logger.Debug("Hysteria2: UDP session EOF for %s", c.destination.String())
				return 0, nil, io.EOF
			}
			// Log other errors for debugging
			logger.Debug("Hysteria2: UDP receive error for %s: %v", c.destination.String(), r.err)
			return 0, nil, r.err
		}
		n = copy(p, r.data)
		logger.Debug("Hysteria2: received %d bytes from %s for dest %s", n, r.addr, c.destination.String())
		// Parse source address
		if host, portStr, parseErr := net.SplitHostPort(r.addr); parseErr == nil {
			if port, portErr := net.LookupPort("udp", portStr); portErr == nil {
				if ip := net.ParseIP(host); ip != nil {
					return n, &net.UDPAddr{IP: ip, Port: port}, nil
				}
			}
		}
		return n, c.destination.UDPAddr(), nil

	case <-timeout:
		logger.Debug("Hysteria2: read timeout for %s", c.destination.String())
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: fmt.Errorf("i/o timeout")}
	}
}

// WriteTo writes a packet to the Hysteria2 UDP connection.
func (c *hysteria2PacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, errors.New("connection closed")
	}
	c.mu.Unlock()

	destStr := c.destination.String()
	logger.Debug("Hysteria2: sending %d bytes to %s", len(p), destStr)
	err = c.conn.Send(p, destStr)
	if err != nil {
		logger.Debug("Hysteria2: send error to %s: %v", destStr, err)
		return 0, err
	}
	return len(p), nil
}

// Close closes the connection.
func (c *hysteria2PacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true

	// Cancel the receiver goroutine first
	if c.recvCancel != nil {
		c.recvCancel()
	}

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// LocalAddr returns the local address.
func (c *hysteria2PacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

// SetDeadline sets read and write deadlines.
func (c *hysteria2PacketConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *hysteria2PacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline (no-op for Hysteria2).
func (c *hysteria2PacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// upgradeToWebSocket performs a WebSocket handshake and returns a WebSocket connection.
func upgradeToWebSocket(conn net.Conn, cfg *config.ProxyOutbound) (net.Conn, error) {
	// Generate WebSocket key
	keyBytes := make([]byte, 16)
	if _, err := crand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate WebSocket key: %w", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	// Build WebSocket upgrade request
	path := cfg.WSPath
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	host := cfg.WSHost
	if host == "" {
		host = cfg.Server
		if cfg.Port != 80 && cfg.Port != 443 {
			host = fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)
		}
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"\r\n", path, host, wsKey)

	// Send upgrade request
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("failed to send WebSocket upgrade request: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to read WebSocket upgrade response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("WebSocket upgrade failed: status %d", resp.StatusCode)
	}

	logger.Debug("WebSocket: upgrade successful to %s%s", host, path)

	return &wsConn{
		Conn:   conn,
		reader: reader,
	}, nil
}

// wsConn wraps a net.Conn with WebSocket framing.
type wsConn struct {
	net.Conn
	reader     *bufio.Reader
	readBuf    []byte
	readOffset int
}

// Read reads data from the WebSocket connection.
func (c *wsConn) Read(p []byte) (n int, err error) {
	// If we have buffered data, return it first
	if c.readOffset < len(c.readBuf) {
		n = copy(p, c.readBuf[c.readOffset:])
		c.readOffset += n
		if c.readOffset >= len(c.readBuf) {
			c.readBuf = nil
			c.readOffset = 0
		}
		return n, nil
	}

	// Read WebSocket frame header
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return 0, err
	}

	// Parse frame header
	// fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7F)

	// Handle extended payload length
	if payloadLen == 126 {
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, extLen); err != nil {
			return 0, err
		}
		payloadLen = int(binary.BigEndian.Uint16(extLen))
	} else if payloadLen == 127 {
		extLen := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, extLen); err != nil {
			return 0, err
		}
		payloadLen = int(binary.BigEndian.Uint64(extLen))
	}

	// Read masking key if present
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
			return 0, err
		}
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, err
	}

	// Unmask if needed
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	// Handle control frames
	if opcode == 0x8 { // Close
		return 0, io.EOF
	} else if opcode == 0x9 { // Ping
		// Send pong
		c.writeFrame(0xA, payload)
		return c.Read(p) // Read next frame
	} else if opcode == 0xA { // Pong
		return c.Read(p) // Ignore pong, read next frame
	}

	// Copy data to output buffer
	n = copy(p, payload)
	if n < len(payload) {
		c.readBuf = payload
		c.readOffset = n
	}

	return n, nil
}

// Write writes data to the WebSocket connection.
func (c *wsConn) Write(p []byte) (n int, err error) {
	return c.writeFrame(0x2, p) // Binary frame
}

// writeFrame writes a WebSocket frame.
func (c *wsConn) writeFrame(opcode byte, payload []byte) (n int, err error) {
	// Build frame header
	var header []byte
	payloadLen := len(payload)

	// FIN bit + opcode
	header = append(header, 0x80|opcode)

	// Mask bit (client must mask) + payload length
	if payloadLen < 126 {
		header = append(header, 0x80|byte(payloadLen))
	} else if payloadLen < 65536 {
		header = append(header, 0x80|126)
		header = append(header, byte(payloadLen>>8), byte(payloadLen))
	} else {
		header = append(header, 0x80|127)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(payloadLen))
		header = append(header, lenBytes...)
	}

	// Generate masking key
	maskKey := make([]byte, 4)
	if _, err := crand.Read(maskKey); err != nil {
		return 0, err
	}
	header = append(header, maskKey...)

	// Mask payload
	maskedPayload := make([]byte, payloadLen)
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%4]
	}

	// Write header and payload
	if _, err := c.Conn.Write(header); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(maskedPayload); err != nil {
		return 0, err
	}

	return len(payload), nil
}
