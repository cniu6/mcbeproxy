// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	xraynet "github.com/xtls/xray-core/common/net"
	xrayinternet "github.com/xtls/xray-core/transport/internet"
	xraysplithttp "github.com/xtls/xray-core/transport/internet/splithttp"
	xraystat "github.com/xtls/xray-core/transport/internet/stat"

	"mcpeserverproxy/internal/config"
)

type fakeConnectedPacketConn struct {
	writeToCalls int
	writeCalls   int
	payload      []byte
}

func (c *fakeConnectedPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (c *fakeConnectedPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	c.writeToCalls++
	return 0, fmt.Errorf("write udp 127.0.0.1:1->127.0.0.1:2: use of WriteTo with pre-connected connection")
}

func (c *fakeConnectedPacketConn) Write(p []byte) (int, error) {
	c.writeCalls++
	c.payload = append(c.payload[:0], p...)
	return len(p), nil
}

func (c *fakeConnectedPacketConn) Close() error                     { return nil }
func (c *fakeConnectedPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *fakeConnectedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConnectedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConnectedPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestPacketConnWrapperWriteFallsBackForConnectedPacketConn(t *testing.T) {
	conn := &fakeConnectedPacketConn{}
	wrapper := &packetConnWrapper{
		PacketConn: conn,
		remoteAddr: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 19132,
		},
	}
	payload := []byte("hello")

	n, err := wrapper.Write(payload)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("expected %d bytes written, got %d", len(payload), n)
	}
	if conn.writeToCalls != 1 {
		t.Fatalf("expected one WriteTo attempt, got %d", conn.writeToCalls)
	}
	if conn.writeCalls != 1 {
		t.Fatalf("expected one fallback Write call, got %d", conn.writeCalls)
	}
	if string(conn.payload) != string(payload) {
		t.Fatalf("unexpected payload: %q", conn.payload)
	}
}

func TestTrackedPacketConnWriteToFallsBackForConnectedPacketConn(t *testing.T) {
	conn := &fakeConnectedPacketConn{}
	tracked := &trackedPacketConn{PacketConn: conn}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}
	payload := []byte("hello")

	n, err := tracked.WriteTo(payload, addr)
	if err != nil {
		t.Fatalf("WriteTo returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("expected %d bytes written, got %d", len(payload), n)
	}
	if conn.writeToCalls != 1 {
		t.Fatalf("expected one WriteTo attempt, got %d", conn.writeToCalls)
	}
	if conn.writeCalls != 1 {
		t.Fatalf("expected one fallback Write call, got %d", conn.writeCalls)
	}
}

// **Feature: singbox-outbound-proxy, Property 5: Direct routing for empty/direct proxy_outbound**
// **Validates: Requirements 2.2**
// For any ServerConfig with proxy_outbound set to empty string or "direct",
// the routing logic should return a direct connection (no proxy).
func TestProperty5_DirectRoutingForEmptyOrDirectProxyOutbound(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for server configs with empty or "direct" proxy_outbound
	directProxyOutboundGen := gen.OneConstOf("", "direct")

	properties.Property("empty proxy_outbound uses direct connection", prop.ForAll(
		func(proxyOutbound string) bool {
			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          19132,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound,
			}

			// Verify IsDirectConnection returns true for empty or "direct"
			if !cfg.IsDirectConnection() {
				t.Logf("IsDirectConnection should return true for proxy_outbound=%q", proxyOutbound)
				return false
			}

			// Create a ProxyDialer with an OutboundManager
			outboundMgr := NewOutboundManager(nil)
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			// Verify shouldUseDirect returns true
			if !dialer.shouldUseDirect() {
				t.Logf("shouldUseDirect should return true for proxy_outbound=%q", proxyOutbound)
				return false
			}

			return true
		},
		directProxyOutboundGen,
	))

	properties.Property("nil outbound manager does not imply direct connection", prop.ForAll(
		func(proxyOutbound string) bool {
			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          19132,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound,
			}

			// Create a ProxyDialer with nil OutboundManager
			dialer := NewProxyDialer(nil, cfg, 5*time.Second)

			// Verify shouldUseDirect only reflects explicit direct mode.
			if dialer.shouldUseDirect() != cfg.IsDirectConnection() {
				t.Logf("shouldUseDirect mismatch for proxy_outbound=%q", proxyOutbound)
				return false
			}
			if cfg.IsDirectConnection() {
				return true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "udp", "127.0.0.1:19132")
			if err == nil {
				if conn != nil {
					_ = conn.Close()
				}
				t.Logf("expected outbound manager unavailable error for proxy_outbound=%q", proxyOutbound)
				return false
			}
			if !strings.Contains(err.Error(), "outbound manager unavailable") {
				t.Logf("unexpected error: %v", err)
				return false
			}

			return true
		},
		gen.AnyString(),
	))

	properties.Property("nil server config fails closed", prop.ForAll(
		func(_ bool) bool {
			// Create a ProxyDialer with nil ServerConfig
			outboundMgr := NewOutboundManager(nil)
			dialer := NewProxyDialer(outboundMgr, nil, 5*time.Second)

			if dialer.shouldUseDirect() {
				t.Logf("shouldUseDirect should return false when serverConfig is nil")
				return false
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "udp", "127.0.0.1:19132")
			if err == nil {
				if conn != nil {
					_ = conn.Close()
				}
				t.Logf("expected missing server config error")
				return false
			}
			if !strings.Contains(err.Error(), "missing server config") {
				t.Logf("unexpected error: %v", err)
				return false
			}

			return true
		},
		gen.Bool(),
	))

	properties.Property("direct connection actually works", prop.ForAll(
		func(proxyOutbound string) bool {
			// Create a local UDP server to test direct connection
			serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Logf("Failed to resolve server address: %v", err)
				return false
			}

			serverConn, err := net.ListenUDP("udp", serverAddr)
			if err != nil {
				t.Logf("Failed to create server connection: %v", err)
				return false
			}
			defer serverConn.Close()

			actualServerAddr := serverConn.LocalAddr().String()

			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          serverConn.LocalAddr().(*net.UDPAddr).Port,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound, // empty or "direct"
			}

			// Create a ProxyDialer
			outboundMgr := NewOutboundManager(nil)
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			// Dial should succeed with direct connection
			conn, err := dialer.Dial("udp", actualServerAddr)
			if err != nil {
				t.Logf("Failed to dial: %v", err)
				return false
			}
			defer conn.Close()

			// Verify connection is established
			if conn == nil {
				t.Logf("Connection should not be nil")
				return false
			}

			return true
		},
		directProxyOutboundGen,
	))

	properties.TestingRun(t)
}

func TestEnsureImplementedTransport_GrpcIsAllowed(t *testing.T) {
	cfg := &config.ProxyOutbound{
		Name:            "grpc-vless",
		Type:            config.ProtocolVLESS,
		Server:          "example.com",
		Port:            443,
		Network:         "grpc",
		GRPCServiceName: "gun",
	}
	if err := ensureImplementedTransport(cfg, "TCP"); err != nil {
		t.Fatalf("expected grpc transport to be allowed, got: %v", err)
	}
}

func TestEnsureImplementedTransport_HTTPUpgradeIsAllowed(t *testing.T) {
	cfg := &config.ProxyOutbound{
		Name:    "httpupgrade-vless",
		Type:    config.ProtocolVLESS,
		Server:  "example.com",
		Port:    443,
		Network: "httpupgrade",
		WSPath:  "/edge-upgrade",
		WSHost:  "cdn.example.com",
	}
	if err := ensureImplementedTransport(cfg, "TCP"); err != nil {
		t.Fatalf("expected httpupgrade transport to be allowed, got: %v", err)
	}
}

func TestEnsureImplementedTransport_XHTTPIsAllowed(t *testing.T) {
	cfg := &config.ProxyOutbound{
		Name:      "xhttp-vless",
		Type:      config.ProtocolVLESS,
		Server:    "example.com",
		Port:      443,
		Network:   "xhttp",
		WSPath:    "/split",
		WSHost:    "cdn.example.com",
		XHTTPMode: "auto",
	}
	if err := ensureImplementedTransport(cfg, "TCP"); err != nil {
		t.Fatalf("expected xhttp transport to be allowed, got: %v", err)
	}
}

func TestUpgradeToXHTTP_DialsLocalSplitHTTP(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate test port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatalf("failed to close probe listener: %v", err)
	}

	listen, err := xraysplithttp.ListenXH(context.Background(), xraynet.LocalHostIP, xraynet.Port(port), &xrayinternet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &xraysplithttp.Config{Path: "/split"},
	}, func(conn xraystat.Connection) {
		go func(c xraystat.Connection) {
			defer c.Close()
			var payload [4]byte
			if _, err := io.ReadFull(c, payload[:]); err != nil {
				return
			}
			if string(payload[:]) != "ping" {
				return
			}
			_, _ = c.Write([]byte("pong"))
		}(conn)
	})
	if err != nil {
		t.Fatalf("failed to listen xhttp test server: %v", err)
	}
	defer listen.Close()

	cfg := &config.ProxyOutbound{
		Name:      "local-xhttp",
		Type:      config.ProtocolVLESS,
		Server:    "127.0.0.1",
		Port:      port,
		Network:   "xhttp",
		WSPath:    "/split",
		XHTTPMode: "packet-up",
	}

	conn, err := upgradeToXHTTP(context.Background(), nil, cfg)
	if err != nil {
		t.Fatalf("upgradeToXHTTP failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("failed to write xhttp payload: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read xhttp response: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("unexpected xhttp response %q", string(buf))
	}
}

func TestGrpcServiceAndTunNames(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		wantService string
		wantTun     string
		wantErr     bool
	}{
		{name: "simple service", serviceName: "gun", wantService: "gun", wantTun: "Tun"},
		{name: "custom path", serviceName: "/my/sample/Tun", wantService: "my/sample", wantTun: "Tun"},
		{name: "custom path alternatives", serviceName: "/my/sample/path1|path2", wantService: "my/sample", wantTun: "path1"},
		{name: "invalid custom path", serviceName: "/broken", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.ProxyOutbound{GRPCServiceName: tt.serviceName}
			gotService, gotTun, err := grpcServiceAndTunNames(cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotService != tt.wantService || gotTun != tt.wantTun {
				t.Fatalf("unexpected grpc service split, got (%q, %q), want (%q, %q)", gotService, gotTun, tt.wantService, tt.wantTun)
			}
		})
	}
}

func TestGrpcAuthority(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.ProxyOutbound
		want string
	}{
		{
			name: "explicit grpc authority wins",
			cfg: &config.ProxyOutbound{
				Server:        "server.example.com",
				SNI:           "sni.example.com",
				GRPCAuthority: "authority.example.com",
			},
			want: "authority.example.com",
		},
		{
			name: "sni fallback",
			cfg: &config.ProxyOutbound{
				Server: "server.example.com",
				SNI:    "sni.example.com",
			},
			want: "sni.example.com",
		},
		{
			name: "server fallback",
			cfg: &config.ProxyOutbound{
				Server: "server.example.com",
			},
			want: "server.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := grpcAuthority(tt.cfg); got != tt.want {
				t.Fatalf("unexpected grpc authority, got %q want %q", got, tt.want)
			}
		})
	}
}

func TestEffectiveTLSALPN_GrpcPrependsH2(t *testing.T) {
	cfg := &config.ProxyOutbound{
		Type:    config.ProtocolVLESS,
		Network: "grpc",
		ALPN:    "http/1.1",
	}
	want := []string{"h2", "http/1.1"}
	if got := effectiveTLSALPN(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ALPN list, got %v want %v", got, want)
	}
}

func TestHostnamePortAddr_NetworkAndString(t *testing.T) {
	addr := &HostnamePortAddr{Host: "mco.cubecraft.net", Port: 19132}
	if got := addr.Network(); got != "udp" {
		t.Fatalf("expected network=udp, got %q", got)
	}
	if got, want := addr.String(), "mco.cubecraft.net:19132"; got != want {
		t.Fatalf("unexpected addr string, got %q want %q", got, want)
	}

	var _ net.Addr = addr
}

func TestBuildUDPDestinationAddr_PreserveHostnameForProxy(t *testing.T) {
	addr, udpAddr, err := buildUDPDestinationAddr(context.Background(), "play.venitymc.com:19132", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if udpAddr != nil {
		t.Fatalf("expected unresolved hostname to keep udpAddr nil, got %+v", udpAddr)
	}
	hostnameAddr, ok := addr.(*HostnamePortAddr)
	if !ok {
		t.Fatalf("expected HostnamePortAddr, got %T", addr)
	}
	if hostnameAddr.Host != "play.venitymc.com" || hostnameAddr.Port != 19132 {
		t.Fatalf("unexpected hostname addr: %+v", hostnameAddr)
	}
}

func TestRawUDPProxyRefreshTargetAddrs_PreserveHostnameWhenProxying(t *testing.T) {
	cfg := &config.ServerConfig{
		ID:            "server-1",
		Target:        "play.venitymc.com",
		Port:          19132,
		ListenAddr:    "127.0.0.1:19133",
		Enabled:       true,
		ProxyOutbound: "node-a",
	}
	proxy := NewRawUDPProxy("server-1", cfg, nil, nil)
	proxy.SetOutboundManager(NewOutboundManager(nil))

	if err := proxy.refreshTargetAddrs(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy.targetAddr != nil {
		t.Fatalf("expected targetAddr to stay nil for unresolved proxied hostname, got %+v", proxy.targetAddr)
	}
	hostnameAddr, ok := proxy.targetPacketAddr.(*HostnamePortAddr)
	if !ok {
		t.Fatalf("expected HostnamePortAddr, got %T", proxy.targetPacketAddr)
	}
	if got := hostnameAddr.String(); got != "play.venitymc.com:19132" {
		t.Fatalf("unexpected targetPacketAddr: %q", got)
	}
}

func TestRawUDPProxyStart_PreserveHostnameWhenProxying(t *testing.T) {
	cfg := &config.ServerConfig{
		ID:            "server-1",
		Target:        "play.venitymc.com",
		Port:          19132,
		ListenAddr:    "127.0.0.1:0",
		Enabled:       true,
		ProxyOutbound: "node-a",
	}
	proxy := NewRawUDPProxy("server-1", cfg, nil, nil)
	proxy.SetOutboundManager(NewOutboundManager(nil))

	if err := proxy.Start(); err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}
	defer func() {
		_ = proxy.Stop()
	}()

	if proxy.targetAddr != nil {
		t.Fatalf("expected targetAddr to stay nil for unresolved proxied hostname after Start, got %+v", proxy.targetAddr)
	}
	hostnameAddr, ok := proxy.targetPacketAddr.(*HostnamePortAddr)
	if !ok {
		t.Fatalf("expected HostnamePortAddr after Start, got %T", proxy.targetPacketAddr)
	}
	if got := hostnameAddr.String(); got != "play.venitymc.com:19132" {
		t.Fatalf("unexpected targetPacketAddr after Start: %q", got)
	}
}

func TestRawUDPProxyUpdateConfig_PreserveHostnameWhenProxying(t *testing.T) {
	cfg := &config.ServerConfig{
		ID:            "server-1",
		Target:        "play.venitymc.com",
		Port:          19132,
		ListenAddr:    "127.0.0.1:0",
		Enabled:       true,
		ProxyOutbound: "node-a",
	}
	proxy := NewRawUDPProxy("server-1", cfg, nil, nil)
	proxy.SetOutboundManager(NewOutboundManager(nil))

	if err := proxy.Start(); err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}
	defer func() {
		_ = proxy.Stop()
	}()

	nextCfg := *cfg
	nextCfg.Target = "geo.example.com"
	nextCfg.Port = 19133
	proxy.UpdateConfig(&nextCfg)

	if proxy.targetAddr != nil {
		t.Fatalf("expected targetAddr to stay nil for unresolved proxied hostname after UpdateConfig, got %+v", proxy.targetAddr)
	}
	hostnameAddr, ok := proxy.targetPacketAddr.(*HostnamePortAddr)
	if !ok {
		t.Fatalf("expected HostnamePortAddr after UpdateConfig, got %T", proxy.targetPacketAddr)
	}
	if got := hostnameAddr.String(); got != "geo.example.com:19133" {
		t.Fatalf("unexpected targetPacketAddr after UpdateConfig: %q", got)
	}
}

func TestRawUDPProxyPingTargetServer_DirectConnectedUDPWrite(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen target udp: %v", err)
	}
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, MaxUDPPacketSize)
		_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			done <- err
			return
		}
		if n == 0 || buf[0] != raknetUnconnectedPing {
			done <- errors.New("target did not receive a RakNet ping")
			return
		}
		pong := buildUnconnectedPongPacket(0, 123456789, []byte("MCPE;Test;1;1.20;0;20;123456789;Test;Survival;1;19132;19133;"))
		_, err = serverConn.WriteToUDP(pong, addr)
		done <- err
	}()

	targetAddr := serverConn.LocalAddr().(*net.UDPAddr)
	cfg := &config.ServerConfig{
		ID:         "server-1",
		Target:     targetAddr.IP.String(),
		Port:       targetAddr.Port,
		ListenAddr: "127.0.0.1:0",
		Enabled:    true,
	}
	proxy := NewRawUDPProxy("server-1", cfg, nil, nil)
	if err := proxy.Start(); err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}
	defer func() {
		_ = proxy.Stop()
	}()

	if latency := proxy.pingTargetServer(); latency < 0 {
		t.Fatalf("expected direct RawUDP target ping to succeed, got %d", latency)
	}
	if err := <-done; err != nil {
		t.Fatalf("target server failed: %v", err)
	}
}

func TestPlainUDPProxyRefreshTargetAddr_PreserveHostnameWhenProxying(t *testing.T) {
	cfg := &config.ServerConfig{
		ID:            "server-1",
		Target:        "play.venitymc.com",
		Port:          19132,
		ListenAddr:    "127.0.0.1:19133",
		Enabled:       true,
		ProxyOutbound: "node-a",
	}
	proxy := NewPlainUDPProxy("server-1", cfg)
	proxy.SetOutboundManager(NewOutboundManager(nil))
	proxy.refreshTargetAddr()

	hostnameAddr, ok := proxy.targetAddr.(*HostnamePortAddr)
	if !ok {
		t.Fatalf("expected HostnamePortAddr, got %T", proxy.targetAddr)
	}
	if got := hostnameAddr.String(); got != "play.venitymc.com:19132" {
		t.Fatalf("unexpected targetAddr: %q", got)
	}
}

func TestPlainTCPProxyDialOutboundFailsClosedWithoutOutboundManager(t *testing.T) {
	proxy := NewPlainTCPProxy("server-1", &config.ServerConfig{
		ID:            "server-1",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:19133",
		Enabled:       true,
		ProxyOutbound: "node-a",
	})

	conn, nodeName, err := proxy.dialOutbound(context.Background(), "127.0.0.1:19132")
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected PlainTCPProxy to fail closed without outbound manager")
	}
	if nodeName != "" {
		t.Fatalf("expected empty node name on failure, got %q", nodeName)
	}
	if !strings.Contains(err.Error(), "outbound manager unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPlainUDPProxyDialTargetConnFailsClosedWithoutOutboundManager(t *testing.T) {
	proxy := NewPlainUDPProxy("server-1", &config.ServerConfig{
		ID:            "server-1",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:19133",
		Enabled:       true,
		ProxyOutbound: "node-a",
	})
	proxy.refreshTargetAddr()

	conn, addr, err := proxy.dialTargetConn(context.Background())
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected PlainUDPProxy to fail closed without outbound manager")
	}
	if addr != nil {
		t.Fatalf("expected nil target addr on failure, got %v", addr)
	}
	if !strings.Contains(err.Error(), "outbound manager unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProxyPortListenerDialOutboundFailsClosedWithoutOutboundManager(t *testing.T) {
	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:            "port-1",
		ListenAddr:    "127.0.0.1:1080",
		Type:          "mixed",
		Enabled:       true,
		ProxyOutbound: "node-a",
	}, nil, newProxyPortDialerPool(nil))

	conn, nodeName, err := listener.dialOutbound(context.Background(), "127.0.0.1:19132")
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected proxy port dial to fail closed without outbound manager")
	}
	if nodeName != "" {
		t.Fatalf("expected empty node name on failure, got %q", nodeName)
	}
	if !strings.Contains(err.Error(), "outbound manager unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRawUDPProxyDialThroughProxyFailsClosedWithoutOutboundManager(t *testing.T) {
	proxy := NewRawUDPProxy("server-1", &config.ServerConfig{
		ID:            "server-1",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:19133",
		Enabled:       true,
		ProxyOutbound: "node-a",
	}, nil, nil)

	conn, nodeName, err := proxy.dialThroughProxyWithTimeout(200 * time.Millisecond)
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected RawUDPProxy to fail closed without outbound manager")
	}
	if nodeName != "" {
		t.Fatalf("expected empty node name on failure, got %q", nodeName)
	}
	if !strings.Contains(err.Error(), "outbound manager unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRawUDPProxyDialThroughProxySupportsDirectToken(t *testing.T) {
	proxy := NewRawUDPProxy("server-1", &config.ServerConfig{
		ID:            "server-1",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "127.0.0.1:19133",
		Enabled:       true,
		ProxyOutbound: "missing-node,direct",
	}, nil, nil)
	proxy.SetOutboundManager(NewOutboundManager(nil))

	conn, nodeName, err := proxy.dialThroughProxyWithTimeout(time.Second)
	if err != nil {
		t.Fatalf("expected explicit direct token to work for RawUDPProxy, got error: %v", err)
	}
	defer conn.Close()
	if nodeName != DirectNodeName {
		t.Fatalf("expected selected node %q, got %q", DirectNodeName, nodeName)
	}
}

func TestWrapHysteria2UDPError(t *testing.T) {
	tests := []struct {
		name      string
		input     error
		wantNil   bool
		wantHint  bool
		checkWrap bool
	}{
		{name: "nil", input: nil, wantNil: true},
		{name: "idle timeout", input: errorf("connect error: timeout: no recent network activity"), wantHint: true, checkWrap: true},
		{name: "deadline exceeded", input: context.DeadlineExceeded, wantHint: true, checkWrap: true},
		{name: "generic", input: errorf("some other failure"), wantHint: false, checkWrap: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapHysteria2UDPError(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil error, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected wrapped error, got nil")
			}
			if tt.wantHint {
				msg := got.Error()
				if !containsAny(msg, []string{"unreachable", "QUIC", "TUN", "firewall"}) {
					t.Fatalf("expected actionable hint in error, got %q", msg)
				}
			}
			if tt.checkWrap && tt.input != nil {
				if unwrapped := errors.Unwrap(got); unwrapped == nil {
					t.Fatalf("expected wrapped inner error, got nil")
				}
			}
		})
	}
}

func errorf(msg string) error { return &simpleErr{msg: msg} }

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestProxyDialerDirectTokenInMultiNodeSelectorStillWorks(t *testing.T) {
	cfg := &config.ServerConfig{
		ID:            "test-server",
		Name:          "Test Server",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "0.0.0.0:19132",
		Protocol:      "bedrock",
		Enabled:       true,
		ProxyOutbound: "missing-node,direct",
	}

	dialer := NewProxyDialer(NewOutboundManager(nil), cfg, 5*time.Second)
	conn, err := dialer.DialContext(context.Background(), "udp", "127.0.0.1:19132")
	if err != nil {
		t.Fatalf("expected explicit direct token to keep working, got error: %v", err)
	}
	defer conn.Close()
	if dialer.GetSelectedNode() != DirectNodeName {
		t.Fatalf("expected selected node %q, got %q", DirectNodeName, dialer.GetSelectedNode())
	}
}

func TestProxyDialerMultiNodeSelectorFailsClosedWithoutExplicitDirect(t *testing.T) {
	cfg := &config.ServerConfig{
		ID:            "test-server",
		Name:          "Test Server",
		Target:        "127.0.0.1",
		Port:          19132,
		ListenAddr:    "0.0.0.0:19132",
		Protocol:      "bedrock",
		Enabled:       true,
		ProxyOutbound: "missing-a,missing-b",
	}

	dialer := NewProxyDialer(NewOutboundManager(nil), cfg, 5*time.Second)
	dialer.setSelectedNode("stale-node")
	conn, err := dialer.DialContext(context.Background(), "udp", "127.0.0.1:19132")
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected multi-node selector without direct to fail closed")
	}
	if !errors.Is(err, ErrOutboundNotFound) {
		t.Fatalf("expected ErrOutboundNotFound, got: %v", err)
	}
	if dialer.GetSelectedNode() != "" {
		t.Fatalf("selected node should be cleared after failure, got %q", dialer.GetSelectedNode())
	}
}

// **Feature: singbox-outbound-proxy, Property 6: Fallback to direct for non-existent outbound**
// **Validates: Requirements 2.4**
// For any ServerConfig referencing a non-existent proxy outbound name,
// the routing logic should return a direct connection.
func TestProperty6_FallbackToDirectForNonExistentOutbound(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for non-existent outbound names
	nonExistentOutboundGen := gen.Identifier().Map(func(s string) string {
		return "nonexistent_" + s
	})

	properties.Property("non-existent outbound returns error without direct fallback", prop.ForAll(
		func(proxyOutbound string) bool {
			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          19132,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound, // non-existent outbound
			}

			// Create an OutboundManager without the referenced outbound
			outboundMgr := NewOutboundManager(nil)

			// Create a ProxyDialer
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			// Verify shouldUseDirect returns false (because proxy_outbound is set)
			if dialer.shouldUseDirect() {
				t.Logf("shouldUseDirect should return false for proxy_outbound=%q", proxyOutbound)
				return false
			}

			dialer.setSelectedNode("stale-node")
			conn, err := dialer.Dial("udp", "127.0.0.1:19132")
			if err == nil {
				if conn != nil {
					_ = conn.Close()
				}
				t.Logf("Dial should fail closed for proxy_outbound=%q", proxyOutbound)
				return false
			}
			if !errors.Is(err, ErrOutboundNotFound) {
				t.Logf("expected ErrOutboundNotFound, got: %v", err)
				return false
			}
			if dialer.GetSelectedNode() != "" {
				t.Logf("selected node should be cleared after failure, got %q", dialer.GetSelectedNode())
				return false
			}

			return true
		},
		nonExistentOutboundGen,
	))

	properties.Property("DialContext also returns error without direct fallback", prop.ForAll(
		func(proxyOutbound string) bool {
			cfg := &config.ServerConfig{
				ID:            "test-server",
				Name:          "Test Server",
				Target:        "127.0.0.1",
				Port:          19132,
				ListenAddr:    "0.0.0.0:19132",
				Protocol:      "bedrock",
				Enabled:       true,
				ProxyOutbound: proxyOutbound, // non-existent outbound
			}

			// Create an OutboundManager without the referenced outbound
			outboundMgr := NewOutboundManager(nil)

			// Create a ProxyDialer
			dialer := NewProxyDialer(outboundMgr, cfg, 5*time.Second)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			dialer.setSelectedNode("stale-node")
			conn, err := dialer.DialContext(ctx, "udp", "127.0.0.1:19132")
			if err == nil {
				if conn != nil {
					_ = conn.Close()
				}
				t.Logf("DialContext should fail closed for proxy_outbound=%q", proxyOutbound)
				return false
			}
			if !errors.Is(err, ErrOutboundNotFound) {
				t.Logf("expected ErrOutboundNotFound, got: %v", err)
				return false
			}
			if dialer.GetSelectedNode() != "" {
				t.Logf("selected node should be cleared after failure, got %q", dialer.GetSelectedNode())
				return false
			}

			return true
		},
		nonExistentOutboundGen,
	))

	properties.TestingRun(t)
}
