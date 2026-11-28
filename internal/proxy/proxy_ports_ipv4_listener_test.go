package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// --- 共享地址族选择器的合同 ---

func TestListenNetworkForAddressProxyPorts(t *testing.T) {
	cases := []struct {
		network string
		address string
		want    string
	}{
		{"tcp", "127.0.0.1:1080", "tcp4"},
		{"tcp", "0.0.0.0:1080", "tcp4"},
		{"udp", "192.168.1.2:19132", "udp4"},
		{"udp", "0.0.0.0:19132", "udp4"},
		{"tcp", "[::1]:1080", "tcp"},
		{"udp", "[::]:19132", "udp"},
		{"tcp", ":1080", "tcp"},
		{"udp", ":19132", "udp"},
		{"tcp", "localhost:1080", "tcp"},
		// 已经是带族的网络保持不变
		{"tcp4", "127.0.0.1:1080", "tcp4"},
		{"udp6", "[::1]:19132", "udp6"},
	}
	for _, c := range cases {
		if got := listenNetworkForAddress(c.network, c.address); got != c.want {
			t.Errorf("listenNetworkForAddress(%q, %q) = %q, want %q", c.network, c.address, got, c.want)
		}
	}
}

// --- 代理端口 TCP：IPv4 字面地址应绑定 IPv4，真实流量通过 ---

func TestProxyPortTCPIPv4ListenerAndTraffic(t *testing.T) {
	addr := freeTCPListenAddr(t)
	cfg := newTestProxyPortConfig("ipv4-tcp", addr)
	cfg.Type = config.ProxyPortTypeSocks5
	cfg.Username = "u"
	cfg.Password = "p"
	cm := config.NewProxyPortConfigManager(t.TempDir() + "/proxy_ports.json")
	if err := cm.AddPort(cfg); err != nil {
		t.Fatal(err)
	}
	mgr := NewProxyPortManager(cm, nil)
	if err := mgr.Start(true); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	mgr.mu.Lock()
	l := mgr.listeners[cfg.ID]
	mgr.mu.Unlock()
	if l == nil || l.listener == nil {
		t.Fatal("listener not started")
	}
	// 实际绑定应为 IPv4 字面地址
	tcpAddr, ok := l.listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.IP.To4() == nil {
		t.Fatalf("listener bound to non-IPv4 address: %v", l.listener.Addr())
	}

	// 真实 SOCKS5 认证 + CONNECT 流量
	echo := startEcho(t)
	conn, err := net.Dial("tcp4", l.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial IPv4 proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	greetingResp := make([]byte, 2)
	if _, err := io.ReadFull(br, greetingResp); err != nil || greetingResp[0] != 0x05 || greetingResp[1] != 0x02 {
		t.Fatalf("greeting response: %v %v", greetingResp, err)
	}
	auth := []byte{0x01, byte(len("u")), 'u', byte(len("p")), 'p'}
	if _, err := conn.Write(auth); err != nil {
		t.Fatal(err)
	}
	ar := make([]byte, 2)
	if _, err := io.ReadFull(br, ar); err != nil || ar[1] != 0 {
		t.Fatalf("auth reply: %v %v", ar, err)
	}
	host, portStr, _ := net.SplitHostPort(echo)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(br, rep); err != nil || rep[1] != 0 {
		t.Fatalf("connect reply: %v %v", rep, err)
	}
	if _, err := conn.Write([]byte("ipv4-tcp-ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("ipv4-tcp-ok"))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ipv4-tcp-ok" {
		t.Fatalf("echo: %q %v", got, err)
	}
}

// --- HTTPS 代理端口 IPv4 监听：TLS 握手可连，重启后仍为 IPv4 ---

func TestProxyPortHTTPSIPv4ListenerAndRestart(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeHTTPSListenerPair(t, dir, "https", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	addr := freeTCPListenAddr(t)
	cfg := &config.ProxyPortConfig{
		ID: "ipv4-https", Name: "ipv4-https", Type: config.ProxyPortTypeHTTPS,
		ListenAddr: addr, Enabled: true,
		TLS: &config.ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: "proxy.example.test"},
	}
	cm := config.NewProxyPortConfigManager(dir + "/proxy_ports.json")
	if err := cm.AddPort(cfg); err != nil {
		t.Fatal(err)
	}
	mgr := NewProxyPortManager(cm, nil)
	if err := mgr.Start(true); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	probe := func(m *ProxyPortManager, id string) string {
		t.Helper()
		m.mu.Lock()
		l := m.listeners[id]
		m.mu.Unlock()
		if l == nil || l.listener == nil {
			t.Fatal("HTTPS listener missing")
		}
		ta, ok := l.listener.Addr().(*net.TCPAddr)
		if !ok || ta.IP.To4() == nil {
			t.Fatalf("HTTPS bound non-IPv4: %v", l.listener.Addr())
		}
		return l.listener.Addr().String()
	}
	bound := probe(mgr, cfg.ID)

	// 真实 IPv4 TLS 握手通过（测试自签证书跳过校验，仅验证监听可达）
	conn, err := tls.Dial("tcp4", bound, &tls.Config{InsecureSkipVerify: true, ServerName: "proxy.example.test"})
	if err != nil {
		t.Fatalf("TLS handshake to IPv4 HTTPS proxy: %v", err)
	}
	_ = conn.Close()

	// 显式停止并重新加载配置后重启，验证仍为 IPv4
	mgr.Stop()
	cm2 := config.NewProxyPortConfigManager(dir + "/proxy_ports.json")
	if err := cm2.Load(); err != nil {
		t.Fatal(err)
	}
	mgr2 := NewProxyPortManager(cm2, nil)
	if err := mgr2.Start(true); err != nil {
		t.Fatal(err)
	}
	defer mgr2.Stop()
	probe(mgr2, cfg.ID)
}

// --- SOCKS5 UDP relay：跟随 TCP 入口 IPv4，primary/fallback 均为 udp4，真实流量与重启 ---

func echoUDP(pc *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteToUDP(buf[:n], addr)
	}
}

func TestProxyPortSOCKS5UDPRelayIPv4AndRestart(t *testing.T) {
	udpEcho, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	go echoUDP(udpEcho)

	addr := freeTCPListenAddr(t)
	cfg := newTestProxyPortConfig("ipv4-socks-udp", addr)
	cfg.Type = config.ProxyPortTypeSocks5
	cm := config.NewProxyPortConfigManager(t.TempDir() + "/proxy_ports.json")
	if err := cm.AddPort(cfg); err != nil {
		t.Fatal(err)
	}
	mgr := NewProxyPortManager(cm, nil)
	if err := mgr.Start(true); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	runOnce := func(round string) {
		t.Helper()
		mgr.mu.Lock()
		l := mgr.listeners[cfg.ID]
		mgr.mu.Unlock()
		if l == nil || l.listener == nil {
			t.Fatal("listener missing")
		}
		if ta, ok := l.listener.Addr().(*net.TCPAddr); !ok || ta.IP.To4() == nil {
			t.Fatalf("TCP listener non-IPv4: %v", l.listener.Addr())
		}

		conn, err := net.Dial("tcp4", l.listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
			t.Fatalf("associate reply: %v %v", reply, err)
		}

		l.relayMu.Lock()
		relay := l.sharedRelay
		l.relayMu.Unlock()
		if relay == nil {
			t.Fatal("shared UDP relay not created")
		}
		udpAddr, ok := relay.conn.LocalAddr().(*net.UDPAddr)
		if !ok || udpAddr.IP.To4() == nil {
			t.Fatalf("UDP relay bound non-IPv4: %v", relay.conn.LocalAddr())
		}

		clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer clientUDP.Close()
		_ = clientUDP.SetDeadline(time.Now().Add(5 * time.Second))

		payload := []byte("udp-ipv4-" + round)
		dgram := []byte{0x00, 0x00, 0x00, 0x01}
		dgram = append(dgram, echoAddr.IP.To4()...)
		dgram = append(dgram, byte(echoAddr.Port>>8), byte(echoAddr.Port&0xff))
		dgram = append(dgram, payload...)
		// 0.0.0.0 不能作为目的地址，改用 127.0.0.1（relay 绑定在 0.0.0.0 上）
		dest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udpAddr.Port}
		if _, err := clientUDP.WriteToUDP(dgram, dest); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, _, err := clientUDP.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n < 10 || string(buf[10:n]) != string(payload) {
			t.Fatalf("relayed payload: %q", buf[:n])
		}
	}
	runOnce("first")

	// 实际重启：Stop 后 Start，验证 UDP relay 重建且仍为 IPv4
	mgr.Stop()
	if err := mgr.Start(true); err != nil {
		t.Fatal(err)
	}
	runOnce("after-restart")
}

// --- HY2 包监听：IPv4 字面地址必须 udp4，真实 IPv4 包可达 ---

func TestSecureHY2PacketListenerIPv4(t *testing.T) {
	_, _, profile := secureTestPort(t, "hysteria2")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dialer, err := CreateSingboxDialer(profile.Outbound("ipv4-hy2-client"))
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	echo := startEcho(t)
	conn, err := dialer.DialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatalf("HY2 dial via IPv4 listener: %v", err)
	}
	defer conn.Close()
	echoOK(t, conn, "hy2-ipv4-tcp")
}

// --- secureAdmission 监听器工厂：泛型 tcp + IPv4 地址应产生 IPv4 监听 ---

func TestSecureAdmissionListenFactoryIPv4(t *testing.T) {
	gate := newSecureAdmission(4, time.Second)
	defer gate.Close()
	ln, err := gate.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok || ta.IP.To4() == nil {
		t.Fatalf("secureAdmission bound non-IPv4: %v", ln.Addr())
	}
	// 真实 IPv4 连接到该监听器
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := ln.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case server := <-accepted:
		defer server.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("accept timed out")
	}
}
