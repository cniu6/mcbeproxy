package proxy

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// An HTTP+TLS outbound must reach a real HTTPS listener using that listener's
// certificate, with verification still on. A matching name plus the pinned CA
// succeeds; a wrong SNI, a missing CA, or a wrong password must fail instead
// of silently skipping verification.
func TestHTTPSOutboundThroughRealHTTPSListener(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certPath, keyPath := writeHTTPSListenerPair(t, dir, "listener", now.Add(-time.Hour), now.Add(time.Hour))
	port := freeListenPort(t)
	cfgMgr := config.NewProxyPortConfigManager(filepath.Join(dir, "proxy_ports.json"))
	if err := cfgMgr.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfgMgr.AddPort(&config.ProxyPortConfig{
		ID: "https-up", Name: "https-up", Type: config.ProxyPortTypeHTTPS,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Enabled: true,
		Username: "alice", Password: "s3cret:pw",
		TLS: &config.ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: "proxy.example.test"},
	}); err != nil {
		t.Fatal(err)
	}
	mgr := NewProxyPortManager(cfgMgr, nil)
	defer mgr.Stop()
	if err := mgr.Start(true); err != nil {
		t.Fatalf("start HTTPS listener: %v", err)
	}
	echo := startTCPEcho(t)

	tryTunnel := func(sni, ca, password string) error {
		cfg := &config.ProxyOutbound{
			Name: "https-node", Type: config.ProtocolHTTP, Server: "127.0.0.1", Port: port, Enabled: true,
			TLS: true, SNI: sni, TLSCAFile: ca, Username: "alice", Password: password,
		}
		dialer, err := CreateSingboxDialer(cfg)
		if err != nil {
			t.Fatalf("create dialer: %v", err)
		}
		defer dialer.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", echo.String())
		if err != nil {
			return err
		}
		defer conn.Close()
		const msg = "https-listener-ok"
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(conn, msg); err != nil {
			return err
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil {
			return err
		}
		if string(got) != msg {
			t.Fatalf("echo mismatch: %q", got)
		}
		return nil
	}

	if err := tryTunnel("proxy.example.test", certPath, "s3cret:pw"); err != nil {
		t.Fatalf("verified tunnel through HTTPS listener failed: %v", err)
	}
	if err := tryTunnel("wrong.example.test", certPath, "s3cret:pw"); err == nil {
		t.Fatal("SNI mismatch must fail verification, not skip it")
	}
	if err := tryTunnel("proxy.example.test", "", "s3cret:pw"); err == nil {
		t.Fatal("untrusted (self-signed, no CA) listener certificate was accepted")
	}
	if err := tryTunnel("proxy.example.test", certPath, "wrong"); err == nil {
		t.Fatal("wrong proxy password was accepted")
	}
}
