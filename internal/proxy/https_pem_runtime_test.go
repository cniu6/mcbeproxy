package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// httpsPEMPortFixture is a loopback HTTPS proxy port backed by inline PEM.
// Every fixture owns its config file, manager and listener; cleanup stops them.
type httpsPEMPortFixture struct {
	cfgPath  string
	cfgMgr   *config.ProxyPortConfigManager
	mgr      *ProxyPortManager
	portCfg  *config.ProxyPortConfig
	addr     string
	ca       *testCA
	certPEM  string
	keyPEM   string
	otherPEM string
	otherKey string
	echoAddr string
}

func newHTTPSPEMPortFixture(t *testing.T) *httpsPEMPortFixture {
	t.Helper()
	dir := t.TempDir()
	ca := newTestCA(t, "pem-proxy-ca")
	leaf := ca.issueServerCert(t, "proxy.example.test")
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	// A second pair with a distinct serial, to prove a reload replaced the
	// listener's certificate rather than merely re-reading the same one.
	other := ca.issueServerCert(t, "proxy.example.test")
	otherKeyDER, err := x509.MarshalPKCS8PrivateKey(other.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Certificate[0]}))
	otherKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherKeyDER}))

	cfgPath := filepath.Join(dir, "proxy_ports.json")
	cfgMgr := config.NewProxyPortConfigManager(cfgPath)
	if err := cfgMgr.Load(); err != nil {
		t.Fatal(err)
	}
	port := freeListenPort(t)
	portCfg := &config.ProxyPortConfig{
		ID: "https-pem", Name: "https-pem", Type: config.ProxyPortTypeHTTPS,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Enabled: true,
		Username: "alice", Password: "s3cret:pw",
		TLS: &config.ProxyPortTLSConfig{
			Mode: config.ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: keyPEM,
			ServerName: "proxy.example.test", CAFile: ca.writePEM(t),
		},
	}
	if err := cfgMgr.AddPort(portCfg); err != nil {
		t.Fatal(err)
	}
	mgr := NewProxyPortManager(cfgMgr, nil)
	if err := mgr.Start(true); err != nil {
		t.Fatalf("start HTTPS PEM port: %v", err)
	}
	f := &httpsPEMPortFixture{
		cfgPath: cfgPath, cfgMgr: cfgMgr, mgr: mgr, portCfg: portCfg.Clone(),
		addr: portCfg.ListenAddr, ca: ca, certPEM: certPEM, keyPEM: keyPEM,
		otherPEM: otherPEM, otherKey: otherKey, echoAddr: startTCPEcho(t).String(),
	}
	t.Cleanup(f.mgr.Stop)
	return f
}

// tlsDial performs a fully verified handshake with the loopback proxy. The
// proxy's own ClientTLS contract is the model: pinned CA plus exact name.
func (f *httpsPEMPortFixture) tlsDial(t *testing.T) *tls.Conn {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(f.ca.pem) {
		t.Fatal("test CA PEM not loadable")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", f.addr, &tls.Config{
		RootCAs: roots, ServerName: "proxy.example.test", NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("verified TLS handshake to HTTPS PEM proxy failed: %v", err)
	}
	return conn
}

func (f *httpsPEMPortFixture) update(t *testing.T, mutate func(*config.ProxyPortConfig)) {
	t.Helper()
	next := f.portCfg.Clone()
	mutate(next)
	if err := f.cfgMgr.UpdatePort(f.portCfg.ID, next); err != nil {
		t.Fatalf("update config: %v", err)
	}
	f.portCfg = next.Clone()
	if err := f.cfgMgr.Reload(); err != nil {
		t.Fatalf("reload config file: %v", err)
	}
	if err := f.mgr.Reload(true); err != nil {
		t.Fatalf("reload HTTPS PEM listener: %v", err)
	}
}

func (f *httpsPEMPortFixture) listener(t *testing.T) *proxyPortListener {
	t.Helper()
	f.mgr.mu.Lock()
	defer f.mgr.mu.Unlock()
	l := f.mgr.listeners[f.portCfg.ID]
	if l == nil {
		t.Fatal("HTTPS PEM listener is not running")
	}
	return l
}

// tunnelEcho sends an HTTP CONNECT through the verified TLS listener and
// checks that bytes reach the loopback echo server and come back.
func (f *httpsPEMPortFixture) tunnelEcho(t *testing.T, conn *tls.Conn) {
	t.Helper()
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic YWxpY2U6czNjcmV0OnB3\r\n\r\n", f.echoAddr, f.echoAddr)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT through HTTPS PEM proxy failed: %q, %v", status, err)
	}
	// The 200 line is followed by an empty CRLF line before tunnel bytes.
	blank, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(blank) != "" {
		t.Fatalf("unexpected CONNECT header footer: %q, %v", blank, err)
	}
	const msg = "pem-tunnel-ok"
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatal(err)
	}
	// reader already buffered tunnel bytes; keep reading from it.
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != msg {
		t.Fatalf("tunnel echo = %q, %v; want %q", got, err, msg)
	}
}

// A valid inline PEM config must yield a working HTTPS forward proxy with a
// certificate the client can verify against the pinned CA.
func TestHTTPSPEMPortForwardsWithVerifiedHandshake(t *testing.T) {
	f := newHTTPSPEMPortFixture(t)
	conn := f.tlsDial(t)
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1", got)
	}
	f.tunnelEcho(t, conn)
}

// An inline fullchain (leaf first, CA second) must build a live listener that
// a CA-only client can verify, without any certificate files on the server.
func TestHTTPSPEMPortAcceptsFullchainForCAOnlyClient(t *testing.T) {
	f := newHTTPSPEMPortFixture(t)
	fullchain := f.certPEM + string(f.ca.pem)
	f.update(t, func(cfg *config.ProxyPortConfig) {
		cfg.TLS.CertPEM = fullchain
		cfg.TLS.KeyPEM = f.keyPEM
	})
	conn := f.tlsDial(t)
	defer conn.Close()
	if got := conn.ConnectionState().VerifiedChains; len(got) == 0 {
		t.Fatal("CA-only client did not verify the inline fullchain listener")
	}
}

// Reload with a valid new PEM pair must replace the listener; a later invalid
// replacement must leave the good listener running and forwarding.
func TestHTTPSPEMPortReloadValidAndRetainsOnInvalid(t *testing.T) {
	f := newHTTPSPEMPortFixture(t)
	before := f.listener(t)

	f.update(t, func(cfg *config.ProxyPortConfig) {
		cfg.TLS.CertPEM = f.otherPEM
		cfg.TLS.KeyPEM = f.otherKey
	})
	after := f.listener(t)
	if before == after {
		t.Fatal("valid PEM update did not restart the HTTPS listener")
	}
	if err := f.cfgMgr.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := f.listener(t); got != after {
		t.Fatal("an unchanged reload must preserve the listener")
	}
	conn := f.tlsDial(t)
	_ = conn.Close()

	invalid := f.portCfg.Clone()
	invalid.TLS.KeyPEM = "not a key"
	if err := f.cfgMgr.UpdatePort(invalid.ID, invalid); err != nil {
		t.Fatal(err)
	}
	if err := f.cfgMgr.Reload(); err != nil {
		t.Fatal(err)
	}
	// The manager deliberately keeps the bad config on disk while the proxy
	// runtime retains the last good listener. Drive the runtime reload directly.
	if err := f.mgr.Reload(true); err == nil {
		t.Fatal("invalid PEM replacement was accepted by the runtime reload")
	}
	if got := f.listener(t); got != after {
		t.Fatal("invalid PEM replacement must not take down the live listener")
	}
	probe := f.tlsDial(t)
	defer probe.Close()
	f.tunnelEcho(t, probe)
}

// Switching source modes must restart the port with the new certificate
// source, and an identical reload must then be a no-op.
func TestHTTPSPEMPortSwitchesModes(t *testing.T) {
	f := newHTTPSPEMPortFixture(t)
	certPath := filepath.Join(filepath.Dir(f.cfgPath), "switched.crt")
	keyPath := filepath.Join(filepath.Dir(f.cfgPath), "switched.key")
	if err := os.WriteFile(certPath, []byte(f.otherPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(f.otherKey), 0600); err != nil {
		t.Fatal(err)
	}
	caFile := f.portCfg.TLS.CAFile
	pemListener := f.listener(t)

	f.update(t, func(cfg *config.ProxyPortConfig) {
		cfg.TLS = &config.ProxyPortTLSConfig{
			Mode: config.ProxyPortTLSModeFile, CertFile: certPath, KeyFile: keyPath,
			ServerName: "proxy.example.test", CAFile: caFile,
		}
	})
	fileListener := f.listener(t)
	if fileListener == pemListener {
		t.Fatal("switching from PEM to file mode did not replace the listener")
	}
	conn := f.tlsDial(t)
	_ = conn.Close()

	f.update(t, func(cfg *config.ProxyPortConfig) {
		cfg.TLS = &config.ProxyPortTLSConfig{
			Mode: config.ProxyPortTLSModePEM, CertPEM: f.certPEM, KeyPEM: f.keyPEM,
			ServerName: "proxy.example.test", CAFile: caFile,
		}
	})
	if got := f.listener(t); got == fileListener {
		t.Fatal("switching from file to PEM mode did not replace the listener")
	}
	conn = f.tlsDial(t)
	_ = conn.Close()

	// Effective-mode equality must see equivalent configs as unchanged.
	stable := f.listener(t)
	f.update(t, func(*config.ProxyPortConfig) {})
	if got := f.listener(t); got != stable {
		t.Fatal("unchanged PEM config caused a spurious listener reload")
	}
}
