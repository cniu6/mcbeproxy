package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// testCA holds a generated CA and its PEM bytes for writing to a file.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *testCA) writePEM(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, ca.pem, 0600); err != nil {
		t.Fatalf("write CA PEM: %v", err)
	}
	return path
}

func (ca *testCA) issueServerCert(t *testing.T, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	if ip := net.ParseIP(dnsNames[0]); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = dnsNames[1:]
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSHTTPConnectProxy starts an HTTP CONNECT proxy over TLS using the
// supplied certificate. It records the negotiated ALPN and the CONNECT
// request's HTTP version so tests can assert HTTP/1.1 behaviour.
func startTLSHTTPConnectProxy(t *testing.T, cert tls.Certificate, username, password string, onConnect func(proto string, req *http.Request)) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					return
				}
				handleTLSHTTPConnect(tlsConn, username, password, tlsConn.ConnectionState().NegotiatedProtocol, onConnect)
			}(c)
		}
	}()
	return ln.Addr()
}

func handleTLSHTTPConnect(c net.Conn, username, password, proto string, onConnect func(string, *http.Request)) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	if onConnect != nil {
		onConnect(proto, req)
	}
	authOK := username == ""
	if username != "" {
		user, pass, ok := req.BasicAuth()
		// HTTP CONNECT sends credentials in Proxy-Authorization; Go's
		// BasicAuth() reads Authorization, so check the raw header too.
		if !ok {
			raw := req.Header.Get("Proxy-Authorization")
			if strings.HasPrefix(raw, "Basic ") {
				decoded, err := decodeBasic(raw[6:])
				if err == nil {
					parts := strings.SplitN(decoded, ":", 2)
					if len(parts) == 2 {
						user, pass, ok = parts[0], parts[1], true
					}
				}
			}
		}
		authOK = ok && user == username && pass == password
	}
	if !authOK {
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go io.Copy(upstream, br)
	io.Copy(c, upstream)
}

func decodeBasic(s string) (string, error) {
	data, err := base64Decode(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func TestHTTPOverTLSWithCustomCA(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	cert := ca.issueServerCert(t, "proxy.test")
	echo := startTCPEcho(t)

	negotiated := make(chan string, 1)
	proxyAddr := startTLSHTTPConnectProxy(t, cert, "", "", func(proto string, _ *http.Request) {
		negotiated <- proto
	})
	host, port := splitHostPortConfig(t, proxyAddr)

	cfg := &config.ProxyOutbound{
		Name:      "https-proxy",
		Type:      config.ProtocolHTTP,
		Server:    host,
		Port:      port,
		TLS:       true,
		SNI:       "proxy.test", // SNI differs from server address 127.0.0.1
		TLSCAFile: ca.writePEM(t),
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
		t.Fatalf("dial via HTTPS proxy: %v", err)
	}
	defer conn.Close()

	want := []byte("tls-ca-ok")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
	if got := <-negotiated; got != "http/1.1" {
		t.Fatalf("CONNECT ALPN = %q, want http/1.1", got)
	}

	// The server prefers h2, so a browser fingerprint must not advertise it.
	cfg.Fingerprint = "chrome"
	fingerprinted, err := CreateSingboxDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer fingerprinted.Close()
	second, err := fingerprinted.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatalf("dial with fingerprint: %v", err)
	}
	defer second.Close()
	if got := <-negotiated; got != "http/1.1" {
		t.Fatalf("fingerprinted CONNECT ALPN = %q, want http/1.1", got)
	}
}

func TestHTTPSProxyInTCPChain(t *testing.T) {
	ca := newTestCA(t, "chain-ca")
	secure := startTLSHTTPConnectProxy(t, ca.issueServerCert(t, "chain.proxy.test"), "alice", "pass:word", nil)
	plain := startHTTPConnectProxy(t, "", "")
	secureHost, securePort := splitHostPortConfig(t, secure)
	plainHost, plainPort := splitHostPortConfig(t, plain)
	first := &config.ProxyOutbound{Name: "plain", Type: config.ProtocolHTTP, Server: plainHost, Port: plainPort, Enabled: true}
	second := &config.ProxyOutbound{
		Name: "https-hop", Type: config.ProtocolHTTP, Server: secureHost, Port: securePort, Enabled: true,
		TLS: true, SNI: "chain.proxy.test", TLSCAFile: ca.writePEM(t), Username: "alice", Password: "pass:word",
	}
	echo := startTCPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer, err := CreateChainDialer([]*config.ProxyOutbound{first, second})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()
	conn, err := dialer.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const message = "authenticated TLS hop in a TCP chain"
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != message {
		t.Fatalf("echo = %q, err = %v", got, err)
	}
}

func TestHTTPOverTLSSNI_MismatchRejectsUntrusted(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	cert := ca.issueServerCert(t, "proxy.test")
	echo := startTCPEcho(t)
	proxyAddr := startTLSHTTPConnectProxy(t, cert, "", "", nil)
	host, port := splitHostPortConfig(t, proxyAddr)

	// No CA configured: system roots do not trust the test CA. SNI != server
	// must NOT auto-enable insecure.
	cfg := &config.ProxyOutbound{
		Name:   "https-untrusted",
		Type:   config.ProtocolHTTP,
		Server: host,
		Port:   port,
		TLS:    true,
		SNI:    "proxy.test",
	}
	dialer, err := CreateSingboxDialer(cfg)
	if err != nil {
		t.Fatalf("create dialer: %v", err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "tcp", echo.String()); err == nil {
		t.Fatal("expected verification failure with untrusted CA and SNI mismatch")
	}
}

func TestHTTPOverTLSExplicitInsecure(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	cert := ca.issueServerCert(t, "proxy.test")
	echo := startTCPEcho(t)
	proxyAddr := startTLSHTTPConnectProxy(t, cert, "", "", nil)
	host, port := splitHostPortConfig(t, proxyAddr)

	cfg := &config.ProxyOutbound{
		Name:     "https-insecure",
		Type:     config.ProtocolHTTP,
		Server:   host,
		Port:     port,
		TLS:      true,
		SNI:      "wrong.name",
		Insecure: true,
	}
	dialer, err := CreateSingboxDialer(cfg)
	if err != nil {
		t.Fatalf("create dialer: %v", err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatalf("explicit insecure should connect, got: %v", err)
	}
	conn.Close()
}

func TestHTTPProxyTLSConfigSessionCacheIsolation(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	caFile := ca.writePEM(t)

	cfg := &config.ProxyOutbound{
		Name:      "with-ca",
		Type:      config.ProtocolHTTP,
		Server:    "127.0.0.1",
		Port:      443,
		TLS:       true,
		SNI:       "proxy.test",
		TLSCAFile: caFile,
	}
	tlsCfg, utlsCfg, err := httpProxyTLSConfig(cfg)
	if err != nil {
		t.Fatalf("httpProxyTLSConfig: %v", err)
	}
	if tlsCfg.ClientSessionCache != nil || utlsCfg.ClientSessionCache != nil {
		t.Fatal("custom CA must disable session cache to avoid cross-trust resumption")
	}
	if tlsCfg.RootCAs == nil || utlsCfg.RootCAs == nil {
		t.Fatal("custom CA must set RootCAs")
	}
	if tlsCfg.ServerName != "proxy.test" {
		t.Fatalf("ServerName = %q, want proxy.test", tlsCfg.ServerName)
	}
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("NextProtos = %v, want [http/1.1]", tlsCfg.NextProtos)
	}

	// No CA: system roots, session cache enabled for standard TLS.
	cfg2 := &config.ProxyOutbound{Name: "system", Type: config.ProtocolHTTP, Server: "127.0.0.1", Port: 443, TLS: true, SNI: "proxy.test"}
	tlsCfg2, _, err := httpProxyTLSConfig(cfg2)
	if err != nil {
		t.Fatalf("httpProxyTLSConfig no CA: %v", err)
	}
	if tlsCfg2.ClientSessionCache == nil {
		t.Fatal("system trust should use the shared session cache")
	}
}

func TestHTTPProxyTLSConfigValidation(t *testing.T) {
	// CA on non-TLS HTTP is rejected by config.Validate.
	cfg := &config.ProxyOutbound{Name: "x", Type: config.ProtocolHTTP, Server: "127.0.0.1", Port: 8080, TLSCAFile: "ca.pem"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for tls_ca_file without tls")
	}
	// CA + Insecure is rejected.
	cfg = &config.ProxyOutbound{Name: "x", Type: config.ProtocolHTTP, Server: "127.0.0.1", Port: 443, TLS: true, Insecure: true, TLSCAFile: "ca.pem"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for tls_ca_file with insecure")
	}
	// Valid combination.
	cfg = &config.ProxyOutbound{Name: "x", Type: config.ProtocolHTTP, Server: "127.0.0.1", Port: 443, TLS: true, TLSCAFile: "ca.pem"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestNativeOverMihomoWithCustomCA(t *testing.T) {
	cfg := &config.ProxyOutbound{
		Name:   "mihomo-forced",
		Type:   config.ProtocolHTTP,
		Server: "127.0.0.1",
		Port:   443,
		TLS:    true,
		ProviderOptions: map[string]interface{}{
			"core": "mihomo",
		},
	}
	if !supportsMihomo(cfg) {
		t.Fatal("without CA, core=mihomo should route to mihomo")
	}
	cfg.TLSCAFile = "ca.pem"
	if supportsMihomo(cfg) {
		t.Fatal("custom CA must force native HTTP dialer")
	}
}

func TestCacheKeyIncludesTLSCAFile(t *testing.T) {
	base := &config.ProxyOutbound{Name: "x", Type: config.ProtocolHTTP, Server: "127.0.0.1", Port: 443, TLS: true, SNI: "proxy.test"}
	k1 := proxyOutboundDialerCacheKey(base)
	withCA := base.Clone()
	withCA.TLSCAFile = "ca.pem"
	k2 := proxyOutboundDialerCacheKey(withCA)
	if k1 == k2 {
		t.Fatal("cache key must differ when tls_ca_file changes")
	}
	// Clone must carry the field.
	cloned := withCA.Clone()
	if cloned.TLSCAFile != "ca.pem" {
		t.Fatal("Clone must preserve tls_ca_file")
	}
	if !cloned.Equal(withCA) {
		t.Fatal("Equal must treat identical tls_ca_file as equal")
	}
	if withCA.Equal(base) {
		t.Fatal("Equal must detect tls_ca_file difference")
	}
}

// base64Decode is a small helper for the in-process proxy test server.
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
