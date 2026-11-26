package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// writeHTTPSListenerPair writes a self-signed certificate valid for the test
// name with a distinct serial, so renewals are detectable by serial number.
func writeHTTPSListenerPair(t *testing.T, dir, name string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "proxy.example.test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"proxy.example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// The live HTTPS listener must serve a renewed certificate to new handshakes
// without being restarted, which keeps existing proxy tunnels untouched.
func TestHTTPSListenerServesRenewedCertificateWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeHTTPSListenerPair(t, dir, "old", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	port := freeListenPort(t)
	cfgMgr := config.NewProxyPortConfigManager(filepath.Join(dir, "proxy_ports.json"))
	if err := cfgMgr.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := &config.ProxyPortConfig{
		ID: "tls-live", Name: "tls-live", Type: config.ProxyPortTypeHTTPS,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Enabled: true,
		TLS: &config.ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: "proxy.example.test"},
	}
	if err := cfgMgr.AddPort(cfg); err != nil {
		t.Fatal(err)
	}
	mgr := NewProxyPortManager(cfgMgr, nil)
	defer mgr.Stop()
	if err := mgr.Start(true); err != nil {
		t.Fatalf("start: %v", err)
	}

	before := servedLeafSerial(t, cfg.ListenAddr)
	newCert, newKey := writeHTTPSListenerPair(t, dir, "new", time.Now().Add(-time.Minute), time.Now().Add(2*time.Hour))
	mustCopy(t, newCert, certPath)
	mustCopy(t, newKey, keyPath)
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(certPath, later, later)
	_ = os.Chtimes(keyPath, later, later)

	after := servedLeafSerial(t, cfg.ListenAddr)
	if before == after {
		t.Fatal("listener kept serving the pre-renewal certificate")
	}
	// The probe's connection is closed by the client; the listener should drain
	// it shortly after. Poll instead of asserting immediately to avoid a race.
	deadline := time.Now().Add(3 * time.Second)
	for mgr.GetActiveConnectionCountForPort(cfg.ID) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := mgr.GetActiveConnectionCountForPort(cfg.ID); got != 0 {
		t.Fatalf("probe connections leaked: %d", got)
	}
}

func servedLeafSerial(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "proxy.example.test", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
}

func mustCopy(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func freeListenPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
