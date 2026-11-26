package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLoadHTTPProxyRootsRelativePath(t *testing.T) {
	// Relative paths are loaded from the server's current working directory.
	tmp := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	if err := os.WriteFile("ca.pem", testCAPEM(t), 0600); err != nil {
		t.Fatalf("write ca.pem: %v", err)
	}
	pool, err := LoadHTTPProxyRoots("ca.pem")
	if err != nil {
		t.Fatalf("LoadHTTPProxyRoots relative: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool for relative CA file")
	}
	// Empty path always means system trust (nil pool).
	pool, err = LoadHTTPProxyRoots("  ")
	if err != nil || pool != nil {
		t.Fatalf("LoadHTTPProxyRoots empty = %v, %v; want nil, nil", pool, err)
	}
	// Absolute paths also work.
	abs := filepath.Join(tmp, "ca.pem")
	pool, err = LoadHTTPProxyRoots(abs)
	if err != nil || pool == nil {
		t.Fatalf("LoadHTTPProxyRoots absolute = %v, %v; want non-nil", pool, err)
	}
}

func TestProxyOutboundTLSCAFileJSONRoundTrip(t *testing.T) {
	raw := `{"name":"https","type":"http","server":"127.0.0.1","port":8443,"tls":true,"sni":"proxy.example","tls_ca_file":"certs/private-ca.pem"}`
	cfg, err := FromJSON([]byte(raw))
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	if cfg.TLSCAFile != "certs/private-ca.pem" {
		t.Fatalf("TLSCAFile = %q", cfg.TLSCAFile)
	}
	data, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if !strings.Contains(string(data), `"tls_ca_file":"certs/private-ca.pem"`) {
		t.Fatalf("serialized JSON missing tls_ca_file: %s", data)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestProxyOutboundTLSCAFileValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ProxyOutbound
		want bool
	}{
		{"http no tls with ca", &ProxyOutbound{Name: "x", Type: ProtocolHTTP, Server: "127.0.0.1", Port: 8080, TLSCAFile: "ca.pem"}, true},
		{"http tls insecure with ca", &ProxyOutbound{Name: "x", Type: ProtocolHTTP, Server: "127.0.0.1", Port: 443, TLS: true, Insecure: true, TLSCAFile: "ca.pem"}, true},
		{"http tls with ca", &ProxyOutbound{Name: "x", Type: ProtocolHTTP, Server: "127.0.0.1", Port: 443, TLS: true, TLSCAFile: "ca.pem"}, false},
		{"socks5 tls with ca", &ProxyOutbound{Name: "x", Type: ProtocolSOCKS5, Server: "127.0.0.1", Port: 443, TLS: true, TLSCAFile: "ca.pem"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.want {
				t.Fatalf("Validate() error = %v, want error = %v", err, tc.want)
			}
		})
	}
}

func TestProxyOutboundTLSCAFileCloneEqual(t *testing.T) {
	a := &ProxyOutbound{Name: "x", Type: ProtocolHTTP, Server: "127.0.0.1", Port: 443, TLS: true, TLSCAFile: "ca.pem"}
	b := a.Clone()
	if b.TLSCAFile != a.TLSCAFile {
		t.Fatalf("Clone lost TLSCAFile: %q", b.TLSCAFile)
	}
	if !a.Equal(b) {
		t.Fatal("Equal should treat clones as equal")
	}
	b.TLSCAFile = "other.pem"
	if a.Equal(b) {
		t.Fatal("Equal should detect TLSCAFile change")
	}
	// Ensure JSON marshal/unmarshal preserves it through the generic path.
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var c ProxyOutbound
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.TLSCAFile != "ca.pem" {
		t.Fatalf("JSON roundtrip lost TLSCAFile: %q", c.TLSCAFile)
	}
}
