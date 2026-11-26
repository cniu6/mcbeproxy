package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeHTTPSTestPair writes a CA-signed leaf certificate for dnsName, valid
// between notBefore and notAfter, and returns the cert and key file paths.
func writeHTTPSTestPair(t *testing.T, dir, name, dnsName string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func serveCertFingerprint(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	return cert.Certificate[0]
}

// The listener must pick up a renewed certificate without a restart, keep the
// previous one when the renewal is broken, and reject mismatched names up front.
func TestHTTPSCertificateHotReloadAndRejection(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certPath, keyPath := writeHTTPSTestPair(t, dir, "live", "proxy.example.test", now.Add(-time.Hour), now.Add(time.Hour))
	cfg := &ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: "proxy.example.test"}

	serverTLS, err := cfg.ServerTLS()
	if err != nil {
		t.Fatalf("ServerTLS: %v", err)
	}
	first := serveCertFingerprint(t, serverTLS)

	// Renewal: write a new pair over the same paths and bump the mtime.
	renewedCert, renewedKey := writeHTTPSTestPair(t, dir, "renewed", "proxy.example.test", now.Add(-time.Minute), now.Add(2*time.Hour))
	copyFile(t, renewedCert, certPath)
	copyFile(t, renewedKey, keyPath)
	later := now.Add(time.Minute)
	if err := os.Chtimes(certPath, later, later); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, later, later); err != nil {
		t.Fatal(err)
	}
	if string(serveCertFingerprint(t, serverTLS)) == string(first) {
		t.Fatal("renewed certificate was not picked up without restart")
	}
	renewedFP := serveCertFingerprint(t, serverTLS)

	// A broken renewal (truncated key) must keep serving the last good pair.
	if err := os.WriteFile(keyPath, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, later.Add(time.Minute), later.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if string(serveCertFingerprint(t, serverTLS)) != string(renewedFP) {
		t.Fatal("broken renewal dropped the working certificate")
	}

	// A certificate for another name is rejected before the listener starts.
	wrongCert, wrongKey := writeHTTPSTestPair(t, dir, "wrong", "other.example.test", now.Add(-time.Hour), now.Add(time.Hour))
	bad := &ProxyPortTLSConfig{CertFile: wrongCert, KeyFile: wrongKey, ServerName: "proxy.example.test"}
	if _, err := bad.ServerTLS(); err == nil {
		t.Fatal("mismatched certificate name was accepted")
	}

	// Expired certificate is rejected as well.
	expiredCert, expiredKey := writeHTTPSTestPair(t, dir, "expired", "proxy.example.test", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	expired := &ProxyPortTLSConfig{CertFile: expiredCert, KeyFile: expiredKey, ServerName: "proxy.example.test"}
	if _, err := expired.ServerTLS(); err == nil {
		t.Fatal("expired certificate was accepted")
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// Trust is scoped to the single connection configuration: a private CA file
// must be loadable, and an unreadable or empty CA file must fail loudly.
func TestHTTPSClientRootsScopedAndValidated(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certPath, _ := writeHTTPSTestPair(t, dir, "ca-src", "proxy.example.test", now.Add(-time.Hour), now.Add(time.Hour))
	caPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	pool, err := LoadHTTPProxyRoots(caPath)
	if err != nil || pool == nil {
		t.Fatalf("LoadHTTPProxyRoots(valid) = %v, %v", pool, err)
	}
	if none, err := LoadHTTPProxyRoots(""); err != nil || none != nil {
		t.Fatalf("empty path must mean system roots, got %v, %v", none, err)
	}
	if _, err := LoadHTTPProxyRoots(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing CA file was accepted")
	}
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("no certificate here"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHTTPProxyRoots(empty); err == nil {
		t.Fatal("CA file without PEM certificates was accepted")
	}
}
