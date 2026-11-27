package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/logger"
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
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

// Equals treats a legacy empty mode and an explicit file mode as the same
// source, so an API round-trip cannot restart a live listener. It never
// mutates either config.
func TestProxyPortTLSEqualsUsesEffectiveMode(t *testing.T) {
	legacy := &ProxyPortTLSConfig{CertFile: "a.crt", KeyFile: "a.key", ServerName: "proxy.example.test"}
	cloneTLS := func(c *ProxyPortTLSConfig) *ProxyPortTLSConfig {
		copy := *c
		return &copy
	}
	explicit := cloneTLS(legacy)
	explicit.Mode = " FILE "
	if !legacy.Equals(explicit) {
		t.Fatal("legacy empty mode must equal explicit file mode")
	}
	if legacy.Mode != "" || explicit.Mode != " FILE " {
		t.Fatal("Equals mutated a compared config")
	}
	pemMode := cloneTLS(legacy)
	pemMode.Mode = ProxyPortTLSModePEM
	pemMode.CertPEM, pemMode.KeyPEM = "cert", "key"
	pemMode.CertFile, pemMode.KeyFile = "", ""
	if legacy.Equals(pemMode) || pemMode.Equals(legacy) {
		t.Fatal("different TLS source modes must not compare equal")
	}
	if !pemMode.Equals(cloneTLS(pemMode)) {
		t.Fatal("identical PEM configs must compare equal")
	}
	pemMode.KeyPEM = "other key"
	if pemMode.Equals(&ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: "cert", KeyPEM: "key"}) {
		t.Fatal("different inline keys must not compare equal")
	}
	var nilTLS *ProxyPortTLSConfig
	if nilTLS.Equals(&ProxyPortTLSConfig{}) || !nilTLS.Equals(nil) {
		t.Fatal("nil TLS equality is wrong")
	}
}

func pemPairFromFiles(t *testing.T, certPath, keyPath string) (string, string) {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(certPEM), string(keyPEM)
}

// Inline PEM works as a full source; validity/name checks and source
// exclusivity apply just as they do in file mode. Legacy configs without an
// explicit mode stay in file mode.
func TestHTTPSPEMMode(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certPath, keyPath := writeHTTPSTestPair(t, dir, "inline", "proxy.example.test", now.Add(-time.Hour), now.Add(time.Hour))
	certPEM, keyPEM := pemPairFromFiles(t, certPath, keyPath)

	cfg := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: keyPEM, ServerName: "proxy.example.test"}
	serverTLS, err := cfg.ServerTLS()
	if err != nil {
		t.Fatalf("PEM ServerTLS: %v", err)
	}
	if len(serverTLS.Certificates) != 1 || len(serverTLS.Certificates[0].Certificate) != 1 {
		t.Fatalf("PEM certificates = %d, want exactly one", len(serverTLS.Certificates))
	}
	if !bytes.Equal(serverTLS.Certificates[0].Certificate[0], mustPEMBlock(t, certPEM).Bytes) {
		t.Fatal("PEM listener does not serve the configured certificate")
	}
	if serverTLS.GetCertificate != nil || serverTLS.Certificates[0].PrivateKey == nil {
		t.Fatal("PEM mode must carry a parsed static key pair, not a file reloader")
	}

	// Mixed case and whitespace normalize without mutating the config; the
	// legacy empty value also keeps working as file mode.
	mixedCase := &ProxyPortTLSConfig{Mode: " PeM ", CertPEM: certPEM, KeyPEM: keyPEM, ServerName: "proxy.example.test"}
	if _, err := mixedCase.ServerTLS(); err != nil {
		t.Fatalf("normalizable PEM mode failed: %v", err)
	}
	if mixedCase.Mode != " PeM " {
		t.Fatalf("validation mutated mode: %q", mixedCase.Mode)
	}
	if got := ProxyPortTLSMode(mixedCase); got != ProxyPortTLSModePEM {
		t.Fatalf("normalized mode = %q, want pem", got)
	}
	if got := ProxyPortTLSMode(&ProxyPortTLSConfig{}); got != ProxyPortTLSModeFile {
		t.Fatalf("legacy empty mode = %q, want file", got)
	}

	legacy := &ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: "proxy.example.test"}
	if _, err := legacy.ServerTLS(); err != nil {
		t.Fatalf("legacy file mode failed: %v", err)
	}
	if legacy.Mode != "" {
		t.Fatalf("legacy config mode was mutated to %q", legacy.Mode)
	}

	wrongName := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: keyPEM, ServerName: "wrong.example.test"}
	if _, err := wrongName.ServerTLS(); err == nil {
		t.Fatal("PEM certificate with wrong name was accepted")
	}
	if err := checkNoSecretLeak(wrongName); err != nil {
		t.Fatal(err)
	}

	expiredCert, expiredKey := writeHTTPSTestPair(t, dir, "expired", "proxy.example.test", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	expiredPEM, expiredKeyPEM := pemPairFromFiles(t, expiredCert, expiredKey)
	expired := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: expiredPEM, KeyPEM: expiredKeyPEM, ServerName: "proxy.example.test"}
	if _, err := expired.ServerTLS(); err == nil {
		t.Fatal("expired PEM certificate was accepted")
	}
	if err := checkNoSecretLeak(expired); err != nil {
		t.Fatal(err)
	}

	notYetValidCert, notYetValidKey := writeHTTPSTestPair(t, dir, "future", "proxy.example.test", now.Add(48*time.Hour), now.Add(72*time.Hour))
	futurePEM, futureKeyPEM := pemPairFromFiles(t, notYetValidCert, notYetValidKey)
	future := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: futurePEM, KeyPEM: futureKeyPEM, ServerName: "proxy.example.test"}
	if _, err := future.ServerTLS(); err == nil {
		t.Fatal("not-yet-valid PEM certificate was accepted")
	}

	otherCert, otherKey := writeHTTPSTestPair(t, dir, "other", "proxy.example.test", now.Add(-time.Hour), now.Add(time.Hour))
	_, otherKeyPEM := pemPairFromFiles(t, otherCert, otherKey)
	mismatched := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: otherKeyPEM, ServerName: "proxy.example.test"}
	if _, err := mismatched.ServerTLS(); err == nil {
		t.Fatal("mismatched PEM private key was accepted")
	}
	if err := checkNoSecretLeak(mismatched); err != nil {
		t.Fatal(err)
	}

	malformedKey := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: "not a key", ServerName: "proxy.example.test"}
	if _, err := malformedKey.ServerTLS(); err == nil {
		t.Fatal("invalid PEM key was accepted")
	}
	if err := checkNoSecretLeak(malformedKey); err != nil {
		t.Fatal(err)
	}

	// A hostile PEM block Type must never be echoed through an error or log.
	marker := "SECRET-MARKER-BLOCK-TYPE"
	hostileKey := pem.EncodeToMemory(&pem.Block{Type: marker, Bytes: []byte("secret")})
	hostile := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: string(hostileKey), ServerName: "proxy.example.test"}
	if err := checkNoSecretLeak(hostile, marker); err != nil {
		t.Fatal(err)
	}

	for _, mixed := range []*ProxyPortTLSConfig{
		{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: keyPEM, CertFile: certPath, ServerName: "proxy.example.test"},
		{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: keyPEM, KeyFile: keyPath, ServerName: "proxy.example.test"},
		{Mode: ProxyPortTLSModeFile, CertFile: certPath, KeyFile: keyPath, CertPEM: certPEM, ServerName: "proxy.example.test"},
		{Mode: ProxyPortTLSModeFile, CertFile: certPath, KeyFile: keyPath, KeyPEM: keyPEM, ServerName: "proxy.example.test"},
	} {
		if _, err := mixed.ServerTLS(); err == nil {
			t.Fatal("mixed PEM/file TLS sources were accepted")
		}
	}

	huge := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: strings.Repeat("x", maxInlineTLSPEMBytes+1), KeyPEM: keyPEM, ServerName: "proxy.example.test"}
	if _, err := huge.ServerTLS(); err == nil {
		t.Fatal("oversized PEM certificate was accepted")
	}
	hugeKey := &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: strings.Repeat("x", maxInlineTLSPEMBytes+1), ServerName: "proxy.example.test"}
	if _, err := hugeKey.ServerTLS(); err == nil {
		t.Fatal("oversized PEM key was accepted")
	}

	badMode := &ProxyPortTLSConfig{Mode: "inline", CertPEM: certPEM, KeyPEM: keyPEM, ServerName: "proxy.example.test"}
	if _, err := badMode.ServerTLS(); err == nil {
		t.Fatal("unsupported TLS mode was accepted")
	}
}

// checkNoSecretLeak captures validation errors and logs for a bad config and
// asserts that no caller-supplied PEM marker leaked through either channel.
func checkNoSecretLeak(cfg *ProxyPortTLSConfig, markers ...string) error {
	var buf bytes.Buffer
	logger.SetDefaultOutput(&buf)
	defer logger.SetDefaultOutput(os.Stdout)

	_, err := cfg.ServerTLS()
	if err == nil {
		return errors.New("expected validation to fail")
	}
	for _, marker := range append([]string{"PRIVATE KEY", "CERTIFICATE"}, markers...) {
		if strings.Contains(err.Error(), marker) || strings.Contains(buf.String(), marker) {
			return fmt.Errorf("validation disclosed PEM content (%q): error=%v, log=%s", marker, err, buf.String())
		}
	}
	return nil
}

func mustPEMBlock(t *testing.T, text string) *pem.Block {
	t.Helper()
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatal("PEM did not decode")
	}
	return block
}

// Config saving must round-trip inline PEM and tighten file permissions on
// POSIX; file mode keeps the ordinary 0644 config file.
func TestProxyPortPEMPersistenceAndPermissions(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certPath, keyPath := writeHTTPSTestPair(t, dir, "saved", "proxy.example.test", now.Add(-time.Hour), now.Add(time.Hour))
	certPEM, keyPEM := pemPairFromFiles(t, certPath, keyPath)

	path := filepath.Join(dir, "proxy_ports.json")
	mgr := NewProxyPortConfigManager(path)
	if err := mgr.Load(); err != nil {
		t.Fatal(err)
	}
	add := func(cfg *ProxyPortConfig) {
		t.Helper()
		if err := mgr.AddPort(cfg); err != nil {
			t.Fatal(err)
		}
	}
	add(&ProxyPortConfig{
		ID: "pem", Name: "pem", Type: ProxyPortTypeHTTPS, ListenAddr: "127.0.0.1:18443", Enabled: true,
		TLS: &ProxyPortTLSConfig{Mode: ProxyPortTLSModePEM, CertPEM: certPEM, KeyPEM: keyPEM, ServerName: "proxy.example.test"},
	})
	add(&ProxyPortConfig{
		ID: "file", Name: "file", Type: ProxyPortTypeHTTPS, ListenAddr: "127.0.0.1:18444", Enabled: true,
		TLS: &ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: "proxy.example.test"},
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"cert_pem"`, `"key_pem"`} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("saved config is missing %s", field)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("config permissions = %04o, want 0600", got)
		}
	}

	reloaded := NewProxyPortConfigManager(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.GetPort("pem")
	if !ok || got.TLS == nil {
		t.Fatal("inline PEM port did not round-trip")
	}
	if got.TLS.CertPEM != certPEM || got.TLS.KeyPEM != keyPEM || ProxyPortTLSMode(got.TLS) != ProxyPortTLSModePEM {
		t.Fatal("inline PEM values did not round-trip")
	}
	if _, err := got.TLS.ServerTLS(); err != nil {
		t.Fatalf("reloaded PEM config is invalid: %v", err)
	}
	if legacy, ok := reloaded.GetPort("file"); !ok || legacy.TLS.Mode != "" {
		t.Fatal("legacy file port did not round-trip unchanged")
	}

	// Re-saving without any inline key restores the default permissions.
	if err := reloaded.DeletePort("pem"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0644 {
			t.Fatalf("config permissions after removing PEM = %04o, want 0644", got)
		}
	}

	// Persistence is a deep copy: mutating a returned config must not change
	// the manager's stored PEM.
	clone, _ := reloaded.GetPort("file")
	clone.TLS.Mode = "pem"
	clone.TLS.CertPEM = certPEM
	clone.TLS.KeyPEM = keyPEM
	stored, _ := reloaded.GetPort("file")
	if stored.TLS.Mode != "" || stored.TLS.CertPEM != "" || stored.TLS.KeyPEM != "" {
		t.Fatal("GetPort returned a TLS config sharing storage with the manager")
	}
	if err := json.Unmarshal(data, &[]ProxyPortConfig{}); err != nil {
		t.Fatalf("saved config is not valid JSON: %v", err)
	}
}
