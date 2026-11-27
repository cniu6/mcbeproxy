package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

func apiTestPEMTLS(t *testing.T) *config.ProxyPortTLSConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "proxy.example.test"},
		DNSNames:     []string{"proxy.example.test"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &config.ProxyPortTLSConfig{
		Mode:       config.ProxyPortTLSModePEM,
		CertPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		ServerName: "proxy.example.test",
	}
}

func pemAPIRequest(t *testing.T, r http.Handler, method, path string, data any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func assertPEMHidden(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(w.Body.String(), "-----BEGIN") || strings.Contains(w.Body.String(), `"cert_pem":`) || strings.Contains(w.Body.String(), `"key_pem":`) {
		t.Fatal("response exposed a PEM body or write-only field")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("response with certificate settings must not be cached")
	}
}

func TestHTTPSPEMAPIWriteOnlyAndPreserve(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "ports.json")
	cm := config.NewProxyPortConfigManager(path)
	a := &APIServer{proxyPortConfigMgr: cm}
	r := gin.New()
	r.POST("/ports", a.createProxyPort)
	r.POST("/ports/bulk", a.createProxyPortsBulk)
	r.GET("/ports", a.getProxyPorts)
	r.GET("/ports/:id/runtime", a.getProxyPortRuntime)
	r.PUT("/ports/:id", a.updateProxyPort)
	r.POST("/ports/:id/share", a.shareProxyPort)
	r.POST("/ports/bulk-share", a.shareProxyPortsBulk)
	r.POST("/ports/:id/export", a.exportSecurePort)

	cfg := &config.ProxyPortConfig{ID: "inline", Name: "inline", Type: "https", Enabled: true,
		ListenAddr: "127.0.0.1:18443", Username: "test-user", Password: "test-password", TLS: apiTestPEMTLS(t)}
	w := pemAPIRequest(t, r, "POST", "/ports", cfg)
	if w.Code != http.StatusOK {
		t.Fatalf("create status=%d: %s", w.Code, w.Body.String())
	}
	assertPEMHidden(t, w)
	var created struct {
		Data proxyPortConfigDTO `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.TLS == nil || created.Data.TLS.Mode != "pem" || !created.Data.TLS.HasCertPEM || !created.Data.TLS.HasKeyPEM {
		t.Fatal("create response lost configured PEM flags")
	}
	saved, ok := cm.GetPort(cfg.ID)
	if !ok || saved.TLS.KeyPEM != cfg.TLS.KeyPEM || saved.TLS.CertPEM != cfg.TLS.CertPEM {
		t.Fatal("PEM material not saved")
	}
	reloaded := config.NewProxyPortConfigManager(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	restored, ok := reloaded.GetPort(cfg.ID)
	if !ok || restored.TLS.KeyPEM != cfg.TLS.KeyPEM {
		t.Fatal("PEM key did not survive disk reload")
	}
	w = pemAPIRequest(t, r, "GET", "/ports", nil)
	assertPEMHidden(t, w)
	var listed struct {
		Data []proxyPortListDTO `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Data) != 1 || listed.Data[0].ID != cfg.ID || !listed.Data[0].TLS.HasKeyPEM {
		t.Fatal("list response lost flat config fields or PEM flags")
	}
	// Save exactly what a fresh list supplies; no private key is in the DTO.
	edit := listed.Data[0].proxyPortConfigDTO
	edit.Name = "renamed"
	edit.Enabled = false
	w = pemAPIRequest(t, r, "PUT", "/ports/inline", edit)
	if w.Code != http.StatusOK {
		t.Fatalf("roundtrip status=%d: %s", w.Code, w.Body.String())
	}
	assertPEMHidden(t, w)
	after, _ := cm.GetPort(cfg.ID)
	if after.TLS.KeyPEM != saved.TLS.KeyPEM || after.TLS.CertPEM != saved.TLS.CertPEM || after.Enabled || after.Name != "renamed" {
		t.Fatal("list/update roundtrip erased certificate material or lost unrelated changes")
	}

	edit.Enabled = true
	w = pemAPIRequest(t, r, "PUT", "/ports/inline", edit)
	if w.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	assertPEMHidden(t, w)
	w = pemAPIRequest(t, r, "GET", "/ports/inline/runtime", nil)
	assertPEMHidden(t, w)
	for _, format := range []string{"links", "clash"} {
		w = pemAPIRequest(t, r, "POST", "/ports/inline/share", map[string]any{"format": format, "address": "proxy.example.test:18443"})
		if w.Code != http.StatusOK {
			t.Fatalf("share %s status=%d", format, w.Code)
		}
		assertPEMHidden(t, w)
		w = pemAPIRequest(t, r, "POST", "/ports/bulk-share", map[string]any{"format": format, "host": "proxy.example.test", "ids": []string{"inline"}})
		if w.Code != http.StatusOK {
			t.Fatalf("bulk share %s status=%d", format, w.Code)
		}
		assertPEMHidden(t, w)
	}
	w = pemAPIRequest(t, r, "POST", "/ports/inline/export", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("secure export unexpectedly accepted HTTPS: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("secure export leaked key")
	}

	// A bad replacement must leave both saved material and metadata unchanged.
	bad := after.Clone()
	bad.Enabled = true
	bad.TLS.KeyPEM = "not-a-private-key-SENSITIVE"
	w = pemAPIRequest(t, r, "PUT", "/ports/inline", bad)
	if w.Code != http.StatusBadRequest {
		t.Fatal("bad PEM replacement accepted")
	}
	assertPEMHidden(t, w)
	if strings.Contains(w.Body.String(), bad.TLS.KeyPEM) {
		t.Fatal("invalid key echoed")
	}
	afterBad, _ := cm.GetPort(cfg.ID)
	if afterBad.TLS.KeyPEM != saved.TLS.KeyPEM {
		t.Fatal("bad replacement overwrote saved key")
	}

	bulk := cfg.Clone()
	bulk.ID, bulk.Name, bulk.ListenAddr = "inline-bulk", "bulk", "127.0.0.1:18444"
	w = pemAPIRequest(t, r, "POST", "/ports/bulk", bulkCreateProxyPortsRequest{Ports: []*config.ProxyPortConfig{bulk}})
	if w.Code != http.StatusOK {
		t.Fatalf("bulk: %d %s", w.Code, w.Body.String())
	}
	assertPEMHidden(t, w)
	var bulkResult struct {
		Data []proxyPortConfigDTO `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &bulkResult); err != nil {
		t.Fatal(err)
	}
	if len(bulkResult.Data) != 1 || !bulkResult.Data[0].TLS.HasKeyPEM {
		t.Fatal("bulk response missing flags")
	}
}

func TestHTTPSPEMUpdateModes(t *testing.T) {
	pair := apiTestPEMTLS(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte(pair.CertPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(pair.KeyPEM), 0600); err != nil {
		t.Fatal(err)
	}
	fileTLS := &config.ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, ServerName: pair.ServerName}
	file := &config.ProxyPortConfig{ID: "file", Name: "file", Type: "https", Enabled: true, ListenAddr: "127.0.0.1:18443", TLS: fileTLS}
	inline := file.Clone()
	inline.TLS = pair

	t.Run("omitted TLS preserves full configuration", func(t *testing.T) {
		p := inline.Clone()
		p.TLS = nil
		if err := prepareHTTPSProxyPort(p, inline); err != nil {
			t.Fatal(err)
		}
		if p.TLS == inline.TLS || p.TLS.KeyPEM != pair.KeyPEM {
			t.Fatal("TLS not cloned and preserved")
		}
	})
	t.Run("same PEM mode blanks preserve", func(t *testing.T) {
		p := inline.Clone()
		p.TLS.CertPEM, p.TLS.KeyPEM = "\n", ""
		if err := prepareHTTPSProxyPort(p, inline); err != nil {
			t.Fatal(err)
		}
		if p.TLS.CertPEM != pair.CertPEM || p.TLS.KeyPEM != pair.KeyPEM {
			t.Fatal("blanks erased PEM")
		}
	})
	t.Run("only new certificate preserves key", func(t *testing.T) {
		p := inline.Clone()
		p.TLS.KeyPEM = ""
		if err := prepareHTTPSProxyPort(p, inline); err != nil {
			t.Fatal(err)
		}
		if p.TLS.KeyPEM != pair.KeyPEM {
			t.Fatal("blank key not preserved")
		}
	})
	t.Run("file to PEM clears file source", func(t *testing.T) {
		p := file.Clone()
		p.TLS.Mode = "pem"
		p.TLS.CertPEM, p.TLS.KeyPEM = pair.CertPEM, pair.KeyPEM
		if err := prepareHTTPSProxyPort(p, file); err != nil {
			t.Fatal(err)
		}
		if p.TLS.CertFile != "" || p.TLS.KeyFile != "" {
			t.Fatal("switch retained old file paths")
		}
	})
	t.Run("PEM to file clears inline source", func(t *testing.T) {
		p := inline.Clone()
		p.TLS.Mode = "file"
		p.TLS.CertFile, p.TLS.KeyFile = certPath, keyPath
		if err := prepareHTTPSProxyPort(p, inline); err != nil {
			t.Fatal(err)
		}
		if p.TLS.CertPEM != "" || p.TLS.KeyPEM != "" {
			t.Fatal("switch retained old inline key")
		}
	})
	t.Run("incomplete source cannot reuse another mode", func(t *testing.T) {
		for _, old := range []*config.ProxyPortConfig{file, inline} {
			p := old.Clone()
			p.TLS.Mode = "pem"
			if old == inline {
				p.TLS.Mode = "file"
			}
			if err := prepareHTTPSProxyPort(p, old); err == nil {
				t.Fatal("incomplete mode switch accepted")
			}
		}
	})
	t.Run("legacy omitted mode is file", func(t *testing.T) {
		p := inline.Clone()
		p.TLS = &config.ProxyPortTLSConfig{ServerName: pair.ServerName}
		if err := prepareHTTPSProxyPort(p, inline); err == nil {
			t.Fatal("missing mode inferred PEM")
		}
	})
	t.Run("same-mode mixed sources rejected", func(t *testing.T) {
		p := inline.Clone()
		p.TLS.CertFile = certPath
		if err := prepareHTTPSProxyPort(p, inline); err == nil {
			t.Fatal("mixed sources accepted")
		}
	})
	t.Run("disable still works when TLS files disappear", func(t *testing.T) {
		p := file.Clone()
		p.Enabled = false
		p.TLS.KeyFile = filepath.Join(dir, "missing")
		if err := prepareHTTPSProxyPort(p, file); err != nil {
			t.Fatal(err)
		}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHTTPSPEMRequestErrorsDoNotEchoSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &APIServer{proxyPortConfigMgr: config.NewProxyPortConfigManager(filepath.Join(t.TempDir(), "ports.json"))}
	r := gin.New()
	r.POST("/ports", a.createProxyPort)
	w := pemAPIRequest(t, r, "POST", "/ports", map[string]any{"type": "https", "enabled": "SECRET-PEM-VALUE"})
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "SECRET-PEM-VALUE") {
		t.Fatal("JSON error exposed submitted value")
	}
	assertPEMHidden(t, w)
}

func TestRunProxyPortConnectivityTest_HTTPSPEM(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked to origin")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	dir := t.TempDir()
	cfg := &config.ProxyPortConfig{ID: "inline", Name: "inline", Type: "https", Enabled: true,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))),
		Username:   "test-user", Password: "test-password", TLS: apiTestPEMTLS(t)}
	cfg.TLS.CAFile = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(cfg.TLS.CAFile, []byte(cfg.TLS.CertPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepareHTTPSProxyPort(cfg, nil); err != nil {
		t.Fatal(err)
	}
	cm := config.NewProxyPortConfigManager(filepath.Join(dir, "ports.json"))
	if err := cm.AddPort(cfg); err != nil {
		t.Fatal(err)
	}
	mgr := proxy.NewProxyPortManager(cm, nil)
	t.Cleanup(mgr.Stop)
	if err := mgr.Start(true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*config.ProxyPortConfig)
	}{
		{name: "trusted PEM forwards"},
		{name: "wrong password", want: "407", change: func(p *config.ProxyPortConfig) { p.Password = "wrong" }},
		{name: "untrusted certificate", want: "HTTPS proxy TLS", change: func(p *config.ProxyPortConfig) { p.TLS.CAFile = "" }},
		{name: "wrong server name", want: "HTTPS proxy TLS", change: func(p *config.ProxyPortConfig) { p.TLS.ServerName = "wrong.example.test" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := cfg.Clone()
			if tc.change != nil {
				tc.change(p)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var out testProxyPortResult
			runProxyPortConnectivityTest(ctx, p, origin.URL, &out)
			if tc.want == "" {
				if !out.Success || out.StatusCode != http.StatusNoContent {
					t.Fatalf("test failed: %+v", out)
				}
			} else if out.Success || !strings.Contains(out.Error, tc.want) {
				t.Fatalf("want %q: %+v", tc.want, out)
			}
		})
	}
}
