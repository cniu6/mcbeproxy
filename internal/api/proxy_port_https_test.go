package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

func TestRunProxyPortConnectivityTest_HTTPS(t *testing.T) {
	dir := t.TempDir()
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("origin received proxy credentials")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer fixture.Close()
	pair := fixture.TLS.Certificates[0]
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) == 0 {
		t.Fatal("test certificate has no DNS names")
	}
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}

	ports := config.NewProxyPortConfigManager(filepath.Join(dir, "proxy_ports.json"))
	cfg := &config.ProxyPortConfig{
		ID: "https-test", Name: "https-test", Type: config.ProxyPortTypeHTTPS,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))), Enabled: true,
		Username: "proxy-user", Password: "password:test",
		TLS: &config.ProxyPortTLSConfig{CertFile: certPath, KeyFile: keyPath, CAFile: certPath, ServerName: cert.DNSNames[0]},
	}
	if err := prepareHTTPSProxyPort(cfg, nil); err != nil {
		t.Fatal(err)
	}
	if err := ports.AddPort(cfg); err != nil {
		t.Fatal(err)
	}
	mgr := proxy.NewProxyPortManager(ports, nil)
	defer mgr.Stop()
	if err := mgr.Start(true); err != nil {
		t.Fatal(err)
	}

	httpOrigin := httptest.NewServer(fixture.Config.Handler)
	defer httpOrigin.Close()
	for _, tt := range []struct {
		name   string
		target string
		change func(*config.ProxyPortConfig)
		want   string
	}{
		{name: "HTTP forward", target: httpOrigin.URL},
		{name: "HTTPS CONNECT", target: fixture.URL},
		{name: "wrong password", target: fixture.URL, change: func(p *config.ProxyPortConfig) { p.Password = "not-the-password" }, want: "Proxy Authentication Required"},
		{name: "no password", target: httpOrigin.URL, change: func(p *config.ProxyPortConfig) { p.Username, p.Password = "", "" }, want: "407"},
		{name: "untrusted", target: fixture.URL, change: func(p *config.ProxyPortConfig) { p.TLS.CAFile = "" }, want: "HTTPS proxy TLS"},
		{name: "wrong name", target: fixture.URL, change: func(p *config.ProxyPortConfig) { p.TLS.ServerName = "wrong.example.invalid" }, want: "HTTPS proxy TLS"},
		{name: "no plaintext", target: httpOrigin.URL, change: func(p *config.ProxyPortConfig) { p.Type = config.ProxyPortTypeHTTP }, want: "EOF"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := cfg.Clone()
			if tt.change != nil {
				tt.change(client)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var out testProxyPortResult
			runProxyPortConnectivityTest(ctx, client, tt.target, &out)
			if tt.want == "" {
				if !out.Success || out.StatusCode != http.StatusNoContent {
					t.Fatalf("proxy test failed: %+v", out)
				}
			} else if out.Success || !strings.Contains(out.Error, tt.want) {
				t.Fatalf("wanted error with %q, got %+v", tt.want, out)
			}
		})
	}

	// An invalid certificate replacement from a file reload must not discard
	// the working listener or block unrelated ports.
	replacement := cfg.Clone()
	replacement.TLS.KeyFile = filepath.Join(dir, "missing-key.pem")
	if err := prepareHTTPSProxyPort(replacement, cfg); err == nil {
		t.Fatal("API preflight accepted missing key")
	}
	if err := ports.UpdatePort(cfg.ID, replacement); err != nil {
		t.Fatal(err)
	}
	plain := &config.ProxyPortConfig{ID: "plain", Name: "plain", Type: config.ProxyPortTypeHTTP,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))), Enabled: true}
	if err := ports.AddPort(plain); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(true); err == nil {
		t.Fatal("reload unexpectedly accepted missing key")
	}
	for _, p := range []*config.ProxyPortConfig{cfg, plain} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var out testProxyPortResult
		runProxyPortConnectivityTest(ctx, p, httpOrigin.URL, &out)
		cancel()
		if !out.Success {
			t.Fatalf("%s unavailable after bad replacement: %+v", p.ID, out)
		}
	}
}
