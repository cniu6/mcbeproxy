package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

func TestProxyPortDetailConvertsPlainToSecure(t *testing.T) {
	for _, kind := range []string{config.ProxyPortTypeHysteria2, config.ProxyPortTypeMieru} {
		t.Run(kind, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			cm := config.NewProxyPortConfigManager(filepath.Join(t.TempDir(), "ports.json"))
			a := &APIServer{proxyPortConfigMgr: cm}
			router := gin.New()
			router.POST("/ports", a.createProxyPort)
			router.PUT("/ports/:id", a.updateProxyPort)
			router.POST("/ports/:id/export", a.exportSecurePort)
			call := func(method, path string, value any) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(value)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(raw)))
				return w
			}
			p := config.ProxyPortConfig{ID: "type-change", Name: "fixture", Type: "http", ListenAddr: "127.0.0.1:18443", Enabled: false}
			if w := call("POST", "/ports", p); w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			p.Type = kind
			if w := call("PUT", "/ports/type-change", p); w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			saved, _ := cm.GetPort(p.ID)
			if saved.Type != kind || saved.Secure == nil || len(saved.Password) < 16 {
				t.Fatal("conversion did not create secure settings")
			}
			if kind == config.ProxyPortTypeHysteria2 {
				ids := proxy.NewSecureIdentityStore(cm.IdentityDataDir())
				_, before, err := ids.Load(saved.Secure.IdentityID)
				if err != nil {
					t.Fatal(err)
				}
				p = *redactSecurePort(saved)
				p.Name = "renamed"
				if w := call("PUT", "/ports/type-change", p); w.Code != http.StatusOK {
					t.Fatal(w.Code, w.Body.String())
				}
				_, after, _ := ids.Load(saved.Secure.IdentityID)
				if before.SHA256 != after.SHA256 {
					t.Fatal("editing replaced the certificate identity")
				}
				w := call("POST", "/ports/type-change/export?format=link", map[string]string{"address": "127.0.0.1:18443"})
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "mcproxy://") {
					t.Fatal("converted saved entry could not be exported")
				}
				// An existing HY2 identity disappearing must not silently rotate trust.
				path := filepath.Join(cm.IdentityDataDir(), "secure-identities", saved.Secure.IdentityID+".json")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				w = call("PUT", "/ports/type-change", p)
				if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "HY2证书无法读取") {
					t.Fatal("missing identity should be rejected, not regenerated")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("missing identity was recreated")
				}
			}
			// Preserve the original restriction even when the entry is disabled.
			p.Type = config.ProxyPortTypeSocks5
			w := call("PUT", "/ports/type-change", p)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "不可原位更换") {
				t.Fatal("saved secure protocol change was accepted")
			}
		})
	}
}

func TestProxyPortConversionDoesNotReplaceCorruptIdentity(t *testing.T) {
	cm := config.NewProxyPortConfigManager(filepath.Join(t.TempDir(), "ports.json"))
	p := &config.ProxyPortConfig{ID: "existing", Name: "fixture", Type: "http", ListenAddr: "127.0.0.1:18443"}
	if err := cm.AddPort(p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cm.IdentityDataDir(), "secure-identities", p.ID+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	p = p.Clone()
	p.Type = config.ProxyPortTypeHysteria2
	a := &APIServer{proxyPortConfigMgr: cm}
	if err := a.prepareSecurePort(p); err == nil {
		t.Fatal("corrupt identity was accepted")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "corrupt-fixture" {
		t.Fatal("corrupt identity was overwritten")
	}
}
