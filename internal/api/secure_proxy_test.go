package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/config"
)

func TestSecureProxyAPICredentialsAndProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	cm := config.NewProxyPortConfigManager(filepath.Join(dir, "ports.json"))
	a := &APIServer{proxyPortConfigMgr: cm}
	router := gin.New()
	router.POST("/ports", a.createProxyPort)
	router.GET("/ports", a.getProxyPorts)
	router.PUT("/ports/:id", a.updateProxyPort)
	router.POST("/ports/:id/export", a.exportSecurePort)
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(raw)))
		return w
	}
	p := config.ProxyPortConfig{ID: "fixture", Name: "fixture", ListenAddr: "127.0.0.1:18443", Type: "hysteria2", Enabled: false, Users: []config.ProxyPortUser{{Username: "guest"}}}
	w := call("POST", "/ports", p)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved, ok := cm.GetPort(p.ID)
	if !ok || len(saved.Password) < 16 || saved.Secure == nil || saved.Secure.IdentityID == "" || len(saved.Users[0].Password) < 16 {
		t.Fatal("automatic identity or credentials not saved")
	}
	if saved.Secure.Limits.MaxConnections != 4096 || saved.Secure.Limits.MaxUDPAssociations != 4096 || saved.Secure.Limits.IdleSeconds != 300 {
		t.Fatal("new entry did not use recommended defaults")
	}
	if strings.Contains(w.Body.String(), saved.Password) {
		t.Fatal("create leaked password")
	}
	w = call("GET", "/ports", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), saved.Password) {
		t.Fatal("list leaked password")
	}
	var listed struct {
		Data []struct {
			Running bool                     `json:"running"`
			Secure  *config.SecurePortConfig `json:"secure"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Data) != 1 || listed.Data[0].Running || listed.Data[0].Secure == nil || listed.Data[0].Secure.IdentityID != saved.Secure.IdentityID {
		t.Fatal("disabled entry lost identity or reported running")
	}
	w = call("POST", "/ports/fixture/export", map[string]string{"address": "127.0.0.1:18443"})
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
	var env struct {
		Data config.SecureProfile `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env.Data)
	parsed, err := config.ParseSecureProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Upstream.Password != saved.Password || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("bad export")
	}
	w = call("POST", "/ports/fixture/export?format=link", map[string]string{"username": "guest", "name": "香港游戏线路"})
	var shared struct {
		Data struct {
			Link string `json:"link"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &shared); err != nil {
		t.Fatal(err)
	}
	guest, err := config.ParseSecureProfile([]byte(shared.Data.Link))
	if err != nil || w.Code != 200 || guest.Name != "香港游戏线路" || guest.Upstream.Username != "guest" || guest.Upstream.Password != saved.Users[0].Password || guest.Upstream.Server != "example.com" || guest.Upstream.Port != 18443 {
		t.Fatalf("default-address guest link failed: code=%d err=%v", w.Code, err)
	}
	importer := &ProxyOutboundHandler{}
	router.POST("/parse-share", importer.ParseImportContent)
	preview := call("POST", "/parse-share", map[string]string{"content": shared.Data.Link})
	var imported struct {
		Data struct {
			Items []*config.ProxyOutbound `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	if preview.Code != 200 || (len(imported.Data.Items) == 1 && imported.Data.Items[0].Name != "香港游戏线路") || preview.Header().Get("Cache-Control") != "no-store" || len(imported.Data.Items) != 1 || imported.Data.Items[0].SecureUpstream == nil || imported.Data.Items[0].SecureUpstream.CertSHA256 != guest.Upstream.CertSHA256 {
		t.Fatal("quick import lost HY2 trust")
	}
	if guest.Upstream.TrustedCertPEM != parsed.Upstream.TrustedCertPEM {
		t.Fatal("link lost certificate trust")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("share link cacheable")
	}
	edited := redactSecurePort(saved)
	edited.Name = "renamed"
	w = call("PUT", "/ports/fixture", edited)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := cm.GetPort(p.ID)
	if after.Secure == nil || after.Secure.IdentityID != saved.Secure.IdentityID || after.Secure.Limits != saved.Secure.Limits {
		t.Fatal("edit roundtrip lost secure identity or limits")
	}
	if after.Users[0].Password != saved.Users[0].Password {
		t.Fatal("user edit lost saved password")
	}
	if after.Password != saved.Password {
		t.Fatal("empty update erased secret")
	}
	req := CreateProxyOutboundRequest{SecureUpstream: &parsed.Upstream, Name: "trusted", Type: parsed.Upstream.Type, Server: parsed.Upstream.Server, Port: parsed.Upstream.Port, Username: parsed.Upstream.Username, Password: parsed.Upstream.Password}
	node := req.toProxyOutbound()
	if err := node.Validate(); err != nil {
		t.Fatal("import lost trust", err)
	}
	clone := node.Clone()
	clone.SecureUpstream.Password = "changed"
	if node.SecureUpstream.Password == "changed" {
		t.Fatal("trusted config aliases clone")
	}
}
