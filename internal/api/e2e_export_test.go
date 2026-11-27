package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/config"
)

// 端到端：从创建 HY2 入口到导出标准链接，再用 mihomo 的参数约定验证每个字段。
func TestEndToEndSecurePortExportLinkParams(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	cm := config.NewProxyPortConfigManager(filepath.Join(dir, "ports.json"))
	a := &APIServer{proxyPortConfigMgr: cm}
	router := gin.New()
	router.POST("/ports", a.createProxyPort)
	router.POST("/ports/:id/export", a.exportSecurePort)

	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(raw)))
		return w
	}

	p := config.ProxyPortConfig{
		ID: "game-hk", Name: "香港游戏专线", ListenAddr: "0.0.0.0:28443",
		Type: "hysteria2", Enabled: false,
		Users: []config.ProxyPortUser{{Username: "vip-user"}},
	}
	if w := call("POST", "/ports", p); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved, _ := cm.GetPort("game-hk")

	// 1. Base64 标准订阅导出（用 vip-user 账号）
	w := call("POST", "/ports/game-hk/export?format=share", map[string]string{
		"address":  "hk.example.com:28443",
		"username": "vip-user",
	})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var shareResp struct {
		Data struct {
			Format  string `json:"format"`
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &shareResp); err != nil {
		t.Fatal(err)
	}
	if shareResp.Data.Format != "share" {
		t.Fatalf("expected base64 subscription format, got %q", shareResp.Data.Format)
	}
	subscription, err := base64.StdEncoding.DecodeString(shareResp.Data.Content)
	if err != nil {
		t.Fatalf("decode base64 subscription: %v", err)
	}
	links := strings.Fields(string(subscription))
	if len(links) != 1 {
		t.Fatalf("expected one link in subscription, got %d", len(links))
	}
	link := links[0]

	// 2. 严格校验链接结构（apernet 规范 + mihomo convert 约定）
	if !strings.HasPrefix(link, "hysteria2://") {
		t.Fatalf("not a hysteria2 link: %q", link)
	}
	rest := strings.TrimPrefix(link, "hysteria2://")
	// fragment 名称
	hashIdx := strings.Index(rest, "#")
	if hashIdx < 0 {
		t.Fatalf("missing #name fragment: %q", link)
	}
	name, _ := url.QueryUnescape(rest[hashIdx+1:])
	if name != "香港游戏专线" {
		t.Fatalf("wrong node name: %q", name)
	}
	rest = rest[:hashIdx]
	// query
	qIdx := strings.Index(rest, "?")
	if qIdx < 0 {
		t.Fatalf("missing query: %q", link)
	}
	query, _ := url.ParseQuery(rest[qIdx+1:])
	rest = rest[:qIdx]
	rest = strings.TrimSuffix(rest, "/")
	// userinfo@host:port
	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		t.Fatalf("missing @ in authority: %q", link)
	}
	auth, _ := url.QueryUnescape(rest[:atIdx])
	// 认证串必须是 "用户名:密码"，与服务端认证表键一致。
	if auth != "vip-user:"+saved.Users[0].Password {
		t.Fatalf("auth mismatch: got %q", auth)
	}
	if rest[atIdx+1:] != "hk.example.com:28443" {
		t.Fatalf("wrong authority: %q", rest[atIdx+1:])
	}
	// 关键参数：pinSHA256 + sni，且没有 insecure=1
	if query.Get("pinSHA256") == "" {
		t.Fatalf("missing pinSHA256: %q", link)
	}
	if query.Get("sni") == "" {
		t.Fatalf("missing sni: %q", link)
	}
	if query.Get("insecure") == "1" {
		t.Fatalf("must not skip verification: %q", link)
	}

	// 3. Clash YAML 导出并校验安全认证字段。
	w = call("POST", "/ports/game-hk/export?format=clash", map[string]string{"address": "hk.example.com:28443"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var clashResp struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &clashResp)
	yamlText := clashResp.Data.Content

	// 关键字段：type/password/server/port/fingerprint/sni
	for _, want := range []string{"type: hysteria2", "server: hk.example.com", "port: 28443", "fingerprint:", "sni:", "password:"} {
		if !strings.Contains(yamlText, want) {
			t.Fatalf("clash yaml missing %q:\n%s", want, yamlText)
		}
	}
	// 不含私钥
	if strings.Contains(yamlText, "PRIVATE KEY") {
		t.Fatalf("yaml leaked private key")
	}

}
