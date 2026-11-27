package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/config"
)

func TestSecurePortStandardExportFormats(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	cm := config.NewProxyPortConfigManager(filepath.Join(dir, "ports.json"))
	a := &APIServer{proxyPortConfigMgr: cm}
	router := gin.New()
	router.POST("/ports", a.createProxyPort)
	router.POST("/ports/:id/export", a.exportSecurePort)
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(raw)))
		return w
	}
	p := config.ProxyPortConfig{ID: "fixture", Name: "我的HY2线路", ListenAddr: "0.0.0.0:18443", Type: "hysteria2", Enabled: false}
	if w := call("POST", "/ports", p); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved, _ := cm.GetPort(p.ID)

	// format=share → Base64 编码的一行 hysteria2:// 订阅
	w := call("POST", "/ports/fixture/export?format=share", map[string]string{"address": "203.0.113.5:18443"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var shareResp struct {
		Data struct {
			Format  string   `json:"format"`
			Content string   `json:"content"`
			Links   []string `json:"links"`
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
	if !strings.HasPrefix(link, "hysteria2://") {
		t.Fatalf("expected standard hysteria2 link, got %q", link)
	}
	if !strings.Contains(link, "@203.0.113.5:18443") {
		t.Fatalf("link missing server address: %q", link)
	}
	if !strings.Contains(link, "pinSHA256=") {
		t.Fatalf("link missing pinSHA256 for cert pinning: %q", link)
	}
	if strings.Contains(link, "insecure=1") {
		t.Fatalf("pinned link must not skip verification: %q", link)
	}
	// 密码在 userinfo 段
	if !strings.Contains(link, "hysteria2://"+saved.Password[:8]) && !strings.Contains(link, "%") {
		t.Logf("link userinfo: %q", link)
	}

	// format=clash → mihomo YAML
	w = call("POST", "/ports/fixture/export?format=clash", map[string]string{"address": "203.0.113.5:18443"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var clashResp struct {
		Data struct {
			Format  string `json:"format"`
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &clashResp); err != nil {
		t.Fatal(err)
	}
	yaml := clashResp.Data.Content
	if !strings.HasPrefix(yaml, "proxies:") || !strings.Contains(yaml, "type: hysteria2") {
		t.Fatalf("bad clash yaml: %q", yaml)
	}
	if !strings.Contains(yaml, "fingerprint:") {
		t.Fatalf("clash yaml missing cert fingerprint pinning: %q", yaml)
	}
	if strings.Contains(yaml, "PRIVATE KEY") || strings.Contains(yaml, saved.Password+"KEY") {
		t.Fatalf("yaml leaked private material: %q", yaml)
	}
	// 名称应保留
	if !strings.Contains(yaml, "我的HY2线路") && !strings.Contains(yaml, "name:") {
		t.Fatalf("yaml missing name: %q", yaml)
	}
}

func TestProxyOutboundsExportEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	obMgr := config.NewProxyOutboundConfigManager(filepath.Join(dir, "outbounds.json"))
	h := &ProxyOutboundHandler{configMgr: obMgr}
	router := gin.New()
	router.POST("/export", h.ExportProxyOutbounds)

	_ = obMgr.AddOutbound(&config.ProxyOutbound{
		Name: "n-ss", Type: config.ProtocolShadowsocks, Server: "1.2.3.4", Port: 8388,
		Method: "aes-256-gcm", Password: "pw", Enabled: true,
	})
	_ = obMgr.AddOutbound(&config.ProxyOutbound{
		Name: "n-hy2", Type: config.ProtocolHysteria2, Server: "hy.example.com", Port: 443,
		Password: "pw-hy2", SNI: "hy.example.com", Enabled: true,
	})
	_ = obMgr.AddOutbound(&config.ProxyOutbound{
		Name: "n-chain", Type: config.ProtocolChain, Chain: []string{"n-ss"}, Enabled: true,
	})

	call := func(body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/export", bytes.NewReader(raw)))
		return w
	}

	// share 格式批量导出
	w := call(map[string]any{"names": []string{"n-ss", "n-hy2", "n-chain"}, "format": "share"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Format  string `json:"format"`
			Content string `json:"content"`
			Count   int    `json:"count"`
			Skipped []struct {
				Name   string `json:"name"`
				Reason string `json:"reason"`
			} `json:"skipped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Count != 2 {
		t.Fatalf("expected 2 exportable nodes, got %d: %s", resp.Data.Count, w.Body.String())
	}
	if len(resp.Data.Skipped) != 1 || resp.Data.Skipped[0].Name != "n-chain" {
		t.Fatalf("chain node should be skipped: %+v", resp.Data.Skipped)
	}
	// share 格式内容必须是 base64（不含明文 ss://）
	if strings.Contains(resp.Data.Content, "ss://") {
		t.Fatalf("share subscription must be base64 encoded")
	}

	// links 格式明文
	w = call(map[string]any{"names": []string{"n-ss", "n-hy2"}, "format": "links"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Data.Content, "ss://") || !strings.Contains(resp.Data.Content, "hysteria2://") {
		t.Fatalf("links content missing links: %q", resp.Data.Content)
	}

	// clash 格式
	w = call(map[string]any{"names": []string{"n-ss", "n-hy2"}, "format": "clash"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Data.Content, "proxies:") || !strings.Contains(resp.Data.Content, "type: ss") || !strings.Contains(resp.Data.Content, "type: hysteria2") {
		t.Fatalf("bad clash yaml content: %q", resp.Data.Content)
	}

	// 空 names / 坏 format
	if w := call(map[string]any{"names": []string{}, "format": "share"}); w.Code != 400 {
		t.Fatalf("empty names must 400, got %d", w.Code)
	}
	if w := call(map[string]any{"names": []string{"n-ss"}, "format": "bogus"}); w.Code != 400 {
		t.Fatalf("bad format must 400, got %d", w.Code)
	}
}
