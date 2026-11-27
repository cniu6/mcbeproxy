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

// 普通端口与批量导出的接口测试。覆盖：单个/批量、三种格式、多用户账号、socks4 跳过、
// 安全入口 HY2 的 "用户名:密码" 认证串与 pinSHA256、Mieru 的 TCP 传输与必填账号。

func newShareTestRouter(t *testing.T) (*gin.Engine, *config.ProxyPortConfigManager) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cm := config.NewProxyPortConfigManager(filepath.Join(t.TempDir(), "ports.json"))
	a := &APIServer{proxyPortConfigMgr: cm}
	router := gin.New()
	router.POST("/ports", a.createProxyPort)
	router.POST("/ports/:id/share", a.shareProxyPort)
	router.POST("/ports/bulk-share", a.shareProxyPortsBulk)
	return router, cm
}

func postJSON(router *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", path, bytes.NewReader(raw)))
	return w
}

type shareResp struct {
	Data struct {
		Format  string   `json:"format"`
		Content string   `json:"content"`
		Links   []string `json:"links"`
		Count   int      `json:"count"`
		Skipped []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	} `json:"data"`
}

func decodeShare(t *testing.T, w *httptest.ResponseRecorder) shareResp {
	t.Helper()
	var resp shareResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v body=%s", err, w.Body.String())
	}
	return resp
}

func TestSharePlainSocks5SingleAndBulkFormats(t *testing.T) {
	router, cm := newShareTestRouter(t)
	p := config.ProxyPortConfig{
		ID: "s5", Name: "家用SOCKS", ListenAddr: "0.0.0.0:1080", Type: "socks5", Enabled: true,
		Username: "alice", Password: "alicepass123",
	}
	if w := postJSON(router, "/ports", p); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	_ = cm

	// 单个 links：socks5 明文链接，userinfo 含冒号
	w := postJSON(router, "/ports/s5/share", map[string]string{"address": "203.0.113.9", "format": "links"})
	resp := decodeShare(t, w)
	if w.Code != 200 || len(resp.Data.Links) != 1 {
		t.Fatalf("single links failed: %d %s", w.Code, w.Body.String())
	}
	link := resp.Data.Links[0]
	if !strings.HasPrefix(link, "socks5://alice:alicepass123@203.0.113.9:1080") {
		t.Fatalf("bad socks5 link: %s", link)
	}

	// 单个 share：base64 订阅，解码后就是那一条链接
	w = postJSON(router, "/ports/s5/share", map[string]string{"address": "203.0.113.9", "format": "share"})
	resp = decodeShare(t, w)
	raw, err := base64.StdEncoding.DecodeString(resp.Data.Content)
	if err != nil || strings.TrimSpace(string(raw)) != link {
		t.Fatalf("share subscription mismatch: err=%v got=%q", err, raw)
	}

	// 单个 clash
	w = postJSON(router, "/ports/s5/share", map[string]string{"address": "203.0.113.9", "format": "clash"})
	resp = decodeShare(t, w)
	for _, want := range []string{"proxies:", "type: socks5", "username: alice", "password: alicepass123", "udp: true"} {
		if !strings.Contains(resp.Data.Content, want) {
			t.Fatalf("clash missing %q:\n%s", want, resp.Data.Content)
		}
	}

	// 批量：只填 host，端口取监听端口
	w = postJSON(router, "/ports/bulk-share", map[string]any{"ids": []string{"s5"}, "format": "links", "host": "203.0.113.9"})
	resp = decodeShare(t, w)
	if w.Code != 200 || resp.Data.Count != 1 || resp.Data.Links[0] != link {
		t.Fatalf("bulk links mismatch: %d %s", w.Code, w.Body.String())
	}
}

func TestShareBulkRejectsHostWithPort(t *testing.T) {
	router, _ := newShareTestRouter(t)
	_ = postJSON(router, "/ports", config.ProxyPortConfig{ID: "h", Name: "h", ListenAddr: "0.0.0.0:1081", Type: "http", Enabled: true})
	w := postJSON(router, "/ports/bulk-share", map[string]any{"ids": []string{"h"}, "format": "links", "host": "203.0.113.9:9999"})
	if w.Code != 400 {
		t.Fatalf("host with port must be rejected in bulk, got %d", w.Code)
	}
}

func TestShareSocks4SkippedInBulkButErrorsSingle(t *testing.T) {
	router, _ := newShareTestRouter(t)
	_ = postJSON(router, "/ports", config.ProxyPortConfig{ID: "old", Name: "旧SOCKS4", ListenAddr: "0.0.0.0:1082", Type: "socks4", Enabled: true})
	_ = postJSON(router, "/ports", config.ProxyPortConfig{ID: "ok", Name: "正常", ListenAddr: "0.0.0.0:1083", Type: "socks5", Enabled: true})

	// 批量：socks4 进 skipped，socks5 正常导出
	w := postJSON(router, "/ports/bulk-share", map[string]any{"ids": []string{"old", "ok"}, "format": "links", "host": "203.0.113.9"})
	resp := decodeShare(t, w)
	if w.Code != 200 || resp.Data.Count != 1 || len(resp.Data.Skipped) != 1 || resp.Data.Skipped[0].Name != "旧SOCKS4" {
		t.Fatalf("bulk should skip socks4 only: %d %s", w.Code, w.Body.String())
	}

	// 单个 socks4 links：没有可导出内容，返回 400
	if w := postJSON(router, "/ports/old/share", map[string]string{"address": "203.0.113.9", "format": "links"}); w.Code != 400 {
		t.Fatalf("single socks4 links must 400, got %d", w.Code)
	}
}

func TestShareMultiUserAccountSelection(t *testing.T) {
	router, _ := newShareTestRouter(t)
	p := config.ProxyPortConfig{
		ID: "mu", Name: "多用户", ListenAddr: "0.0.0.0:1084", Type: "socks5", Enabled: true,
		Username: "owner", Password: "ownerpass1234",
		Users: []config.ProxyPortUser{
			{Username: "guest", Password: "guestpass1234"},
			{Username: "banned", Password: "bannedpass1234", Disabled: true},
		},
	}
	if w := postJSON(router, "/ports", p); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := postJSON(router, "/ports/mu/share", map[string]string{"address": "203.0.113.9", "format": "links", "username": "guest"})
	resp := decodeShare(t, w)
	if w.Code != 200 || !strings.Contains(resp.Data.Links[0], "guest:guestpass1234@") {
		t.Fatalf("guest account not used: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(router, "/ports/mu/share", map[string]string{"address": "203.0.113.9", "format": "links", "username": "banned"}); w.Code != 400 {
		t.Fatalf("disabled user must be refused, got %d", w.Code)
	}
}

func TestShareHy2EntryUsesUserPassAuthAndPin(t *testing.T) {
	router, cm := newShareTestRouter(t)
	p := config.ProxyPortConfig{ID: "hy", Name: "HY2入口", ListenAddr: "0.0.0.0:18443", Type: "hysteria2", Enabled: false}
	if w := postJSON(router, "/ports", p); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved, _ := cm.GetPort("hy")

	w := postJSON(router, "/ports/hy/share", map[string]string{"address": "hk.example.com:18443", "format": "links"})
	resp := decodeShare(t, w)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	link := resp.Data.Links[0]
	// 认证串必须是 "用户名:密码"，与服务端认证表键 credentials() 一致。
	wantAuth := saved.Username + ":" + saved.Password
	if !strings.Contains(link, "hysteria2://"+wantAuth+"@hk.example.com:18443") {
		t.Fatalf("hy2 auth must be user:pass, got %s", link)
	}
	if !strings.Contains(link, "pinSHA256=") || strings.Contains(link, "insecure=1") {
		t.Fatalf("hy2 link must pin cert and not skip verification: %s", link)
	}

	// Clash 项：password 为 用户名:密码，fingerprint 钉扎
	w = postJSON(router, "/ports/hy/share", map[string]string{"address": "hk.example.com:18443", "format": "clash"})
	resp = decodeShare(t, w)
	if !strings.Contains(resp.Data.Content, "type: hysteria2") || !strings.Contains(resp.Data.Content, "fingerprint:") {
		t.Fatalf("bad hy2 clash: %s", resp.Data.Content)
	}
}

func TestShareMieruClashTCPWithAccount(t *testing.T) {
	router, cm := newShareTestRouter(t)
	p := config.ProxyPortConfig{ID: "mi", Name: "Mieru入口", ListenAddr: "0.0.0.0:19443", Type: "mieru", Enabled: false}
	if w := postJSON(router, "/ports", p); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	saved, _ := cm.GetPort("mi")

	// 没有公开链接标准：links 应 400 并说明原因
	if w := postJSON(router, "/ports/mi/share", map[string]string{"address": "203.0.113.9", "format": "links"}); w.Code != 400 {
		t.Fatalf("mieru links must 400, got %d", w.Code)
	}
	w := postJSON(router, "/ports/mi/share", map[string]string{"address": "203.0.113.9", "format": "clash"})
	resp := decodeShare(t, w)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, want := range []string{"type: mieru", "transport: TCP", "udp: true", "username: " + saved.Username, "password:"} {
		if !strings.Contains(resp.Data.Content, want) {
			t.Fatalf("mieru yaml missing %q:\n%s", want, resp.Data.Content)
		}
	}
}
