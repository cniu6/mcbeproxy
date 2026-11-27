package api

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestV2rayNPortSubscriptionExcludesHTTPWithoutBreakingLinks(t *testing.T) {
	router, _ := newShareTestRouter(t)
	for _, port := range []config.ProxyPortConfig{
		{ID: "socks", Name: "SOCKS", ListenAddr: "127.0.0.1:1080", Type: "socks5", Username: "test", Password: "p:a%2F +中文"},
		{ID: "http", Name: "HTTP", ListenAddr: "127.0.0.1:8081", Type: "http", Username: "test", Password: "http-pass"},
	} {
		if w := postJSON(router, "/ports", port); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := postJSON(router, "/ports/bulk-share", map[string]interface{}{"ids": []string{"socks", "http"}, "format": "share", "host": "203.0.113.9"})
	resp := decodeShare(t, w)
	if w.Code != 200 || resp.Data.Count != 1 || len(resp.Data.Skipped) != 1 || !strings.Contains(resp.Data.Skipped[0].Reason, "v2rayN") {
		t.Fatalf("wrong subscription boundary: %d %s", w.Code, w.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.Data.Content)
	if err != nil || strings.TrimSpace(string(decoded)) != resp.Data.Links[0] {
		t.Fatal("API content does not match its links")
	}
	u, err := url.Parse(resp.Data.Links[0])
	if err != nil {
		t.Fatal(err)
	}
	auth, err := base64.RawStdEncoding.DecodeString(u.User.Username())
	if err != nil || string(auth) != "test:p:a%2F +中文" {
		t.Fatal("API subscription credentials changed")
	}
	w = postJSON(router, "/ports/http/share", map[string]string{"address": "203.0.113.9", "format": "links"})
	if w.Code != 200 || !strings.Contains(decodeShare(t, w).Data.Content, "http://") {
		t.Fatal("generic HTTP links must stay available")
	}
	w = postJSON(router, "/ports/http/share", map[string]string{"address": "203.0.113.9", "format": "share"})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "v2rayN") {
		t.Fatal("all-unsupported response must explain the client limitation")
	}
}

func TestV2rayNNodeExportUsesProductionLegacyFields(t *testing.T) {
	p := &config.ProxyOutbound{Name: "vmess-grpc", Type: config.ProtocolVMess, Server: "example.com", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", TLS: true, Insecure: true,
		Network: "grpc", GRPCServiceName: "svc + %2F", GRPCAuthority: "edge.example.com", ALPN: "h2"}
	// Use the same renderer as the authenticated export route, without a listener.
	link, err := config.ExportShareLink(p)
	if err != nil {
		t.Fatal(err)
	}
	out := renderPortShares("share", []portShareItem{{Name: p.Name, Link: link}}, nil)
	if out.Count != 1 {
		t.Fatalf("render failed: %+v", out.Skipped)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Content)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["host"] != p.GRPCAuthority || fields["path"] != p.GRPCServiceName || fields["insecure"] != "1" || fields["alpn"] != "h2" {
		t.Fatalf("legacy JSON fields lost through API packaging: %v", fields)
	}
}
