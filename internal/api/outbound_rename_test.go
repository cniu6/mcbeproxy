package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/netroute"
	"mcpeserverproxy/internal/proxy"
)

func TestOutboundRenameUpdatesReferencesAndKeepsSecrets(t *testing.T) {
	dir := t.TempDir()
	cm := config.NewProxyOutboundConfigManager(filepath.Join(dir, "nodes.json"))
	ports := config.NewProxyPortConfigManager(filepath.Join(dir, "ports.json"))
	subs := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "subs.json"))
	servers, err := config.NewConfigManager(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := proxy.NewOutboundManager(nil)
	old := &config.ProxyOutbound{Name: "old", Type: "socks5", Server: "127.0.0.1", Port: 1080, Enabled: true, Username: "u", Password: "saved-secret", SubscriptionID: "source", SubscriptionName: "fixture", SubscriptionNodeID: "stable"}
	chain := &config.ProxyOutbound{Name: "chain", Type: "chain", Enabled: true, Chain: []string{"old"}}
	other := &config.ProxyOutbound{Name: "other", Type: "socks5", Server: "127.0.0.1", Port: 1081, Enabled: true}
	for _, node := range []*config.ProxyOutbound{old, chain, other} {
		if err := cm.AddOutbound(node); err != nil {
			t.Fatal(err)
		}
		if err := runtime.AddOutbound(node); err != nil {
			t.Fatal(err)
		}
	}
	server := &config.ServerConfig{ID: "server-id", Name: "自定义服务器", Target: "127.0.0.1", Port: 19132, ListenAddr: "127.0.0.1:19133", Protocol: "raknet", ProxyOutbound: "old,other", AutoSelectBlockedNodes: map[string]*config.NodeAutoSelectBlock{"old": {Reason: "fixture"}}}
	if err := servers.AddServer(server); err != nil {
		t.Fatal(err)
	}
	port := &config.ProxyPortConfig{ID: "port", Name: "port", ListenAddr: "127.0.0.1:11080", Type: "socks5", ProxyOutbound: "old", Users: []config.ProxyPortUser{{Username: "guest", Password: "pass", ProxyOutbound: "other,old"}}}
	if err := ports.AddPort(port); err != nil {
		t.Fatal(err)
	}
	sub := &config.ProxySubscription{ID: "source", Name: "fixture", URL: "https://example.com/nodes", ProxyName: "old"}
	if err := subs.AddSubscription(sub); err != nil {
		t.Fatal(err)
	}
	originalNetwork := netroute.Current()
	defer netroute.Apply(originalNetwork)
	store := netroute.NewStore(filepath.Join(dir, "network.json"))
	if _, err := store.Save(netroute.Config{Rules: []netroute.Rule{{ID: "rule", Name: "fixture", Enabled: true, Targets: "*", Action: netroute.ActionProxy, Outbound: "old,other"}}}); err != nil {
		t.Fatal(err)
	}
	h := NewProxyOutboundHandler(cm, subs, servers, runtime)
	h.portConfigMgr = ports
	a := &APIServer{networkStore: store}
	h.prepareRename = a.prepareOutboundRename
	var reloaded string
	h.SetOutboundReloadHook(func(name string) { reloaded = name })
	router := gin.New()
	router.POST("/update", h.UpdateProxyOutboundByBody)
	body, _ := json.Marshal(map[string]any{"original_name": "old", "name": "香港主力", "type": "socks5", "server": "127.0.0.1", "port": 1080, "enabled": true, "username": "u"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("rename status=%d body=%s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte(old.Password)) {
		t.Fatal("rename leaked saved password")
	}
	if _, exists := cm.GetOutbound("old"); exists {
		t.Fatal("old config key remains")
	}
	if _, exists := runtime.GetOutbound("old"); exists {
		t.Fatal("old runtime key remains")
	}
	renamed, ok := cm.GetOutbound("香港主力")
	if !ok || renamed.Password != old.Password || renamed.SubscriptionNodeID != "stable" || renamed.SubscriptionID != "source" {
		t.Fatal("renaming lost credentials or subscription identity")
	}
	c, _ := cm.GetOutbound("chain")
	if c.Chain[0] != "香港主力" {
		t.Fatal("chain reference not renamed")
	}
	rc, _ := runtime.GetOutbound("chain")
	if rc.Chain[0] != "香港主力" {
		t.Fatal("runtime chain reference not renamed")
	}
	s, _ := servers.GetServer("server-id")
	if s.ProxyOutbound != "香港主力,other" || s.AutoSelectBlockedNodes["香港主力"] == nil || s.Name != "自定义服务器" || s.ID != "server-id" {
		t.Fatal("server references or display identity changed incorrectly")
	}
	p, _ := ports.GetPort("port")
	if p.ProxyOutbound != "香港主力" || p.Users[0].ProxyOutbound != "other,香港主力" {
		t.Fatal("port/user reference not renamed")
	}
	savedSub, _ := subs.GetSubscription("source")
	if savedSub.ProxyName != "香港主力" || netroute.Current().Rules[0].Outbound != "香港主力,other" {
		t.Fatal("subscription or route reference not renamed")
	}
	if reloaded != "香港主力" {
		t.Fatal("reload did not target new name")
	}
	if err := cm.Load(); err != nil {
		t.Fatal(err)
	}
	if _, exists := cm.GetOutbound("香港主力"); !exists {
		t.Fatal("rename not persisted")
	}
	collision := renamed.Clone()
	collision.Name = "other"
	if err := h.updateProxyOutboundConfig("香港主力", collision); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, exists := cm.GetOutbound("香港主力"); !exists {
		t.Fatal("collision removed source")
	}
}

func TestOutboundRenameRollback(t *testing.T) {
	dir := t.TempDir()
	cm := config.NewProxyOutboundConfigManager(filepath.Join(dir, "nodes.json"))
	old := &config.ProxyOutbound{Name: "old", Type: "socks5", Server: "127.0.0.1", Port: 1080}
	if err := cm.AddOutbound(old); err != nil {
		t.Fatal(err)
	}
	h := NewProxyOutboundHandler(cm, nil, nil, nil)
	h.prepareRename = func(string, string) ([]outboundRenameChange, error) {
		return []outboundRenameChange{{apply: func() error { return errors.New("fixture write failed") }, undo: func() error { return nil }}}, nil
	}
	next := old.Clone()
	next.Name = "new"
	if err := h.updateProxyOutboundConfig("old", next); err == nil {
		t.Fatal("write failure ignored")
	}
	if _, ok := cm.GetOutbound("old"); !ok {
		t.Fatal("source not restored")
	}
	if _, ok := cm.GetOutbound("new"); ok {
		t.Fatal("partial rename left new key")
	}
	if err := cm.Load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := cm.GetOutbound("old"); !ok {
		t.Fatal("rollback not persisted")
	}
}

func TestRenameOutboundSelectionExactTokens(t *testing.T) {
	for _, c := range []struct{ in, want string }{{"old,old-extra,other", "new,old-extra,other"}, {"@old", "@old"}, {"old", "new"}, {"other", "other"}} {
		if got := renameOutboundSelection(c.in, "old", "new"); got != c.want {
			t.Fatalf("got %q want %q", got, c.want)
		}
	}
}
