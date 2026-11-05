package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
)

type autoModeController struct {
	mockProxyController
	busy   bool
	closed bool
}

func (p *autoModeController) ValidateServerTransportChange(*config.ServerConfig) error {
	if p.busy {
		return errors.New("busy")
	}
	return nil
}
func (p *autoModeController) CloseSession(server, id, reason string) bool {
	if server != "s" || id != "relay-id" {
		return false
	}
	p.closed = true
	return true
}

func TestAutoModeAPIPreflightAndCloseAuthorization(t *testing.T) {
	a, database, cleanup := setupTestAPI(t)
	defer cleanup()
	controller := &autoModeController{busy: true}
	a.proxyController = controller
	cfg := &config.ServerConfig{ID: "s", Name: "s", Protocol: "raknet", ProxyMode: "raw_udp", Target: "127.0.0.1", Port: 19132, ListenAddr: "127.0.0.1:19133"}
	if err := a.configMgr.AddServer(cfg); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"s","protocol":"raknet","proxy_mode":"auto","target":"127.0.0.1","port":19132,"listen_addr":"127.0.0.1:19133"}`
	request := httptest.NewRequest(http.MethodPut, "/api/servers/s", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	a.GetRouter().ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("busy status=%d body=%s", response.Code, response.Body.String())
	}
	persisted, _ := a.configMgr.GetServer("s")
	if persisted.GetProxyMode() != "raw_udp" {
		t.Fatal("saved rejected transport")
	}
	controller.busy = false
	request = httptest.NewRequest(http.MethodPut, "/api/servers/s", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	a.GetRouter().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", response.Code, response.Body.String())
	}
	persisted, _ = a.configMgr.GetServer("s")
	if persisted.GetProxyMode() != "auto" {
		t.Fatal("auto lost")
	}
	keys := db.NewAPIKeyRepository(database, 100)
	for _, key := range []*db.APIKey{{Key: "viewer-test", Name: "viewer", CreatedAt: time.Now(), IsAdmin: false}, {Key: "admin-test", Name: "admin", CreatedAt: time.Now(), IsAdmin: true}} {
		if err := keys.Create(key); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		key, path string
		status    int
	}{{"", "/api/servers/s/sessions/relay-id/close", 401}, {"viewer-test", "/api/servers/s/sessions/relay-id/close", 403}, {"admin-test", "/api/servers/other/sessions/relay-id/close", 404}, {"admin-test", "/api/servers/s/sessions/relay-id/close", 200}} {
		request := httptest.NewRequest(http.MethodPost, tc.path, nil)
		request.Header.Set("X-API-Key", tc.key)
		response := httptest.NewRecorder()
		a.GetRouter().ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Fatalf("close %s status=%d want=%d body=%s", tc.path, response.Code, tc.status, response.Body.String())
		}
	}
	if !controller.closed {
		t.Fatal("admin close not routed")
	}
}
