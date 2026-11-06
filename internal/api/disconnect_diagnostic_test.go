package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

type disconnectDiagnosticController struct{ mockProxyController }

func (*disconnectDiagnosticController) GetLastDisconnectReport(serverID string) (proxy.RawUDPDisconnectReport, bool) {
	if serverID != "fixture" {
		return proxy.RawUDPDisconnectReport{}, false
	}
	return proxy.RawUDPDisconnectReport{Server: serverID, EndReason: "upstream_read_error", Client: "192.0.2.1:1234"}, true
}

func TestLastDisconnectDiagnosticAdminOnly(t *testing.T) {
	server, database, cleanup := setupTestAPI(t)
	defer cleanup()
	server.proxyController = &disconnectDiagnosticController{mockProxyController: mockProxyController{statuses: []config.ServerConfigDTO{{ID: "fixture", Name: "测试服务器"}, {ID: "unknown"}}}}
	addAPIKeyForAuthTest(t, database, "diagnostic-reader", false)
	addAPIKeyForAuthTest(t, database, "diagnostic-admin", true)
	for _, tc := range []struct {
		key, path string
		status    int
	}{
		{"", "/api/servers/fixture/last-disconnect", http.StatusUnauthorized},
		{"diagnostic-reader", "/api/servers/fixture/last-disconnect", http.StatusForbidden},
		{"diagnostic-admin", "/api/servers/fixture/last-disconnect", http.StatusOK},
		{"diagnostic-admin", "/api/servers/unknown/last-disconnect", http.StatusNotFound},
		{"", "/api/servers/disconnect-reports", http.StatusUnauthorized},
		{"diagnostic-reader", "/api/servers/disconnect-reports", http.StatusForbidden},
		{"diagnostic-admin", "/api/servers/disconnect-reports", http.StatusOK},
	} {
		response := doJSONRequestForAuthTest(server, http.MethodGet, tc.path, tc.key, nil)
		if response.Code != tc.status {
			t.Fatalf("%s status=%d want=%d body=%s", tc.path, response.Code, tc.status, response.Body.String())
		}
		if tc.status == http.StatusOK && tc.path == "/api/servers/disconnect-reports" {
			var payload struct {
				Data []serverDisconnectSnapshot `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Data) != 1 || payload.Data[0].ServerID != "fixture" || payload.Data[0].ServerName != "测试服务器" || payload.Data[0].Report.Client != "192.0.2.1:1234" {
				t.Fatalf("汇总未保留服务器和原始诊断：%s", response.Body.String())
			}
		}
		if tc.status != http.StatusOK && strings.Contains(response.Body.String(), "192.0.2.1") {
			t.Fatal("未授权响应泄漏诊断地址")
		}
	}
}
