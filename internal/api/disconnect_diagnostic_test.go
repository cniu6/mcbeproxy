package api

import (
	"net/http"
	"strings"
	"testing"

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
	server.proxyController = &disconnectDiagnosticController{}
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
	} {
		response := doJSONRequestForAuthTest(server, http.MethodGet, tc.path, tc.key, nil)
		if response.Code != tc.status {
			t.Fatalf("%s status=%d want=%d body=%s", tc.path, response.Code, tc.status, response.Body.String())
		}
		if tc.status != http.StatusOK && strings.Contains(response.Body.String(), "192.0.2.1") {
			t.Fatal("未授权响应泄漏诊断地址")
		}
	}
}
