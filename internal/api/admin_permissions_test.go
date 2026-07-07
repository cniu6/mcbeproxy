package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"mcpeserverproxy/internal/db"
)

func addAPIKeyForAuthTest(t *testing.T, database *db.Database, key string, isAdmin bool) {
	t.Helper()
	repo := db.NewAPIKeyRepository(database, 100)
	if err := repo.Create(&db.APIKey{Key: key, Name: key, CreatedAt: time.Now(), IsAdmin: isAdmin}); err != nil {
		t.Fatalf("Create API key failed: %v", err)
	}
}

func doJSONRequestForAuthTest(api *APIServer, method, path, key string, body any) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	w := httptest.NewRecorder()
	api.GetRouter().ServeHTTP(w, req)
	return w
}

func TestAdminWriteRoutesRejectNonAdmin(t *testing.T) {
	api, database, cleanup := setupTestAPI(t)
	defer cleanup()
	addAPIKeyForAuthTest(t, database, "read-key", false)
	addAPIKeyForAuthTest(t, database, "admin-key", true)

	cases := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/keys", map[string]any{"name": "created", "is_admin": true}},
		{http.MethodPut, "/api/config/entry-path", map[string]any{"entry_path": "/admin"}},
		{http.MethodPost, "/api/acl/blacklist", map[string]any{"display_name": "BadPlayer", "enabled": true}},
		{http.MethodPost, "/api/servers", map[string]any{"id": "srv", "name": "srv", "target": "127.0.0.1", "port": 19132, "listen_addr": "127.0.0.1:0", "protocol": "raknet"}},
		{http.MethodDelete, "/api/sessions/history", nil},
		{http.MethodDelete, "/api/sessions/history/history-id", nil},
		{http.MethodDelete, "/api/sessions/session-id", nil},
		{http.MethodDelete, "/api/logs", nil},
		{http.MethodDelete, "/api/logs/app.log", nil},
		{http.MethodPost, "/api/players/Steve/kick", map[string]any{"reason": "admin-only"}},
		{http.MethodDelete, "/api/players/Steve", nil},
	}

	for _, tc := range cases {
		w := doJSONRequestForAuthTest(api, tc.method, tc.path, "read-key", tc.body)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s non-admin status = %d, want 403, body=%s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	w := doJSONRequestForAuthTest(api, http.MethodPost, "/api/keys", "admin-key", map[string]any{"name": "read-only", "is_admin": false})
	if w.Code != http.StatusOK {
		t.Fatalf("admin create key status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Success bool       `json:"success"`
		Data    *db.APIKey `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal create key response failed: %v", err)
	}
	if !resp.Success || resp.Data == nil {
		t.Fatalf("unexpected create key response: %s", w.Body.String())
	}
	if resp.Data.IsAdmin {
		t.Fatal("admin-created key without is_admin=true must remain non-admin")
	}
}
