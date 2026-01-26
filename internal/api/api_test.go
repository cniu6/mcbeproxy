package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/session"
)

// mockProxyController implements ProxyController for testing.
type mockProxyController struct{}

func (m *mockProxyController) StartServer(serverID string) error               { return nil }
func (m *mockProxyController) StopServer(serverID string) error                { return nil }
func (m *mockProxyController) ReloadServer(serverID string) error              { return nil }
func (m *mockProxyController) IsServerRunning(serverID string) bool            { return false }
func (m *mockProxyController) GetServerStatus(serverID string) string          { return "stopped" }
func (m *mockProxyController) GetActiveSessionsForServer(serverID string) int  { return 0 }
func (m *mockProxyController) GetAllServerStatuses() []config.ServerConfigDTO  { return nil }
func (m *mockProxyController) KickPlayer(playerName string, reason string) int { return 0 }
func (m *mockProxyController) GetServerLatency(serverID string) (int64, bool)  { return 0, false }
func (m *mockProxyController) ReloadProxyPorts() error                         { return nil }

// setupTestAPI creates a test API server with a temporary database.
func setupTestAPI(t *testing.T) (*APIServer, *db.Database, func()) {
	t.Helper()

	// Create temporary database
	tmpFile, err := os.CreateTemp("", "api_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()

	database, err := db.NewDatabase(tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to create database: %v", err)
	}

	if err := database.Initialize(); err != nil {
		database.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to initialize database: %v", err)
	}

	// Create config manager with temp file
	configFile, err := os.CreateTemp("", "server_list_*.json")
	if err != nil {
		database.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to create config file: %v", err)
	}
	configFile.WriteString("[]")
	configFile.Close()

	configMgr, err := config.NewConfigManager(configFile.Name())
	if err != nil {
		database.Close()
		os.Remove(tmpFile.Name())
		os.Remove(configFile.Name())
		t.Fatalf("Failed to create config manager: %v", err)
	}
	configMgr.Load()

	// Create repositories
	keyRepo := db.NewAPIKeyRepository(database, 100)
	playerRepo := db.NewPlayerRepository(database)
	sessionMgr := session.NewSessionManager(5 * time.Minute)

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create monitor
	mon := monitor.NewMonitor()

	// Create ACL manager
	aclManager := acl.NewACLManager(database)

	// Create session repository
	sessionRepo := db.NewSessionRepository(database, 100)

	// Create API server
	api := NewAPIServer(
		config.DefaultGlobalConfig(),
		configMgr,
		sessionMgr,
		database,
		keyRepo,
		playerRepo,
		sessionRepo,
		mon,
		&mockProxyController{},
		aclManager,
		nil, // proxyOutboundHandler - not needed for these tests
		nil,
	)

	cleanup := func() {
		database.Close()
		os.Remove(tmpFile.Name())
		os.Remove(configFile.Name())
	}

	return api, database, cleanup
}

// **Feature: mcpe-server-proxy, Property 10: API Key Authentication**
// **Validates: Requirements 5.2**
//
// *For any* API request with X-API-Key header, the request SHALL be allowed
// if and only if the key exists in the api_keys table.
func TestProperty10_APIKeyAuthentication(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for random API key strings (fixed length to avoid filtering)
	apiKeyGen := gen.SliceOfN(16, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Generator for random key names (fixed length to avoid filtering)
	keyNameGen := gen.SliceOfN(8, gen.AlphaChar()).Map(func(chars []rune) string {
		return string(chars)
	})

	// Property: Valid API key should be allowed when keys are configured
	properties.Property("valid API key allows request", prop.ForAll(
		func(keyValue, keyName string) bool {
			api, database, cleanup := setupTestAPI(t)
			defer cleanup()

			keyRepo := db.NewAPIKeyRepository(database, 100)

			// Create an API key in the database
			apiKey := &db.APIKey{
				Key:       keyValue,
				Name:      keyName,
				CreatedAt: time.Now(),
				IsAdmin:   false,
			}
			if err := keyRepo.Create(apiKey); err != nil {
				t.Logf("Failed to create API key: %v", err)
				return false
			}

			// Make a request with the valid API key
			req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
			req.Header.Set("X-API-Key", keyValue)
			w := httptest.NewRecorder()

			api.GetRouter().ServeHTTP(w, req)

			// Should return 200 OK (not 401 Unauthorized)
			return w.Code == http.StatusOK
		},
		apiKeyGen,
		keyNameGen,
	))

	// Property: Invalid API key should be rejected when keys are configured
	properties.Property("invalid API key rejects request", prop.ForAll(
		func(validKey, invalidKey, keyName string) bool {
			// Ensure valid and invalid keys are different
			if validKey == invalidKey {
				return true // Skip this case
			}

			api, database, cleanup := setupTestAPI(t)
			defer cleanup()

			keyRepo := db.NewAPIKeyRepository(database, 100)

			// Create a valid API key in the database
			apiKey := &db.APIKey{
				Key:       validKey,
				Name:      keyName,
				CreatedAt: time.Now(),
				IsAdmin:   false,
			}
			if err := keyRepo.Create(apiKey); err != nil {
				t.Logf("Failed to create API key: %v", err)
				return false
			}

			// Make a request with an invalid API key
			req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
			req.Header.Set("X-API-Key", invalidKey)
			w := httptest.NewRecorder()

			api.GetRouter().ServeHTTP(w, req)

			// Should return 401 Unauthorized
			return w.Code == http.StatusUnauthorized
		},
		apiKeyGen,
		apiKeyGen,
		keyNameGen,
	))

	// Property: Missing API key should be rejected when keys are configured
	properties.Property("missing API key rejects request when keys exist", prop.ForAll(
		func(keyValue, keyName string) bool {
			api, database, cleanup := setupTestAPI(t)
			defer cleanup()

			keyRepo := db.NewAPIKeyRepository(database, 100)

			// Create an API key in the database
			apiKey := &db.APIKey{
				Key:       keyValue,
				Name:      keyName,
				CreatedAt: time.Now(),
				IsAdmin:   false,
			}
			if err := keyRepo.Create(apiKey); err != nil {
				t.Logf("Failed to create API key: %v", err)
				return false
			}

			// Make a request without API key header
			req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
			w := httptest.NewRecorder()

			api.GetRouter().ServeHTTP(w, req)

			// Should return 401 Unauthorized
			return w.Code == http.StatusUnauthorized
		},
		apiKeyGen,
		keyNameGen,
	))

	// Property: Any request should be allowed when no API keys are configured
	properties.Property("no API keys configured allows all requests", prop.ForAll(
		func(randomKey string) bool {
			api, _, cleanup := setupTestAPI(t)
			defer cleanup()

			// Don't create any API keys - database is empty

			// Make a request with any key (or no key)
			req := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
			if randomKey != "" {
				req.Header.Set("X-API-Key", randomKey)
			}
			w := httptest.NewRecorder()

			api.GetRouter().ServeHTTP(w, req)

			// Should return 200 OK (authentication skipped)
			return w.Code == http.StatusOK
		},
		gen.AnyString(),
	))

	properties.TestingRun(t)
}
