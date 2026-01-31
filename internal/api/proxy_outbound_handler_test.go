package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

// mockOutboundManager implements proxy.OutboundManager for testing.
type mockOutboundManager struct {
	outbounds map[string]*config.ProxyOutbound
	latency  map[string]int64
}

func newMockOutboundManager() *mockOutboundManager {
	return &mockOutboundManager{
		outbounds: make(map[string]*config.ProxyOutbound),
		latency:   make(map[string]int64),
	}
}

func (m *mockOutboundManager) AddOutbound(cfg *config.ProxyOutbound) error {
	m.outbounds[cfg.Name] = cfg
	return nil
}

func (m *mockOutboundManager) GetOutbound(name string) (*config.ProxyOutbound, bool) {
	cfg, ok := m.outbounds[name]
	return cfg, ok
}

func (m *mockOutboundManager) DeleteOutbound(name string) error {
	delete(m.outbounds, name)
	return nil
}

func (m *mockOutboundManager) ListOutbounds() []*config.ProxyOutbound {
	result := make([]*config.ProxyOutbound, 0, len(m.outbounds))
	for _, cfg := range m.outbounds {
		result = append(result, cfg)
	}
	return result
}

func (m *mockOutboundManager) UpdateOutbound(name string, cfg *config.ProxyOutbound) error {
	m.outbounds[cfg.Name] = cfg
	return nil
}

func (m *mockOutboundManager) CheckHealth(ctx context.Context, name string) error {
	return nil
}

func (m *mockOutboundManager) GetHealthStatus(name string) *proxy.HealthStatus {
	if _, ok := m.outbounds[name]; !ok {
		return nil
	}
	return &proxy.HealthStatus{Healthy: true}
}

func (m *mockOutboundManager) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	return nil, nil
}

func (m *mockOutboundManager) Start() error  { return nil }
func (m *mockOutboundManager) Stop() error   { return nil }
func (m *mockOutboundManager) Reload() error { return nil }

func (m *mockOutboundManager) GetActiveConnectionCount() int64 { return 0 }

func (m *mockOutboundManager) GetGroupStats(groupName string) *proxy.GroupStats {
	var nodes []*config.ProxyOutbound
	for _, outbound := range m.outbounds {
		if outbound.Group == groupName {
			nodes = append(nodes, outbound)
		}
	}

	if len(nodes) == 0 {
		return nil
	}

	stats := &proxy.GroupStats{
		Name:       groupName,
		TotalCount: len(nodes),
	}

	for _, node := range nodes {
		if node.GetHealthy() {
			stats.HealthyCount++
		}
		if node.UDPAvailable != nil && *node.UDPAvailable {
			stats.UDPAvailable++
		}
	}

	return stats
}

func (m *mockOutboundManager) ListGroups() []*proxy.GroupStats {
	groupNames := make(map[string]bool)
	for _, outbound := range m.outbounds {
		groupNames[outbound.Group] = true
	}

	var result []*proxy.GroupStats
	for groupName := range groupNames {
		stats := m.GetGroupStats(groupName)
		if stats != nil {
			result = append(result, stats)
		}
	}

	return result
}

func (m *mockOutboundManager) GetOutboundsByGroup(groupName string) []*config.ProxyOutbound {
	var result []*config.ProxyOutbound
	for _, outbound := range m.outbounds {
		if outbound.Group == groupName {
			result = append(result, outbound)
		}
	}
	return result
}

func (m *mockOutboundManager) SelectOutbound(groupOrName, strategy, sortBy string) (*config.ProxyOutbound, error) {
	return nil, nil
}

func (m *mockOutboundManager) SelectOutboundWithFailover(groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	return nil, nil
}

func (m *mockOutboundManager) SetServerNodeLatency(serverID, nodeName, sortBy string, latencyMs int64) {
	key := serverID + "|" + nodeName + "|" + sortBy
	m.latency[key] = latencyMs
}

func (m *mockOutboundManager) GetServerNodeLatency(serverID, nodeName, sortBy string) (int64, bool) {
	key := serverID + "|" + nodeName + "|" + sortBy
	v, ok := m.latency[key]
	return v, ok
}

func (m *mockOutboundManager) SelectOutboundWithFailoverForServer(serverID, groupOrName, strategy, sortBy string, excludeNodes []string) (*config.ProxyOutbound, error) {
	return m.SelectOutboundWithFailover(groupOrName, strategy, sortBy, excludeNodes)
}

// setupTestProxyOutboundHandler creates a test handler with mock dependencies.
func setupTestProxyOutboundHandler() (*ProxyOutboundHandler, *config.ProxyOutboundConfigManager, *mockOutboundManager) {
	// Create config manager
	configMgr := config.NewProxyOutboundConfigManager("test_proxy_outbounds.json")

	// Create mock outbound manager
	outboundMgr := newMockOutboundManager()

	// Create handler
	handler := NewProxyOutboundHandler(configMgr, nil, outboundMgr)

	return handler, configMgr, outboundMgr
}

func setupTestHandler() (*ProxyOutboundHandler, *mockOutboundManager) {
	h, _, m := setupTestProxyOutboundHandler()
	return h, m
}

// setupTestRouter creates a test router with the handler registered.
func setupTestRouter(handler *ProxyOutboundHandler) *gin.Engine {
	router := gin.New()
	router.GET("/api/proxy-outbounds/groups", handler.ListGroups)
	router.GET("/api/proxy-outbounds/groups/:name", handler.GetGroup)
	return router
}

// TestListGroups_Success tests successful group list response.
// Requirements: 8.1, 8.4
func TestListGroups_Success(t *testing.T) {
	handler, mockMgr := setupTestHandler()

	// Add test outbounds with different groups
	udpAvailable := true
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:         "node1",
		Type:         config.ProtocolShadowsocks,
		Server:       "server1.example.com",
		Port:         8388,
		Group:        "HK-香港",
		Method:       "aes-256-gcm",
		Password:     "test",
		UDPAvailable: &udpAvailable,
	})
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:         "node2",
		Type:         config.ProtocolShadowsocks,
		Server:       "server2.example.com",
		Port:         8388,
		Group:        "HK-香港",
		Method:       "aes-256-gcm",
		Password:     "test",
		UDPAvailable: &udpAvailable,
	})
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:     "node3",
		Type:     config.ProtocolShadowsocks,
		Server:   "server3.example.com",
		Port:     8388,
		Group:    "US-美国",
		Method:   "aes-256-gcm",
		Password: "test",
	})
	// Add ungrouped node
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:     "node4",
		Type:     config.ProtocolShadowsocks,
		Server:   "server4.example.com",
		Port:     8388,
		Group:    "", // Ungrouped
		Method:   "aes-256-gcm",
		Password: "test",
	})

	router := setupTestRouter(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/groups", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected success=true, got false")
	}

	// Verify data is an array
	data, ok := response.Data.([]interface{})
	if !ok {
		t.Fatalf("Expected data to be an array, got %T", response.Data)
	}

	// Should have 3 groups: HK-香港, US-美国, and ungrouped (empty string)
	if len(data) != 3 {
		t.Errorf("Expected 3 groups, got %d", len(data))
	}
}

// TestListGroups_Empty tests empty group list response.
// Requirements: 8.1
func TestListGroups_Empty(t *testing.T) {
	handler, _ := setupTestHandler()
	router := setupTestRouter(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/groups", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected success=true, got false")
	}

	// Verify data is an empty array
	data, ok := response.Data.([]interface{})
	if !ok {
		t.Fatalf("Expected data to be an array, got %T", response.Data)
	}

	if len(data) != 0 {
		t.Errorf("Expected 0 groups, got %d", len(data))
	}
}

// TestGetGroup_Success tests successful single group response.
// Requirements: 8.2
func TestGetGroup_Success(t *testing.T) {
	handler, mockMgr := setupTestHandler()

	// Add test outbounds
	udpAvailable := true
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:         "node1",
		Type:         config.ProtocolShadowsocks,
		Server:       "server1.example.com",
		Port:         8388,
		Group:        "HK-香港",
		Method:       "aes-256-gcm",
		Password:     "test",
		UDPAvailable: &udpAvailable,
	})
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:         "node2",
		Type:         config.ProtocolShadowsocks,
		Server:       "server2.example.com",
		Port:         8388,
		Group:        "HK-香港",
		Method:       "aes-256-gcm",
		Password:     "test",
		UDPAvailable: &udpAvailable,
	})

	router := setupTestRouter(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/groups/HK-香港", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected success=true, got false")
	}

	// Verify data contains group stats
	data, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected data to be an object, got %T", response.Data)
	}

	if data["name"] != "HK-香港" {
		t.Errorf("Expected group name 'HK-香港', got '%v'", data["name"])
	}

	if data["total_count"].(float64) != 2 {
		t.Errorf("Expected total_count=2, got %v", data["total_count"])
	}

	if data["udp_available"].(float64) != 2 {
		t.Errorf("Expected udp_available=2, got %v", data["udp_available"])
	}
}

// TestGetGroup_NotFound tests 404 error for non-existent group.
// Requirements: 8.3
func TestGetGroup_NotFound(t *testing.T) {
	handler, _ := setupTestHandler()
	router := setupTestRouter(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/groups/non-existent-group", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Success {
		t.Errorf("Expected success=false, got true")
	}
}

// TestListGroups_IncludesUngrouped tests that ungrouped nodes are included.
// Requirements: 8.4
func TestListGroups_IncludesUngrouped(t *testing.T) {
	handler, mockMgr := setupTestHandler()

	// Add only ungrouped nodes
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:     "node1",
		Type:     config.ProtocolShadowsocks,
		Server:   "server1.example.com",
		Port:     8388,
		Group:    "", // Ungrouped
		Method:   "aes-256-gcm",
		Password: "test",
	})
	mockMgr.AddOutbound(&config.ProxyOutbound{
		Name:     "node2",
		Type:     config.ProtocolShadowsocks,
		Server:   "server2.example.com",
		Port:     8388,
		Group:    "", // Ungrouped
		Method:   "aes-256-gcm",
		Password: "test",
	})

	router := setupTestRouter(handler)

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/groups", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected success=true, got false")
	}

	// Verify data contains ungrouped entry
	data, ok := response.Data.([]interface{})
	if !ok {
		t.Fatalf("Expected data to be an array, got %T", response.Data)
	}

	// Should have 1 group (ungrouped with empty name)
	if len(data) != 1 {
		t.Errorf("Expected 1 group (ungrouped), got %d", len(data))
	}

	// Verify the ungrouped entry has empty name and correct count
	if len(data) > 0 {
		group := data[0].(map[string]interface{})
		if group["name"] != "" {
			t.Errorf("Expected ungrouped entry with empty name, got '%v'", group["name"])
		}
		if group["total_count"].(float64) != 2 {
			t.Errorf("Expected total_count=2 for ungrouped, got %v", group["total_count"])
		}
	}
}
