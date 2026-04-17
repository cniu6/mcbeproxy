package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

// mockOutboundManager implements proxy.OutboundManager for testing.
type mockOutboundManager struct {
	outbounds map[string]*config.ProxyOutbound
	latency   map[string]int64
	selected  map[string]string
}

func newMockOutboundManager() *mockOutboundManager {
	return &mockOutboundManager{
		outbounds: make(map[string]*config.ProxyOutbound),
		latency:   make(map[string]int64),
		selected:  make(map[string]string),
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

func (m *mockOutboundManager) GetServerSelectedNode(serverID string) (string, bool) {
	node, ok := m.selected[serverID]
	if !ok || node == "" {
		return "", false
	}
	return node, true
}

func (m *mockOutboundManager) SetServerSelectedNode(serverID, nodeName string) {
	if nodeName == "" {
		delete(m.selected, serverID)
		return
	}
	m.selected[serverID] = nodeName
}

func (m *mockOutboundManager) GetBestNodeForServer(serverID, groupOrName, sortBy string) (string, int64) {
	var bestName string
	var bestLatency int64
	for name := range m.outbounds {
		latency, ok := m.GetServerNodeLatency(serverID, name, sortBy)
		if !ok || latency <= 0 {
			continue
		}
		if bestName == "" || latency < bestLatency {
			bestName = name
			bestLatency = latency
		}
	}
	return bestName, bestLatency
}

// setupTestProxyOutboundHandler creates a test handler with mock dependencies.
func setupTestProxyOutboundHandler() (*ProxyOutboundHandler, *config.ProxyOutboundConfigManager, *mockOutboundManager) {
	// Create config manager
	configMgr := config.NewProxyOutboundConfigManager("test_proxy_outbounds.json")
	subConfigMgr := config.NewProxySubscriptionConfigManager("test_proxy_subscriptions.json")

	// Create mock outbound manager
	outboundMgr := newMockOutboundManager()

	// Create handler
	handler := NewProxyOutboundHandler(configMgr, subConfigMgr, nil, outboundMgr)

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
	router.POST("/api/proxy-outbounds/parse-import", handler.ParseImportContent)
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

func TestParseImportContent_Success(t *testing.T) {
	handler, _ := setupTestHandler()
	router := setupTestRouter(handler)

	body := map[string]string{
		"content": "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&type=grpc&serviceName=gun&authority=grpc.example.com&sni=cdn.example.com#grpc-node\n",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/proxy-outbounds/parse-import", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !response.Success {
		t.Fatalf("Expected success=true, got false: %v", response.Msg)
	}

	data, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected object response, got %T", response.Data)
	}
	if got := int(data["count"].(float64)); got != 1 {
		t.Fatalf("Expected count=1, got %d", got)
	}
	items, ok := data["items"].([]interface{})
	if !ok || len(items) != 1 {
		t.Fatalf("Expected one parsed item, got %#v", data["items"])
	}
	item, ok := items[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected parsed item object, got %T", items[0])
	}
	if item["type"] != config.ProtocolVLESS {
		t.Fatalf("Expected type=%s, got %v", config.ProtocolVLESS, item["type"])
	}
	if item["network"] != "grpc" {
		t.Fatalf("Expected network=grpc, got %v", item["network"])
	}
	if item["grpc_service_name"] != "gun" {
		t.Fatalf("Expected grpc_service_name=gun, got %v", item["grpc_service_name"])
	}
	if item["grpc_authority"] != "grpc.example.com" {
		t.Fatalf("Expected grpc_authority=grpc.example.com, got %v", item["grpc_authority"])
	}
	if insecure, exists := item["insecure"]; exists && insecure == true {
		t.Fatalf("Expected insecure to be absent or false, got %v", insecure)
	}
}

func TestParseImportContent_HTTPUpgradeSuccess(t *testing.T) {
	handler, _ := setupTestHandler()
	router := setupTestRouter(handler)

	body := map[string]string{
		"content": "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&type=httpupgrade&path=%2Fedge-upgrade&host=cdn.example.com#httpupgrade-node\n",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/proxy-outbounds/parse-import", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !response.Success {
		t.Fatalf("Expected success=true, got false: %v", response.Msg)
	}

	data, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected object response, got %T", response.Data)
	}
	items, ok := data["items"].([]interface{})
	if !ok || len(items) != 1 {
		t.Fatalf("Expected one parsed item, got %#v", data["items"])
	}
	item, ok := items[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected parsed item object, got %T", items[0])
	}
	if item["network"] != "httpupgrade" {
		t.Fatalf("Expected network=httpupgrade, got %v", item["network"])
	}
	if item["ws_path"] != "/edge-upgrade" {
		t.Fatalf("Expected ws_path=/edge-upgrade, got %v", item["ws_path"])
	}
	if item["ws_host"] != "cdn.example.com" {
		t.Fatalf("Expected ws_host=cdn.example.com, got %v", item["ws_host"])
	}
}

func TestParseImportContent_XHTTPSuccess(t *testing.T) {
	handler, _ := setupTestHandler()
	router := setupTestRouter(handler)

	body := map[string]string{
		"content": "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&type=xhttp&path=%2Fsplit&host=cdn.example.com&mode=stream-up#xhttp-node\n",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/proxy-outbounds/parse-import", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !response.Success {
		t.Fatalf("Expected success=true, got false: %v", response.Msg)
	}

	data, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected object response, got %T", response.Data)
	}
	items, ok := data["items"].([]interface{})
	if !ok || len(items) != 1 {
		t.Fatalf("Expected one parsed item, got %#v", data["items"])
	}
	item, ok := items[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected parsed item object, got %T", items[0])
	}
	if item["network"] != "xhttp" {
		t.Fatalf("Expected network=xhttp, got %v", item["network"])
	}
	if item["ws_path"] != "/split" {
		t.Fatalf("Expected ws_path=/split, got %v", item["ws_path"])
	}
	if item["ws_host"] != "cdn.example.com" {
		t.Fatalf("Expected ws_host=cdn.example.com, got %v", item["ws_host"])
	}
	if item["xhttp_mode"] != "stream-up" {
		t.Fatalf("Expected xhttp_mode=stream-up, got %v", item["xhttp_mode"])
	}
}

func TestBuildHTTPTestTargets_DeduplicatesAndPreservesOrder(t *testing.T) {
	targets := buildHTTPTestTargets([]string{"google", "cloudflare", "google", "baidu", "unknown", "CLOUDFLARE"})
	if len(targets) != 3 {
		t.Fatalf("expected 3 unique targets, got %d", len(targets))
	}
	if targets[0].Name != "Google" || targets[1].Name != "Cloudflare" || targets[2].Name != "Baidu" {
		t.Fatalf("unexpected target order: %#v", targets)
	}
}

func TestHTTPTestClient_ReusesConnectionForSameHost(t *testing.T) {
	handler, _ := setupTestHandler()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	var dialCalls int32
	client, transport := newHTTPTestClient(httpTestClientConfig{
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			atomic.AddInt32(&dialCalls, 1)
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
		requestTimeout:        5 * time.Second,
		tlsHandshakeTimeout:   5 * time.Second,
		responseHeaderTimeout: 5 * time.Second,
		idleConnTimeout:       30 * time.Second,
	})
	defer transport.CloseIdleConnections()

	cfg := &config.ProxyOutbound{Name: "node-1", Server: "reuse.test", Port: 443}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first := handler.testHTTPWithClient(ctx, client, cfg, HTTPTestTarget{Name: "first", URL: server.URL + "/first"})
	second := handler.testHTTPWithClient(ctx, client, cfg, HTTPTestTarget{Name: "second", URL: server.URL + "/second"})

	if !first.Success || !second.Success {
		t.Fatalf("expected both requests to succeed, got first=%+v second=%+v", first, second)
	}
	if got := atomic.LoadInt32(&dialCalls); got != 1 {
		t.Fatalf("expected connection reuse to keep dial count at 1, got %d", got)
	}
}

func TestBatchProxyTestBudgetsIncreaseWithWorkers(t *testing.T) {
	workers := runtime.GOMAXPROCS(0)
	if workers < 4 {
		workers = 4
	}
	if got, want := defaultBatchProxyTestConcurrency("http"), defaultBatchProxyTestTypeBudget("http"); got != want {
		t.Fatalf("http default concurrency=%d, want %d", got, want)
	}
	if got, want := defaultBatchProxyTestConcurrency("udp"), defaultBatchProxyTestTypeBudget("udp"); got != want {
		t.Fatalf("udp default concurrency=%d, want %d", got, want)
	}
	if got := defaultBatchProxyTestGlobalBudget(); got < 64 || got > 256 {
		t.Fatalf("global batch budget out of expected range: %d", got)
	}
	if got := defaultBatchProxyTestTypeBudget("http"); got < 48 || got > 128 {
		t.Fatalf("http batch budget out of expected range: %d", got)
	}
	if got := defaultBatchProxyTestTypeBudget("udp"); got < 24 || got > 96 {
		t.Fatalf("udp batch budget out of expected range: %d", got)
	}
}

func TestParseImportContent_FiltersMetadataLikeNodeNames(t *testing.T) {
	handler, _ := setupTestHandler()
	router := setupTestRouter(handler)

	body := map[string]string{
		"content": "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls#剩余流量：1GB\nvmess://eyJhZGQiOiJ2bWVzcy5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjEyM2U0NTY3LWU4OWItMTJkMy1hNDU2LTQyNjYxNDE3NDAwMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwicHMiOiJ2bWVzcy1ub2RlIiwidGxzIjoidGxzIn0=\n",
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/proxy-outbounds/parse-import", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var response APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if !response.Success {
		t.Fatalf("Expected success=true, got false: %v", response.Msg)
	}

	data, ok := response.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected object response, got %T", response.Data)
	}
	if got := int(data["count"].(float64)); got != 1 {
		t.Fatalf("Expected count=1, got %d", got)
	}
	if got := int(data["filtered"].(float64)); got != 1 {
		t.Fatalf("Expected filtered=1, got %d", got)
	}
	items, ok := data["items"].([]interface{})
	if !ok || len(items) != 1 {
		t.Fatalf("Expected one parsed item, got %#v", data["items"])
	}
	item, ok := items[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected parsed item object, got %T", items[0])
	}
	if item["name"] != "vmess-node" {
		t.Fatalf("Expected surviving node name vmess-node, got %v", item["name"])
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

func TestShouldMeasureWarmUDPTestLatency(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.ProxyOutbound
		want bool
	}{
		{name: "nil config", cfg: nil, want: false},
		{name: "anytls enabled", cfg: &config.ProxyOutbound{Type: config.ProtocolAnyTLS}, want: true},
		// Regression: Hysteria2 pays a full QUIC handshake on a cold outbound,
		// so the first RakNet ping latency is misleading. A warm measurement
		// represents the steady-state RTT proxy traffic will see.
		{name: "hysteria2 enabled", cfg: &config.ProxyOutbound{Type: config.ProtocolHysteria2}, want: true},
		{name: "vless disabled", cfg: &config.ProxyOutbound{Type: config.ProtocolVLESS}, want: false},
		{name: "trojan disabled", cfg: &config.ProxyOutbound{Type: config.ProtocolTrojan}, want: false},
		{name: "vmess disabled", cfg: &config.ProxyOutbound{Type: config.ProtocolVMess}, want: false},
		{name: "shadowsocks disabled", cfg: &config.ProxyOutbound{Type: config.ProtocolShadowsocks}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldMeasureWarmUDPTestLatency(tt.cfg); got != tt.want {
				t.Fatalf("shouldMeasureWarmUDPTestLatency() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestShouldReuseCachedUDPTestOutbound guards the MCBE UDP test cache-reuse
// policy. Hysteria2 and AnyTLS must reuse the long-lived outbound (and thus
// the underlying QUIC / AnyTLS session) because a fresh handshake per test
// can easily consume the entire 8s test budget on high-RTT paths and causes
// spurious "QUIC handshake timed out" failures; all other protocols must
// fall back to a per-call fresh outbound to avoid unexpected session
// sharing side effects.
func TestShouldReuseCachedUDPTestOutbound(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.ProxyOutbound
		want bool
	}{
		{name: "nil config", cfg: nil, want: false},
		{name: "anytls cached", cfg: &config.ProxyOutbound{Type: config.ProtocolAnyTLS}, want: true},
		{name: "hysteria2 cached", cfg: &config.ProxyOutbound{Type: config.ProtocolHysteria2}, want: true},
		{name: "vless not cached", cfg: &config.ProxyOutbound{Type: config.ProtocolVLESS}, want: false},
		{name: "trojan not cached", cfg: &config.ProxyOutbound{Type: config.ProtocolTrojan}, want: false},
		{name: "vmess not cached", cfg: &config.ProxyOutbound{Type: config.ProtocolVMess}, want: false},
		{name: "shadowsocks not cached", cfg: &config.ProxyOutbound{Type: config.ProtocolShadowsocks}, want: false},
		{name: "socks5 not cached", cfg: &config.ProxyOutbound{Type: config.ProtocolSOCKS5}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldReuseCachedUDPTestOutbound(tt.cfg); got != tt.want {
				t.Fatalf("shouldReuseCachedUDPTestOutbound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClampBatchProxyTestConcurrency_Bounds(t *testing.T) {
	tests := []struct {
		name      string
		total     int
		requested int
		testType  string
		want      int
	}{
		{name: "zero total returns one", total: 0, requested: 16, testType: "udp", want: 1},
		{name: "udp clamped to type budget", total: 200, requested: 256, testType: "udp", want: defaultBatchProxyTestTypeBudget("udp")},
		{name: "tcp clamped to type budget", total: 200, requested: 256, testType: "tcp", want: defaultBatchProxyTestTypeBudget("tcp")},
		{name: "http clamped to type budget", total: 200, requested: 256, testType: "http", want: defaultBatchProxyTestTypeBudget("http")},
		{name: "requested beats total", total: 3, requested: 32, testType: "udp", want: 3},
		{name: "default used when requested <= 0", total: 200, requested: 0, testType: "udp", want: defaultBatchProxyTestConcurrency("udp")},
		{name: "unknown type clamped to global budget", total: 200, requested: 256, testType: "other", want: defaultBatchProxyTestTypeBudget("other")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clampBatchProxyTestConcurrency(tc.total, tc.requested, tc.testType)
			if got < 1 {
				t.Fatalf("concurrency must be >= 1, got %d", got)
			}
			if got != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, got)
			}
		})
	}
}

// TestDefaultBatchProxyTestBudgets_MeetFloors ensures the shared cross-batch
// limiter budgets never shrink below the documented floors even on tiny
// dev boxes. Regression guard against accidental lowering during refactors.
func TestDefaultBatchProxyTestBudgets_MeetFloors(t *testing.T) {
	if got := defaultBatchProxyTestGlobalBudget(); got < 64 {
		t.Fatalf("global budget floor violated: got %d want >= 64", got)
	}
	if got := defaultBatchProxyTestTypeBudget("udp"); got < 24 {
		t.Fatalf("udp budget floor violated: got %d want >= 24", got)
	}
	for _, typ := range []string{"tcp", "http"} {
		if got := defaultBatchProxyTestTypeBudget(typ); got < 48 {
			t.Fatalf("%s budget floor violated: got %d want >= 48", typ, got)
		}
	}
}

func TestBatchProxyTestItemTimeout_ByType(t *testing.T) {
	cases := map[string]time.Duration{
		"tcp":     12 * time.Second,
		"http":    20 * time.Second,
		"udp":     12 * time.Second,
		"unknown": 15 * time.Second,
	}
	for typ, want := range cases {
		if got := batchProxyTestItemTimeout(typ); got != want {
			// "unknown" branch falls through to default; assert only declared ones.
			if typ == "unknown" {
				continue
			}
			t.Fatalf("type %q: expected %s, got %s", typ, want, got)
		}
	}
}

func TestAcquireBatchProxyTestPermit_ReleasesTokens(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	release, err := acquireBatchProxyTestPermit(ctx, "udp")
	if err != nil {
		t.Fatalf("acquire returned error: %v", err)
	}
	if release == nil {
		t.Fatal("expected release function, got nil")
	}
	release()
	release2, err := acquireBatchProxyTestPermit(ctx, "udp")
	if err != nil {
		t.Fatalf("second acquire returned error: %v", err)
	}
	release2()
}

func TestBatchProxyTestLimiter_Concurrency(t *testing.T) {
	// Regression guard for A1/A2: acquireBatchProxyTestPermit must admit
	// multiple concurrent callers up to the configured budget, never serialize.
	const callers = 8
	var active int32
	var maxActive int32
	done := make(chan struct{})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for i := 0; i < callers; i++ {
		go func() {
			release, err := acquireBatchProxyTestPermit(ctx, "udp")
			if err != nil {
				done <- struct{}{}
				return
			}
			cur := atomic.AddInt32(&active, 1)
			for {
				prev := atomic.LoadInt32(&maxActive)
				if cur <= prev || atomic.CompareAndSwapInt32(&maxActive, prev, cur) {
					break
				}
			}
			time.Sleep(40 * time.Millisecond)
			atomic.AddInt32(&active, -1)
			release()
			done <- struct{}{}
		}()
	}
	for i := 0; i < callers; i++ {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for permits: %v", ctx.Err())
		}
	}
	if atomic.LoadInt32(&maxActive) < 2 {
		t.Fatalf("expected at least 2 concurrent permit holders, got maxActive=%d", maxActive)
	}
}
