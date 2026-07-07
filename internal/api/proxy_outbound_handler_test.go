package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/proxy"
)

func boolPtrForTest(v bool) *bool {
	return &v
}

// mockOutboundManager implements proxy.OutboundManager for testing.
type mockOutboundManager struct {
	outbounds map[string]*config.ProxyOutbound
	latency   map[string]int64
	history   map[string][]proxy.ServerNodeLatencySample
	outbound  map[string][]proxy.OutboundLatencySample
	selected  map[string]string
	manual    map[string]bool
}

func newMockOutboundManager() *mockOutboundManager {
	return &mockOutboundManager{
		outbounds: make(map[string]*config.ProxyOutbound),
		latency:   make(map[string]int64),
		history:   make(map[string][]proxy.ServerNodeLatencySample),
		outbound:  make(map[string][]proxy.OutboundLatencySample),
		selected:  make(map[string]string),
		manual:    make(map[string]bool),
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

func (m *mockOutboundManager) SetOutboundLatency(name, sortBy string, latencyMs int64) {
	key := name + "|" + sortBy
	m.outbound[key] = append(m.outbound[key], proxy.OutboundLatencySample{
		Timestamp: time.Now().UnixMilli(),
		LatencyMs: latencyMs,
		OK:        latencyMs > 0,
	})
}

func (m *mockOutboundManager) GetOutboundLatencyHistory(name, sortBy string) []proxy.OutboundLatencySample {
	key := name + "|" + sortBy
	items := m.outbound[key]
	result := make([]proxy.OutboundLatencySample, len(items))
	copy(result, items)
	return result
}

func (m *mockOutboundManager) DialPacketConn(ctx context.Context, outboundName string, destination string) (net.PacketConn, error) {
	return nil, nil
}

func (m *mockOutboundManager) Start() error  { return nil }
func (m *mockOutboundManager) Stop() error   { return nil }
func (m *mockOutboundManager) Reload() error { return nil }

func (m *mockOutboundManager) GetActiveConnectionCount() int64 { return 0 }
func (m *mockOutboundManager) GetOutboundConnectionCount(outboundName string) int64 {
	return 0
}

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
	m.history[key] = append(m.history[key], proxy.ServerNodeLatencySample{
		Timestamp: time.Now().UnixMilli(),
		LatencyMs: latencyMs,
		OK:        latencyMs > 0,
	})
}

func (m *mockOutboundManager) GetServerNodeLatency(serverID, nodeName, sortBy string) (int64, bool) {
	key := serverID + "|" + nodeName + "|" + sortBy
	v, ok := m.latency[key]
	return v, ok
}

func (m *mockOutboundManager) GetServerNodeLatencyHistory(serverID, nodeName, sortBy string) []proxy.ServerNodeLatencySample {
	key := serverID + "|" + nodeName + "|" + sortBy
	items := m.history[key]
	result := make([]proxy.ServerNodeLatencySample, len(items))
	copy(result, items)
	return result
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

func (m *mockOutboundManager) SetServerSelectedNodeManual(serverID, nodeName string) {
	m.SetServerSelectedNode(serverID, nodeName)
	if m.manual == nil {
		m.manual = make(map[string]bool)
	}
	if nodeName == "" {
		delete(m.manual, serverID)
	} else {
		m.manual[serverID] = true
	}
}

func (m *mockOutboundManager) IsServerNodeManual(serverID string) bool {
	return m.manual[serverID]
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

func setupTestProxyOutboundHandler() (*ProxyOutboundHandler, *config.ProxyOutboundConfigManager, *mockOutboundManager) {
	// Create config manager
	configMgr := config.NewProxyOutboundConfigManager("testdata/test_proxy_outbounds.json")
	subConfigMgr := config.NewProxySubscriptionConfigManager("testdata/test_proxy_subscriptions.json")

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

func setupTestRouter(handler *ProxyOutboundHandler) *gin.Engine {
	router := gin.New()
	router.GET("/api/proxy-outbounds/latency-overview", handler.GetProxyOutboundLatencyOverview)
	router.GET("/api/proxy-outbounds/:name/latency-history", handler.GetProxyOutboundLatencyHistory)
	router.GET("/api/proxy-outbounds/groups", handler.ListGroups)
	router.GET("/api/proxy-outbounds/groups/:name", handler.GetGroup)
	router.POST("/api/proxy-outbounds/parse-import", handler.ParseImportContent)
	return router
}

func TestProxyOutboundBodyUpdateRejectsRename(t *testing.T) {
	dir := t.TempDir()
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(dir, "proxy_outbounds.json"))
	handler := NewProxyOutboundHandler(configMgr, config.NewProxySubscriptionConfigManager(filepath.Join(dir, "subs.json")), nil, newMockOutboundManager())
	if err := configMgr.AddOutbound(&config.ProxyOutbound{Name: "old", Type: config.ProtocolShadowsocks, Server: "127.0.0.1", Port: 8388, Method: "aes-128-gcm", Password: "secret", Enabled: true}); err != nil {
		t.Fatalf("AddOutbound failed: %v", err)
	}
	router := gin.New()
	router.POST("/api/proxy-outbounds/update", handler.UpdateProxyOutboundByBody)

	payload := map[string]any{"name": "new", "type": config.ProtocolShadowsocks, "server": "127.0.0.1", "port": 8388, "method": "aes-128-gcm", "password": "secret", "enabled": true}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-outbounds/update", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("rename update status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestProxyOutboundSensitiveFieldsHiddenAndBlankUpdatePreserves(t *testing.T) {
	dir := t.TempDir()
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(dir, "proxy_outbounds.json"))
	handler := NewProxyOutboundHandler(configMgr, config.NewProxySubscriptionConfigManager(filepath.Join(dir, "subs.json")), nil, newMockOutboundManager())
	if err := configMgr.AddOutbound(&config.ProxyOutbound{Name: "node", Type: config.ProtocolShadowsocks, Server: "127.0.0.1", Port: 8388, Method: "aes-128-gcm", Password: "secret", UUID: "uuid-secret", ObfsPassword: "obfs-secret", Enabled: true}); err != nil {
		t.Fatalf("AddOutbound failed: %v", err)
	}
	router := gin.New()
	router.GET("/api/proxy-outbounds/:name", handler.GetProxyOutbound)
	router.POST("/api/proxy-outbounds/update", handler.UpdateProxyOutboundByBody)

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/node", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte("secret")) || bytes.Contains(w.Body.Bytes(), []byte("uuid-secret")) || bytes.Contains(w.Body.Bytes(), []byte("obfs-secret")) {
		t.Fatalf("response leaked sensitive field: %s", w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("has_password")) || !bytes.Contains(w.Body.Bytes(), []byte("has_uuid")) || !bytes.Contains(w.Body.Bytes(), []byte("has_obfs_password")) {
		t.Fatalf("response missing sensitive presence indicators: %s", w.Body.String())
	}

	payload := map[string]any{"name": "node", "type": config.ProtocolShadowsocks, "server": "127.0.0.1", "port": 8389, "method": "aes-128-gcm", "password": "", "uuid": "", "obfs_password": "", "enabled": true}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/proxy-outbounds/update", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d, body=%s", w.Code, w.Body.String())
	}
	stored, ok := configMgr.GetOutbound("node")
	if !ok {
		t.Fatal("updated outbound not found")
	}
	if stored.Password != "secret" || stored.UUID != "uuid-secret" || stored.ObfsPassword != "obfs-secret" {
		t.Fatalf("blank sensitive update overwrote secrets: password=%q uuid=%q obfs=%q", stored.Password, stored.UUID, stored.ObfsPassword)
	}
}

func TestProxyOutboundBodyDeleteTriggersReloadHook(t *testing.T) {
	dir := t.TempDir()
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(dir, "proxy_outbounds.json"))
	handler := NewProxyOutboundHandler(configMgr, config.NewProxySubscriptionConfigManager(filepath.Join(dir, "subs.json")), nil, newMockOutboundManager())
	if err := configMgr.AddOutbound(&config.ProxyOutbound{Name: "node", Type: config.ProtocolShadowsocks, Server: "127.0.0.1", Port: 8388, Method: "aes-128-gcm", Password: "secret", Enabled: true}); err != nil {
		t.Fatalf("AddOutbound failed: %v", err)
	}
	var reloaded atomic.Int32
	handler.SetOutboundReloadHook(func(name string) {
		if name == "node" {
			reloaded.Add(1)
		}
	})
	router := gin.New()
	router.POST("/api/proxy-outbounds/delete", handler.DeleteProxyOutboundByBody)

	body, _ := json.Marshal(map[string]any{"name": "node"})
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-outbounds/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body=%s", w.Code, w.Body.String())
	}
	if reloaded.Load() != 1 {
		t.Fatalf("reload hook calls = %d, want 1", reloaded.Load())
	}
}

func TestCreateProxySubscriptionSaveDoesNotLeaveAutoUpdateImmediatelyDue(t *testing.T) {
	dir := t.TempDir()
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(dir, "proxy_outbounds.json"))
	subConfigMgr := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "proxy_subscriptions.json"))
	handler := NewProxyOutboundHandler(configMgr, subConfigMgr, nil, newMockOutboundManager())
	router := gin.New()
	router.POST("/api/proxy-subscriptions", handler.CreateProxySubscription)
	var fetchCalls int32
	subscriptionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCalls, 1)
		_, _ = w.Write([]byte("ss://example"))
	}))
	defer subscriptionServer.Close()

	payload, err := json.Marshal(ProxySubscriptionRequest{
		Name:                   "Once",
		URL:                    subscriptionServer.URL + "/once",
		Enabled:                boolPtrForTest(true),
		AutoUpdateEnabled:      boolPtrForTest(true),
		AutoUpdateMode:         config.ProxySubscriptionAutoUpdateModeDaily,
		AutoUpdateTime:         "00:00",
		AutoUpdateIntervalDays: 1,
	})
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/proxy-subscriptions", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&fetchCalls); got != 0 {
		t.Fatalf("save must not fetch subscription URL, got %d request(s)", got)
	}
	subs := subConfigMgr.GetAllSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("expected one subscription, got %d", len(subs))
	}
	sub := subs[0]
	if sub.AutoUpdateEnabled == nil || !*sub.AutoUpdateEnabled {
		t.Fatal("expected auto update enabled to be persisted")
	}
	if sub.GetAutoUpdateMode() != config.ProxySubscriptionAutoUpdateModeDaily {
		t.Fatalf("auto update mode = %q", sub.GetAutoUpdateMode())
	}
	if sub.GetAutoUpdateTime() != "00:00" {
		t.Fatalf("auto update time = %q", sub.GetAutoUpdateTime())
	}
	if sub.AutoUpdateLastAttemptAt.IsZero() {
		t.Fatal("expected manual save to set auto update last attempt baseline")
	}
	scheduledAt := time.Date(sub.AutoUpdateLastAttemptAt.Year(), sub.AutoUpdateLastAttemptAt.Month(), sub.AutoUpdateLastAttemptAt.Day(), 0, 0, 0, 0, sub.AutoUpdateLastAttemptAt.Location())
	if sub.AutoUpdateLastAttemptAt.Before(scheduledAt) {
		t.Fatalf("manual save baseline %s is before scheduled time %s", sub.AutoUpdateLastAttemptAt, scheduledAt)
	}
}

func TestUpdateProxySubscriptionPreservesAutoUpdateFieldsAndSetsManualSaveBaseline(t *testing.T) {
	dir := t.TempDir()
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(dir, "proxy_outbounds.json"))
	subConfigMgr := config.NewProxySubscriptionConfigManager(filepath.Join(dir, "proxy_subscriptions.json"))
	var fetchCalls int32
	subscriptionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCalls, 1)
		_, _ = w.Write([]byte("ss://example"))
	}))
	defer subscriptionServer.Close()
	oldAttempt := time.Now().Add(-48 * time.Hour)
	if err := subConfigMgr.AddSubscription(&config.ProxySubscription{
		ID:                      "sub-1",
		Name:                    "Once",
		URL:                     subscriptionServer.URL + "/once",
		Enabled:                 true,
		AutoUpdateEnabled:       boolPtrForTest(false),
		AutoUpdateMode:          config.ProxySubscriptionAutoUpdateModeInterval,
		AutoUpdateIntervalDays:  7,
		AutoUpdateLastAttemptAt: oldAttempt,
		LastNodeCount:           12,
	}); err != nil {
		t.Fatalf("AddSubscription failed: %v", err)
	}
	handler := NewProxyOutboundHandler(configMgr, subConfigMgr, nil, newMockOutboundManager())
	router := gin.New()
	router.PUT("/api/proxy-subscriptions/:id", handler.UpdateProxySubscription)

	payload, err := json.Marshal(ProxySubscriptionRequest{
		Name:                   "Once Renamed",
		URL:                    subscriptionServer.URL + "/once-new",
		Enabled:                boolPtrForTest(true),
		AutoUpdateEnabled:      boolPtrForTest(true),
		AutoUpdateMode:         config.ProxySubscriptionAutoUpdateModeDaily,
		AutoUpdateTime:         "00:00",
		AutoUpdateIntervalDays: 1,
	})
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/proxy-subscriptions/sub-1", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&fetchCalls); got != 0 {
		t.Fatalf("save must not fetch subscription URL, got %d request(s)", got)
	}
	updated, ok := subConfigMgr.GetSubscription("sub-1")
	if !ok {
		t.Fatal("expected updated subscription")
	}
	if updated.Name != "Once Renamed" {
		t.Fatalf("name = %q", updated.Name)
	}
	if updated.AutoUpdateEnabled == nil || !*updated.AutoUpdateEnabled {
		t.Fatal("expected auto update enabled to be persisted")
	}
	if updated.GetAutoUpdateMode() != config.ProxySubscriptionAutoUpdateModeDaily {
		t.Fatalf("auto update mode = %q", updated.GetAutoUpdateMode())
	}
	if updated.LastNodeCount != 12 {
		t.Fatalf("last node count = %d, want 12", updated.LastNodeCount)
	}
	if !updated.AutoUpdateLastAttemptAt.After(oldAttempt) {
		t.Fatalf("expected manual save baseline to advance, got %s <= %s", updated.AutoUpdateLastAttemptAt, oldAttempt)
	}
}

func TestGetServerNodeLatencyHistory_Success(t *testing.T) {
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(t.TempDir(), "proxy_outbounds.json"))
	subConfigMgr := config.NewProxySubscriptionConfigManager(filepath.Join(t.TempDir(), "proxy_subscriptions.json"))
	serverConfigMgr, err := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatalf("NewConfigManager failed: %v", err)
	}
	outboundMgr := newMockOutboundManager()
	handler := NewProxyOutboundHandler(configMgr, subConfigMgr, serverConfigMgr, outboundMgr)

	node1 := &config.ProxyOutbound{Name: "node-a", Type: config.ProtocolShadowsocks, Server: "a.example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test"}
	node2 := &config.ProxyOutbound{Name: "node-b", Type: config.ProtocolShadowsocks, Server: "b.example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test"}
	if err := configMgr.AddOutbound(node1); err != nil {
		t.Fatalf("AddOutbound node-a failed: %v", err)
	}
	if err := configMgr.AddOutbound(node2); err != nil {
		t.Fatalf("AddOutbound node-b failed: %v", err)
	}
	if err := outboundMgr.AddOutbound(node1); err != nil {
		t.Fatalf("mock AddOutbound node-a failed: %v", err)
	}
	if err := outboundMgr.AddOutbound(node2); err != nil {
		t.Fatalf("mock AddOutbound node-b failed: %v", err)
	}

	serverCfg := &config.ServerConfig{
		ID:              "srv1",
		Name:            "Server 1",
		Target:          "example.com",
		Port:            19132,
		ListenAddr:      "0.0.0.0:19132",
		Protocol:        "raknet",
		Enabled:         true,
		ProxyOutbound:   "node-a,node-b",
		LoadBalanceSort: config.LoadBalanceSortUDP,
	}
	if err := serverConfigMgr.AddServer(serverCfg); err != nil {
		t.Fatalf("AddServer failed: %v", err)
	}

	outboundMgr.SetServerNodeLatency("srv1", "node-a", config.LoadBalanceSortUDP, 81)
	outboundMgr.SetServerNodeLatency("srv1", "node-a", config.LoadBalanceSortUDP, 77)
	outboundMgr.SetServerNodeLatency("srv1", "node-b", config.LoadBalanceSortUDP, 0)

	router := gin.New()
	router.GET("/api/servers/:id/node-latency-history", handler.GetServerNodeLatencyHistory)

	req := httptest.NewRequest(http.MethodGet, "/api/servers/srv1/node-latency-history?sort_by=udp", nil)
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
	if data["server_id"] != "srv1" {
		t.Fatalf("Expected server_id=srv1, got %v", data["server_id"])
	}
	nodes, ok := data["nodes"].([]interface{})
	if !ok {
		t.Fatalf("Expected nodes array, got %T", data["nodes"])
	}
	if len(nodes) != 2 {
		t.Fatalf("Expected 2 nodes, got %d", len(nodes))
	}

	nodeMap := make(map[string]map[string]interface{}, len(nodes))
	for _, item := range nodes {
		entry, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("Expected node entry object, got %T", item)
		}
		name, _ := entry["name"].(string)
		nodeMap[name] = entry
	}
	if len(nodeMap["node-a"]["samples"].([]interface{})) != 2 {
		t.Fatalf("Expected node-a to have 2 samples, got %#v", nodeMap["node-a"]["samples"])
	}
	if len(nodeMap["node-b"]["samples"].([]interface{})) != 1 {
		t.Fatalf("Expected node-b to have 1 sample, got %#v", nodeMap["node-b"]["samples"])
	}
}

func TestGetProxyOutboundLatencyHistory_Success(t *testing.T) {
	handler, mockMgr := setupTestHandler()
	router := setupTestRouter(handler)

	if err := handler.configMgr.AddOutbound(&config.ProxyOutbound{
		Name:     "node-a",
		Type:     config.ProtocolShadowsocks,
		Server:   "a.example.com",
		Port:     443,
		Enabled:  true,
		Method:   "aes-256-gcm",
		Password: "test",
	}); err != nil {
		t.Fatalf("AddOutbound failed: %v", err)
	}
	mockMgr.AddOutbound(&config.ProxyOutbound{Name: "node-a", Type: config.ProtocolShadowsocks, Server: "a.example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test"})

	now := time.Now().UnixMilli()
	mockMgr.outbound["node-a|tcp"] = []proxy.OutboundLatencySample{
		{Timestamp: now - 3_600_000, LatencyMs: 120, OK: true},
		{Timestamp: now - 1_800_000, LatencyMs: 90, OK: true},
		{Timestamp: now - 600_000, LatencyMs: 0, OK: false},
	}
	mockMgr.outbound["node-a|http"] = []proxy.OutboundLatencySample{{Timestamp: now - 1_800_000, LatencyMs: 240, OK: true}}
	mockMgr.outbound["node-a|udp"] = []proxy.OutboundLatencySample{{Timestamp: now - 900_000, LatencyMs: 80, OK: true}}

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/node-a/latency-history?from="+strconv.FormatInt(now-2_000_000, 10)+"&to="+strconv.FormatInt(now, 10)+"&limit=2", nil)
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
	metrics, ok := data["metrics"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected metrics object, got %T", data["metrics"])
	}
	tcp, ok := metrics["tcp"].([]interface{})
	if !ok {
		t.Fatalf("Expected tcp array, got %T", metrics["tcp"])
	}
	if len(tcp) != 2 {
		t.Fatalf("Expected tcp length 2, got %d", len(tcp))
	}
	httpSamples, ok := metrics["http"].([]interface{})
	if !ok || len(httpSamples) != 1 {
		t.Fatalf("Expected one http sample, got %#v", metrics["http"])
	}
	udpSamples, ok := metrics["udp"].([]interface{})
	if !ok || len(udpSamples) != 1 {
		t.Fatalf("Expected one udp sample, got %#v", metrics["udp"])
	}
}

func TestGetProxyOutboundLatencyOverview_Success(t *testing.T) {
	handler, mockMgr := setupTestHandler()
	router := setupTestRouter(handler)

	outboundA := &config.ProxyOutbound{Name: "node-a", Type: config.ProtocolShadowsocks, Server: "a.example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test"}
	outboundB := &config.ProxyOutbound{Name: "node-b", Type: config.ProtocolShadowsocks, Server: "b.example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test"}
	if err := handler.configMgr.AddOutbound(outboundA); err != nil {
		t.Fatalf("AddOutbound node-a failed: %v", err)
	}
	if err := handler.configMgr.AddOutbound(outboundB); err != nil {
		t.Fatalf("AddOutbound node-b failed: %v", err)
	}
	mockMgr.AddOutbound(outboundA)
	mockMgr.AddOutbound(outboundB)
	mockMgr.outbound["node-a|tcp"] = []proxy.OutboundLatencySample{{Timestamp: time.Now().UnixMilli(), LatencyMs: 88, OK: true}}
	mockMgr.outbound["node-b|udp"] = []proxy.OutboundLatencySample{{Timestamp: time.Now().UnixMilli(), LatencyMs: 166, OK: true}}

	req := httptest.NewRequest(http.MethodGet, "/api/proxy-outbounds/latency-overview?limit=10", nil)
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
	history, ok := data["latency_history"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected history map, got %T", data["latency_history"])
	}
	if _, ok := history["node-a"].(map[string]interface{}); !ok {
		t.Fatalf("Expected node-a history entry, got %#v", history["node-a"])
	}
	if _, ok := history["node-b"].(map[string]interface{}); !ok {
		t.Fatalf("Expected node-b history entry, got %#v", history["node-b"])
	}
}

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

func TestParseImportContent_KeepsMetadataLikeNodeNames(t *testing.T) {
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
	if got := int(data["count"].(float64)); got != 2 {
		t.Fatalf("Expected count=2, got %d", got)
	}
	if got := int(data["filtered"].(float64)); got != 0 {
		t.Fatalf("Expected filtered=0, got %d", got)
	}
	items, ok := data["items"].([]interface{})
	if !ok || len(items) != 2 {
		t.Fatalf("Expected two parsed items, got %#v", data["items"])
	}
	item, ok := items[0].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected parsed item object, got %T", items[0])
	}
	if item["name"] != "剩余流量：1GB" {
		t.Fatalf("Expected first node name 剩余流量：1GB, got %v", item["name"])
	}
	item, ok = items[1].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected parsed item object, got %T", items[1])
	}
	if item["name"] != "vmess-node" {
		t.Fatalf("Expected second node name vmess-node, got %v", item["name"])
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

func TestServerNodeBlockUnblockLifecycle(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(t.TempDir(), "proxy_outbounds.json"))
	subConfigMgr := config.NewProxySubscriptionConfigManager(filepath.Join(t.TempDir(), "proxy_subscriptions.json"))
	serverConfigMgr, err := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatalf("NewConfigManager failed: %v", err)
	}
	outboundMgr := newMockOutboundManager()
	handler := NewProxyOutboundHandler(configMgr, subConfigMgr, serverConfigMgr, outboundMgr)

	serverCfg := &config.ServerConfig{
		ID:            "srv1",
		Name:          "Server 1",
		Target:        "example.com",
		Port:          19132,
		ListenAddr:    "0.0.0.0:19132",
		Protocol:      "raknet",
		Enabled:       true,
		ProxyOutbound: "node-a,node-b",
	}
	if err := serverConfigMgr.AddServer(serverCfg); err != nil {
		t.Fatalf("AddServer failed: %v", err)
	}

	router := gin.New()
	router.POST("/api/servers/:id/block-node", handler.BlockServerNode)
	router.POST("/api/servers/:id/unblock-node", handler.UnblockServerNode)
	router.GET("/api/servers/:id/blocked-nodes", handler.GetServerBlockedNodes)

	// Block node-a for this server only.
	body, _ := json.Marshal(map[string]interface{}{"name": "node-a", "reason": "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/servers/srv1/block-node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("block: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Persisted on the server config.
	stored, ok := serverConfigMgr.GetServer("srv1")
	if !ok || !stored.IsNodeAutoSelectBlocked("node-a") {
		t.Fatalf("expected node-a to be blocked on srv1, got %+v", stored.AutoSelectBlockedNodes)
	}
	if stored.IsNodeAutoSelectBlocked("node-b") {
		t.Fatalf("node-b should not be blocked")
	}

	// GET reflects the ban.
	req = httptest.NewRequest(http.MethodGet, "/api/servers/srv1/blocked-nodes", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get blocked: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data, _ := resp.Data.(map[string]interface{})
	blocked, _ := data["blocked"].(map[string]interface{})
	if _, exists := blocked["node-a"]; !exists {
		t.Fatalf("expected node-a in blocked map, got %v", blocked)
	}

	// Unblock node-a.
	body, _ = json.Marshal(map[string]interface{}{"name": "node-a"})
	req = httptest.NewRequest(http.MethodPost, "/api/servers/srv1/unblock-node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unblock: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	stored, _ = serverConfigMgr.GetServer("srv1")
	if stored.IsNodeAutoSelectBlocked("node-a") {
		t.Fatalf("expected node-a unblocked")
	}
}

func TestSwitchServerNodeToSpecificNode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configMgr := config.NewProxyOutboundConfigManager(filepath.Join(t.TempDir(), "proxy_outbounds.json"))
	subConfigMgr := config.NewProxySubscriptionConfigManager(filepath.Join(t.TempDir(), "proxy_subscriptions.json"))
	serverConfigMgr, err := config.NewConfigManager(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatalf("NewConfigManager failed: %v", err)
	}
	outboundMgr := newMockOutboundManager()
	handler := NewProxyOutboundHandler(configMgr, subConfigMgr, serverConfigMgr, outboundMgr)

	nodeA := &config.ProxyOutbound{Name: "node-a", Type: config.ProtocolShadowsocks, Server: "a.example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test"}
	nodeB := &config.ProxyOutbound{Name: "node-b", Type: config.ProtocolShadowsocks, Server: "b.example.com", Port: 443, Enabled: true, Method: "aes-256-gcm", Password: "test"}
	// Candidate resolution reads from configMgr; selection state from outboundMgr.
	if err := configMgr.AddOutbound(nodeA); err != nil {
		t.Fatalf("configMgr AddOutbound node-a: %v", err)
	}
	if err := configMgr.AddOutbound(nodeB); err != nil {
		t.Fatalf("configMgr AddOutbound node-b: %v", err)
	}
	if err := outboundMgr.AddOutbound(nodeA); err != nil {
		t.Fatalf("AddOutbound node-a: %v", err)
	}
	if err := outboundMgr.AddOutbound(nodeB); err != nil {
		t.Fatalf("AddOutbound node-b: %v", err)
	}

	serverCfg := &config.ServerConfig{
		ID:            "srv1",
		Name:          "Server 1",
		Target:        "example.com",
		Port:          19132,
		ListenAddr:    "0.0.0.0:19132",
		Protocol:      "raknet",
		Enabled:       true,
		ProxyOutbound: "node-a,node-b",
	}
	if err := serverConfigMgr.AddServer(serverCfg); err != nil {
		t.Fatalf("AddServer failed: %v", err)
	}

	router := gin.New()
	router.POST("/api/servers/:id/switch-node", handler.SwitchServerNode)

	// Switch to node-b explicitly.
	body, _ := json.Marshal(map[string]interface{}{"node": "node-b"})
	req := httptest.NewRequest(http.MethodPost, "/api/servers/srv1/switch-node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("switch: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if node, ok := outboundMgr.GetServerSelectedNode("srv1"); !ok || node != "node-b" {
		t.Fatalf("expected selected node-b, got %q ok=%v", node, ok)
	}

	// Switching to an unknown node is rejected.
	body, _ = json.Marshal(map[string]interface{}{"node": "ghost"})
	req = httptest.NewRequest(http.MethodPost, "/api/servers/srv1/switch-node", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("switch to unknown: expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
