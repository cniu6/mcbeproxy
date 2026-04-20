package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/config"
)

type ServerLatencyHistorySample struct {
	Timestamp int64  `json:"timestamp"`
	LatencyMs int64  `json:"latency_ms"`
	Online    bool   `json:"online"`
	Stopped   bool   `json:"stopped,omitempty"`
	Source    string `json:"source,omitempty"`
}

type serverLatencyHistoryStore struct {
	config *config.GlobalConfig
	mu     sync.RWMutex
	series map[string][]ServerLatencyHistorySample
}

func newServerLatencyHistoryStore(globalConfig *config.GlobalConfig) *serverLatencyHistoryStore {
	return &serverLatencyHistoryStore{
		config: globalConfig,
		series: make(map[string][]ServerLatencyHistorySample),
	}
}

func (s *serverLatencyHistoryStore) retentionDuration() time.Duration {
	if s == nil || s.config == nil {
		return 5 * 24 * time.Hour
	}
	return time.Duration(s.config.GetLatencyHistoryRetentionDays()) * 24 * time.Hour
}

func (s *serverLatencyHistoryStore) storageLimit() int {
	if s == nil || s.config == nil {
		return 1000
	}
	return s.config.GetLatencyHistoryStorageLimit()
}

func (s *serverLatencyHistoryStore) defaultSnapshotLimit() int {
	if s == nil || s.config == nil {
		return 100
	}
	return s.config.GetLatencyHistoryRenderLimit()
}

func (s *serverLatencyHistoryStore) maxResponseLimit() int {
	if s == nil || s.config == nil {
		return 1000
	}
	return s.config.GetLatencyHistoryStorageLimit()
}

func (s *serverLatencyHistoryStore) minIntervalMs() int64 {
	if s == nil || s.config == nil {
		return int64((10 * time.Minute) / time.Millisecond)
	}
	return int64(time.Duration(s.config.GetLatencyHistoryMinIntervalMinutes()) * time.Minute / time.Millisecond)
}

func (s *serverLatencyHistoryStore) Delete(serverID string) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return
	}
	s.mu.Lock()
	delete(s.series, serverID)
	s.mu.Unlock()
}

func coalesceLatencyHistoryMinIntervalMs(defaultMinGapMs, overrideMs int64) int64 {
	if overrideMs <= 0 {
		return defaultMinGapMs
	}
	if defaultMinGapMs <= 0 || overrideMs < defaultMinGapMs {
		return overrideMs
	}
	return defaultMinGapMs
}

func (s *serverLatencyHistoryStore) Record(serverID string, sample ServerLatencyHistorySample, minIntervalOverrideMs int64) {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return
	}
	if sample.Timestamp <= 0 {
		sample.Timestamp = time.Now().UnixMilli()
	}
	if sample.LatencyMs < 0 {
		sample.LatencyMs = 0
	}
	cutoff := time.UnixMilli(sample.Timestamp).Add(-s.retentionDuration()).UnixMilli()
	minGap := coalesceLatencyHistoryMinIntervalMs(s.minIntervalMs(), minIntervalOverrideMs)

	s.mu.Lock()
	defer s.mu.Unlock()

	series := s.trimExpiredLocked(serverID, cutoff)
	if len(series) == 0 {
		s.series[serverID] = []ServerLatencyHistorySample{sample}
		return
	}

	lastIndex := len(series) - 1
	last := series[lastIndex]
	if sample.Timestamp-last.Timestamp < minGap {
		series[lastIndex] = sample
	} else {
		series = append(series, sample)
	}
	storageLimit := s.storageLimit()
	if storageLimit > 0 && len(series) > storageLimit {
		series = series[len(series)-storageLimit:]
	}
	s.series[serverID] = series
}

func (s *serverLatencyHistoryStore) Snapshot(serverIDs []string, limit int) map[string][]ServerLatencyHistorySample {
	limit = clampHistoryLimit(limit, s.defaultSnapshotLimit(), s.maxResponseLimit())
	cutoff := time.Now().Add(-s.retentionDuration()).UnixMilli()

	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string][]ServerLatencyHistorySample, len(serverIDs))
	for _, serverID := range serverIDs {
		serverID = strings.TrimSpace(serverID)
		if serverID == "" {
			continue
		}
		series := s.trimExpiredLocked(serverID, cutoff)
		if len(series) > limit {
			series = series[len(series)-limit:]
		}
		copied := make([]ServerLatencyHistorySample, len(series))
		copy(copied, series)
		result[serverID] = copied
	}
	return result
}

func (s *serverLatencyHistoryStore) History(serverID string) []ServerLatencyHistorySample {
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return []ServerLatencyHistorySample{}
	}
	cutoff := time.Now().Add(-s.retentionDuration()).UnixMilli()

	s.mu.Lock()
	defer s.mu.Unlock()

	series := s.trimExpiredLocked(serverID, cutoff)
	if len(series) == 0 {
		return []ServerLatencyHistorySample{}
	}
	copied := make([]ServerLatencyHistorySample, len(series))
	copy(copied, series)
	return copied
}

func (s *serverLatencyHistoryStore) trimExpiredLocked(serverID string, cutoff int64) []ServerLatencyHistorySample {
	series := s.series[serverID]
	if len(series) == 0 {
		return nil
	}
	start := 0
	for start < len(series) && series[start].Timestamp < cutoff {
		start++
	}
	if start >= len(series) {
		delete(s.series, serverID)
		return nil
	}
	if start > 0 {
		trimmed := append([]ServerLatencyHistorySample(nil), series[start:]...)
		s.series[serverID] = trimmed
		return trimmed
	}
	return series
}

func clampHistoryLimit(value, defaultLimit, maxLimit int) int {
	if defaultLimit <= 0 {
		defaultLimit = 100
	}
	if maxLimit <= 0 {
		maxLimit = defaultLimit
	}
	if value <= 0 {
		value = defaultLimit
	}
	if value > maxLimit {
		value = maxLimit
	}
	return value
}

func parseHistoryLimit(raw string, defaultLimit, maxLimit int) int {
	if raw == "" {
		return clampHistoryLimit(0, defaultLimit, maxLimit)
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return clampHistoryLimit(0, defaultLimit, maxLimit)
	}
	return clampHistoryLimit(value, defaultLimit, maxLimit)
}

func (a *APIServer) defaultLatencyHistoryRenderLimit() int {
	if a == nil || a.globalConfig == nil {
		return 100
	}
	return a.globalConfig.GetLatencyHistoryRenderLimit()
}

func (a *APIServer) maxLatencyHistoryResponseLimit() int {
	if a == nil || a.globalConfig == nil {
		return 1000
	}
	return a.globalConfig.GetLatencyHistoryStorageLimit()
}

func (a *APIServer) getServerLatencyOverview(c *gin.Context) {
	if a.proxyController == nil {
		respondError(c, http.StatusInternalServerError, "Proxy controller not initialized", "")
		return
	}
	servers := a.proxyController.GetAllServerStatuses()
	limit := parseHistoryLimit(c.Query("history_limit"), a.defaultLatencyHistoryRenderLimit(), a.maxLatencyHistoryResponseLimit())
	respondSuccess(c, a.buildServerLatencyOverview(servers, limit))
}

func (a *APIServer) buildServerLatencyOverview(servers []config.ServerConfigDTO, historyLimit int) map[string]interface{} {
	pings := a.collectServerPings(servers)
	serverIDs := make([]string, 0, len(servers))
	for _, server := range servers {
		serverIDs = append(serverIDs, server.ID)
	}
	return map[string]interface{}{
		"servers":         servers,
		"pings":           pings,
		"latency_history": a.buildServerLatencyHistorySnapshot(serverIDs, historyLimit),
		"generated_at":    time.Now(),
	}
}

func (a *APIServer) collectServerPings(servers []config.ServerConfigDTO) map[string]map[string]interface{} {
	if len(servers) == 0 {
		return map[string]map[string]interface{}{}
	}
	type pingResult struct {
		id   string
		info map[string]interface{}
	}
	results := make(chan pingResult, len(servers))
	var pingWG sync.WaitGroup
	for _, srv := range servers {
		server := srv
		pingWG.Add(1)
		go func() {
			defer pingWG.Done()
			results <- pingResult{id: server.ID, info: a.buildServerPingFromConfig(server)}
		}()
	}
	go func() {
		pingWG.Wait()
		close(results)
	}()

	pings := make(map[string]map[string]interface{}, len(servers))
	for result := range results {
		pings[result.id] = result.info
	}
	return pings
}

func (a *APIServer) buildServerLatencyHistorySnapshot(serverIDs []string, limit int) map[string][]ServerLatencyHistorySample {
	if a == nil || a.serverLatencyHistory == nil {
		result := make(map[string][]ServerLatencyHistorySample, len(serverIDs))
		for _, serverID := range serverIDs {
			serverID = strings.TrimSpace(serverID)
			if serverID == "" {
				continue
			}
			result[serverID] = []ServerLatencyHistorySample{}
		}
		return result
	}
	return a.serverLatencyHistory.Snapshot(serverIDs, limit)
}

func (a *APIServer) latencyHistoryMinIntervalOverrideMs(serverID string, source string) int64 {
	if a == nil || a.configMgr == nil {
		return 0
	}
	if !strings.EqualFold(strings.TrimSpace(source), "auto_ping") {
		return 0
	}
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return 0
	}
	serverCfg, ok := a.configMgr.GetServer(serverID)
	if !ok || serverCfg == nil || !serverCfg.AutoPingEnabled {
		return 0
	}
	intervalMinutes := serverCfg.AutoPingIntervalMinutes
	if intervalMinutes <= 0 && a.globalConfig != nil {
		intervalMinutes = a.globalConfig.GetServerAutoPingIntervalMinutesDefault()
	}
	if intervalMinutes <= 0 {
		return 0
	}
	return int64(time.Duration(intervalMinutes) * time.Minute / time.Millisecond)
}

func (a *APIServer) RecordServerLatency(serverID string, timestampMs int64, latencyMs int64, online bool, stopped bool, source string) {
	if a == nil || a.serverLatencyHistory == nil {
		return
	}
	serverID = strings.TrimSpace(serverID)
	if serverID == "" {
		return
	}
	a.serverLatencyHistory.Record(serverID, ServerLatencyHistorySample{
		Timestamp: timestampMs,
		LatencyMs: latencyMs,
		Online:    online,
		Stopped:   stopped,
		Source:    strings.TrimSpace(source),
	}, a.latencyHistoryMinIntervalOverrideMs(serverID, source))
}

func (a *APIServer) recordServerLatencyInfo(info map[string]interface{}) map[string]interface{} {
	return info
}

func boolValue(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case *bool:
		return v != nil && *v
	default:
		return false
	}
}

func stringValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case *string:
		if v == nil {
			return ""
		}
		return *v
	default:
		return ""
	}
}

func int64Value(value interface{}) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		return int64(v), true
	case uint8:
		return int64(v), true
	case uint16:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint64:
		if v > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(v), true
	case float32:
		return int64(v), true
	case float64:
		return int64(v), true
	default:
		return 0, false
	}
}
