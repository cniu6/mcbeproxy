package api

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/session"
)

// webIndexCache provides smart caching for the public status API.
// - Serves cached data if < 2s old (anti-CC)
// - Stops refreshing if no request for 10s (silent mode)
// - Only fetches fresh data when someone actually requests
type webIndexCache struct {
	mu          sync.Mutex
	data        []byte    // cached JSON response
	updatedAt   time.Time // when cache was last refreshed
	requestedAt time.Time // when last request came in
}

var wiCache = &webIndexCache{}

// getWebIndexAPI returns a consolidated public status snapshot without authentication.
// GET /api/web/index-api
func (a *APIServer) getWebIndexAPI(c *gin.Context) {
	// Parse history pagination params
	historyLimit := 10
	historyPage := 1
	if v := c.Query("history_limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			allowed := map[int]bool{10: true, 20: true, 100: true, 200: true, 500: true, 1000: true}
			if allowed[n] {
				historyLimit = n
			}
		}
	}
	if v := c.Query("history_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			historyPage = n
		}
	}

	reqCtx, reqCancel := a.requestContext(c)
	defer reqCancel()

	wiCache.mu.Lock()
	now := time.Now()
	wiCache.requestedAt = now
	var baseData []byte
	// Serve cached if fresh enough (< 2s)
	if wiCache.data != nil && now.Sub(wiCache.updatedAt) < 2*time.Second {
		baseData = wiCache.data
		wiCache.mu.Unlock()
	} else {
		wiCache.mu.Unlock()
		// Build fresh base response (without history)
		baseData = a.buildWebIndexResponse(reqCtx)
		wiCache.mu.Lock()
		wiCache.data = baseData
		wiCache.updatedAt = time.Now()
		wiCache.mu.Unlock()
	}

	// Fetch history with pagination (always fresh per request)
	var response map[string]interface{}
	json.Unmarshal(baseData, &response)

	historyDTOs, historyTotal := a.fetchSessionHistory(historyLimit, historyPage)
	response["session_history"] = historyDTOs
	response["history_total"] = historyTotal
	response["history_page"] = historyPage
	response["history_limit"] = historyLimit

	final, _ := json.Marshal(response)
	c.Data(http.StatusOK, "application/json; charset=utf-8", final)
}

func (a *APIServer) buildWebIndexResponse(ctx context.Context) []byte {
	var (
		sysStats *monitor.SystemStats
		statsErr error
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if a.monitor == nil {
			return
		}
		sysStats, statsErr = a.monitor.GetSystemStats()
	}()

	servers := a.proxyController.GetAllServerStatuses()

	// Build active sessions snapshot (filtered - no UUID/XUID)
	sessions := a.sessionMgr.GetAllSessions()
	type publicSessionDTO struct {
		ServerID    string `json:"server_id"`
		DisplayName string `json:"display_name"`
		ClientAddr  string `json:"client_addr"`
		BytesUp     int64  `json:"bytes_up"`
		BytesDown   int64  `json:"bytes_down"`
		Duration    int64  `json:"duration_seconds"`
	}
	sessionDTOs := make([]publicSessionDTO, 0, len(sessions))
	for _, sess := range sessions {
		dto := sess.ToDTO()
		sessionDTOs = append(sessionDTOs, publicSessionDTO{
			ServerID:    dto.ServerID,
			DisplayName: dto.DisplayName,
			ClientAddr:  dto.ClientAddr,
			BytesUp:     dto.BytesUp,
			BytesDown:   dto.BytesDown,
			Duration:    dto.Duration,
		})
	}

	// Fetch pings concurrently
	pings := a.collectServerPings(ctx, servers, shouldExposeServerLatencyOverview)

	wg.Wait()

	// Build filtered server list (no IP/port/sensitive fields, no "来源")
	type publicServerDTO struct {
		ID              string `json:"id"`
		Status          string `json:"status"`
		Latency         int64  `json:"latency"`
		Online          bool   `json:"online"`
		ServerName      string `json:"server_name"`
		Stopped         bool   `json:"stopped"`
		AutoPingEnabled bool   `json:"auto_ping_enabled"`
		NextAutoPingAt  int64  `json:"next_auto_ping_at"`
	}
	onlineCount := 0
	totalCount := 0
	publicServers := make([]publicServerDTO, 0, len(servers))
	serverIDs := make([]string, 0, len(servers))
	for _, srv := range servers {
		// Hidden servers are excluded from the public status page entirely
		// (list, total/online counts, and latency overview).
		if srv.Hidden {
			continue
		}
		totalCount++
		if shouldExposeServerLatencyOverview(srv) {
			serverIDs = append(serverIDs, srv.ID)
		}
		ping := pings[srv.ID]
		latency := int64(-1)
		online := false
		stopped := false
		serverName := ""

		if ping != nil {
			if v, ok := ping["latency"]; ok {
				if l, ok := v.(int64); ok {
					latency = l
				}
			}
			if v, ok := ping["online"]; ok {
				if b, ok := v.(bool); ok {
					online = b
				}
			}
			if v, ok := ping["stopped"]; ok {
				if b, ok := v.(bool); ok {
					stopped = b
				}
			}
			if parsed, ok := ping["parsed_motd"]; ok && parsed != nil {
				if pm, ok := parsed.(*ParsedMOTD); ok && pm != nil {
					serverName = pm.ServerName
				}
			}
			if serverName == "" {
				if motd, ok := ping["motd"]; ok {
					if m, ok := motd.(string); ok && m != "" {
						pm := parseMOTD(m)
						if pm != nil {
							serverName = pm.ServerName
						}
					}
				}
			}
		}

		if online {
			onlineCount++
		}

		publicServers = append(publicServers, publicServerDTO{
			ID:              srv.ID,
			Status:          srv.Status,
			Latency:         latency,
			Online:          online,
			ServerName:      serverName,
			Stopped:         stopped,
			AutoPingEnabled: srv.AutoPingEnabled,
			NextAutoPingAt:  srv.NextAutoPingAt,
		})
	}

	// Build public system stats
	type publicNetworkStats struct {
		BytesSent   uint64  `json:"bytes_sent"`
		BytesRecv   uint64  `json:"bytes_recv"`
		SpeedIn     float64 `json:"speed_in_bps"`
		SpeedOut    float64 `json:"speed_out_bps"`
		PacketsSent uint64  `json:"packets_sent"`
		PacketsRecv uint64  `json:"packets_recv"`
	}
	type publicSystemStats struct {
		CPU struct {
			UsagePercent float64 `json:"usage_percent"`
			CoreCount    int     `json:"core_count"`
		} `json:"cpu"`
		Memory struct {
			UsedPercent float64 `json:"used_percent"`
			Used        uint64  `json:"used"`
			Total       uint64  `json:"total"`
			Available   uint64  `json:"available"`
			SwapUsed    uint64  `json:"swap_used"`
			SwapTotal   uint64  `json:"swap_total"`
			SwapPercent float64 `json:"swap_percent"`
		} `json:"memory"`
		Disk struct {
			UsedPercent float64 `json:"used_percent"`
			Used        uint64  `json:"used"`
			Total       uint64  `json:"total"`
			Free        uint64  `json:"free"`
		} `json:"disk"`
		DiskIO  monitor.DiskIOStats `json:"disk_io"`
		Network publicNetworkStats  `json:"network"`
		Process struct {
			PID         int32   `json:"pid"`
			MemoryBytes uint64  `json:"memory_bytes"`
			CPUPercent  float64 `json:"cpu_percent"`
		} `json:"process"`
		GoRuntime struct {
			GoroutineCount int    `json:"goroutine_count"`
			HeapAlloc      uint64 `json:"heap_alloc"`
			HeapSys        uint64 `json:"heap_sys"`
			HeapInuse      uint64 `json:"heap_inuse"`
			StackInuse     uint64 `json:"stack_inuse"`
			NumGC          uint32 `json:"num_gc"`

			HeapObjects    uint64  `json:"heap_objects"`
			NextGC         uint64  `json:"next_gc"`
			TotalSys       uint64  `json:"total_sys"`
			GCPauseTotalNs uint64  `json:"gc_pause_total_ns"`
			LastGCPauseNs  uint64  `json:"last_gc_pause_ns"`
			LastGCUnixMs   int64   `json:"last_gc_unix_ms"`
			GCCPUFraction  float64 `json:"gc_cpu_fraction"`
		} `json:"go_runtime"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		StartTime     string `json:"start_time"`
	}

	var pubStats publicSystemStats
	if sysStats != nil {
		pubStats.CPU.UsagePercent = sysStats.CPU.UsagePercent
		pubStats.CPU.CoreCount = sysStats.CPU.CoreCount
		pubStats.Memory.UsedPercent = sysStats.Memory.UsedPercent
		pubStats.Memory.Used = sysStats.Memory.Used
		pubStats.Memory.Total = sysStats.Memory.Total
		pubStats.Memory.Available = sysStats.Memory.Available
		pubStats.Memory.SwapUsed = sysStats.Memory.SwapUsed
		pubStats.Memory.SwapTotal = sysStats.Memory.SwapTotal
		pubStats.Memory.SwapPercent = sysStats.Memory.SwapPercent
		for _, d := range sysStats.Disk {
			pubStats.Disk.Used += d.Used
			pubStats.Disk.Total += d.Total
			pubStats.Disk.Free += d.Free
		}
		pubStats.DiskIO = sysStats.DiskIO
		if pubStats.Disk.Total > 0 {
			pubStats.Disk.UsedPercent = float64(pubStats.Disk.Used) / float64(pubStats.Disk.Total) * 100
		}
		pubStats.Network.BytesSent = sysStats.NetworkTotal.BytesSent
		pubStats.Network.BytesRecv = sysStats.NetworkTotal.BytesRecv
		pubStats.Network.SpeedIn = sysStats.NetworkTotal.SpeedIn
		pubStats.Network.SpeedOut = sysStats.NetworkTotal.SpeedOut
		pubStats.Network.PacketsSent = sysStats.NetworkTotal.PacketsSent
		pubStats.Network.PacketsRecv = sysStats.NetworkTotal.PacketsRecv
		pubStats.Process.PID = sysStats.Process.PID
		pubStats.Process.MemoryBytes = sysStats.Process.MemoryBytes
		pubStats.Process.CPUPercent = sysStats.Process.CPUPercent
		pubStats.GoRuntime.GoroutineCount = sysStats.GoRuntime.GoroutineCount
		pubStats.GoRuntime.HeapAlloc = sysStats.GoRuntime.HeapAlloc
		pubStats.GoRuntime.HeapSys = sysStats.GoRuntime.HeapSys
		pubStats.GoRuntime.HeapInuse = sysStats.GoRuntime.HeapInuse
		pubStats.GoRuntime.StackInuse = sysStats.GoRuntime.StackInuse
		pubStats.GoRuntime.NumGC = sysStats.GoRuntime.NumGC
		pubStats.GoRuntime.HeapObjects = sysStats.GoRuntime.HeapObjects
		pubStats.GoRuntime.NextGC = sysStats.GoRuntime.NextGC
		pubStats.GoRuntime.TotalSys = sysStats.GoRuntime.TotalSys
		pubStats.GoRuntime.GCPauseTotalNs = sysStats.GoRuntime.GCPauseTotalNs
		pubStats.GoRuntime.LastGCPauseNs = sysStats.GoRuntime.LastGCPauseNs
		pubStats.GoRuntime.LastGCUnixMs = sysStats.GoRuntime.LastGCUnixMs
		pubStats.GoRuntime.GCCPUFraction = sysStats.GoRuntime.GCCPUFraction
		pubStats.UptimeSeconds = sysStats.Uptime
		pubStats.StartTime = sysStats.StartTime
	} else {
		pubStats.GoRuntime.GoroutineCount = runtime.NumGoroutine()
	}

	response := map[string]interface{}{
		"system_stats":    pubStats,
		"servers":         publicServers,
		"online_servers":  onlineCount,
		"total_servers":   totalCount,
		"latency_history": a.buildServerLatencyHistorySnapshot(serverIDs, a.defaultLatencyHistoryRenderLimit()),
		"active_sessions": sessionDTOs,
		"session_count":   len(sessionDTOs),
		"generated_at":    time.Now(),
	}
	if statsErr != nil {
		response["stats_error"] = statsErr.Error()
	}

	data, _ := json.Marshal(response)
	return data
}

// fetchSessionHistory returns paginated session history and total count.
func (a *APIServer) fetchSessionHistory(limit, page int) ([]map[string]interface{}, int) {
	if a.sessionRepo == nil {
		return nil, 0
	}
	total, err := a.sessionRepo.Count()
	if err != nil {
		return nil, 0
	}
	offset := (page - 1) * limit
	if offset >= total {
		return []map[string]interface{}{}, total
	}
	records, err := a.sessionRepo.List(limit, offset)
	if err != nil {
		return nil, 0
	}
	dtos := make([]map[string]interface{}, 0, len(records))
	for _, r := range records {
		dtos = append(dtos, map[string]interface{}{
			"display_name":  r.DisplayName,
			"server_id":     r.ServerID,
			"client_addr":   r.ClientAddr,
			"start_time":    r.StartTime,
			"end_time":      r.EndTime,
			"bytes_up":      r.BytesUp,
			"bytes_down":    r.BytesDown,
			"status":        r.Status,
			"status_reason": r.StatusReason,
		})
	}
	return dtos, total
}

// Suppress unused import warnings
var _ = session.SessionDTO{}

// getWebIndex serves the prebuilt single-file public status page.
// GET /api/web/index
func (a *APIServer) getWebIndex(c *gin.Context) {
	page, err := statusDistFS.ReadFile("status-dist/index.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "status page not built")
		return
	}
	// 页面内已内联 JS/CSS，不引用其它资源；entry 更新后需要重新构建二进制。
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Data(http.StatusOK, "text/html; charset=utf-8", page)
}

func filterWebServerLatencyHistorySamples(samples []ServerLatencyHistorySample, fromMs, toMs int64, limit int) []ServerLatencyHistorySample {
	if len(samples) == 0 {
		return []ServerLatencyHistorySample{}
	}
	if fromMs > 0 && toMs > 0 && fromMs > toMs {
		fromMs, toMs = toMs, fromMs
	}
	filtered := make([]ServerLatencyHistorySample, 0, len(samples))
	for _, sample := range samples {
		if fromMs > 0 && sample.Timestamp < fromMs {
			continue
		}
		if toMs > 0 && sample.Timestamp > toMs {
			continue
		}
		filtered = append(filtered, sample)
	}
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	return filtered
}

func (a *APIServer) getWebServerLatencyHistory(c *gin.Context) {
	if a.proxyController == nil {
		respondError(c, http.StatusInternalServerError, "Proxy controller not initialized", "")
		return
	}
	serverID := strings.TrimSpace(c.Param("id"))
	if serverID == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "id parameter is required")
		return
	}
	servers := a.proxyController.GetAllServerStatuses()
	found := false
	for _, server := range servers {
		if strings.TrimSpace(server.ID) == serverID {
			found = true
			break
		}
	}
	if !found {
		respondError(c, http.StatusNotFound, "Server not found", "No server found with the specified id")
		return
	}
	fromMs, _ := parseOptionalUnixMilli(c.Query("from"))
	toMs, _ := parseOptionalUnixMilli(c.Query("to"))
	limit := parseHistoryLimit(c.Query("limit"), a.defaultLatencyHistoryRenderLimit(), a.maxLatencyHistoryResponseLimit())
	samples := []ServerLatencyHistorySample{}
	if a.serverLatencyHistory != nil {
		samples = filterWebServerLatencyHistorySamples(a.serverLatencyHistory.History(serverID), fromMs, toMs, limit)
	}
	respondSuccess(c, map[string]interface{}{
		"id":      serverID,
		"from":    fromMs,
		"to":      toMs,
		"limit":   limit,
		"samples": samples,
	})
}

func (a *APIServer) getWebProxyOutboundLatencyHistory(c *gin.Context) {
	if a.proxyOutboundHandler == nil || a.proxyOutboundHandler.outboundMgr == nil {
		respondError(c, http.StatusInternalServerError, "Outbound manager not initialized", "")
		return
	}
	if a.proxyOutboundHandler.configMgr == nil {
		respondError(c, http.StatusInternalServerError, "Proxy outbound config manager not initialized", "")
		return
	}
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "name parameter is required")
		return
	}
	outbound, exists := a.proxyOutboundHandler.configMgr.GetOutbound(name)
	if !exists || outbound == nil {
		respondError(c, http.StatusNotFound, "Proxy outbound not found", "No proxy outbound found with the specified name")
		return
	}
	fromMs, _ := parseOptionalUnixMilli(c.Query("from"))
	toMs, _ := parseOptionalUnixMilli(c.Query("to"))
	limit := parseHistoryLimit(c.Query("limit"), a.defaultLatencyHistoryRenderLimit(), a.maxLatencyHistoryResponseLimit())
	respondSuccess(c, map[string]interface{}{
		"name":    name,
		"from":    fromMs,
		"to":      toMs,
		"limit":   limit,
		"metrics": a.proxyOutboundHandler.getProxyOutboundLatencyHistoryMetrics(name, fromMs, toMs, limit),
	})
}

