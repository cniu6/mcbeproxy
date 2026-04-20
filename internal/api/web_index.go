package api

import (
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
		baseData = a.buildWebIndexResponse()
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

func (a *APIServer) buildWebIndexResponse() []byte {
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
	pings := a.collectServerPings(servers)

	wg.Wait()

	// Build filtered server list (no IP/port/sensitive fields, no "来源")
	type publicServerDTO struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		Latency        int64  `json:"latency"`
		Online         bool   `json:"online"`
		ServerName     string `json:"server_name"`
		Stopped        bool   `json:"stopped"`
		AutoPingEnabled bool  `json:"auto_ping_enabled"`
		NextAutoPingAt int64  `json:"next_auto_ping_at"`
	}
	onlineCount := 0
	totalCount := len(servers)
	publicServers := make([]publicServerDTO, 0, len(servers))
	serverIDs := make([]string, 0, len(servers))
	for _, srv := range servers {
		serverIDs = append(serverIDs, srv.ID)
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
		} `json:"memory"`
		Disk struct {
			UsedPercent float64 `json:"used_percent"`
			Used        uint64  `json:"used"`
			Total       uint64  `json:"total"`
		} `json:"disk"`
		Network publicNetworkStats `json:"network"`
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
		for _, d := range sysStats.Disk {
			pubStats.Disk.Used += d.Used
			pubStats.Disk.Total += d.Total
		}
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

// getWebIndex serves the public server status HTML dashboard page.
// GET /api/web/index
func (a *APIServer) getWebIndex(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(webIndexHTML))
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
		"id":     serverID,
		"from":   fromMs,
		"to":     toMs,
		"limit":  limit,
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

const webIndexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Minecraft BE 服务器状态</title>
<style>
:root{--bg:#080c18;--bg2:#0f1526;--card:#131a30;--card-hover:#182040;--border:#1c2848;--border2:#243058;--text:#c8d6e5;--text2:#8a96a8;--text3:#5a6578;--heading:#edf2f7;--accent:#4f8cff;--accent2:#6c5ce7;--green:#00d68f;--red:#ff6b6b;--orange:#ffa94d;--shadow:0 2px 12px rgba(0,0,0,0.3)}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',Roboto,sans-serif;min-height:100vh;padding:24px 16px;line-height:1.5}
.container{max-width:800px;margin:0 auto}

/* Header */
.header{text-align:center;margin-bottom:24px;padding:28px 20px 22px;background:linear-gradient(135deg,rgba(79,140,255,0.08),rgba(108,92,231,0.08));border:1px solid var(--border);border-radius:16px;position:relative;overflow:hidden}
.header::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle at 30% 40%,rgba(79,140,255,0.06),transparent 60%);pointer-events:none}
.header h1{font-size:1.6em;font-weight:700;color:var(--heading);margin-bottom:8px;letter-spacing:-0.02em}
.header h1 .icon{margin-right:8px}
.badge{display:inline-block;padding:4px 18px;border-radius:20px;font-size:0.8em;font-weight:600;letter-spacing:0.3px}
.badge{background:rgba(0,214,143,0.15);color:var(--green);border:1px solid rgba(0,214,143,0.25)}
.badge.error{background:rgba(255,107,107,0.15);color:var(--red);border-color:rgba(255,107,107,0.25)}

/* Toolbar */
.toolbar{display:flex;justify-content:flex-end;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.toolbar .refresh-info{font-size:0.78em;color:var(--text2);display:flex;align-items:center;gap:6px}
.toolbar .refresh-info .dot{width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.toolbar .t{color:var(--text);font-weight:500;font-variant-numeric:tabular-nums}
.btn{background:var(--card);border:1px solid var(--border);color:var(--text);padding:6px 14px;border-radius:10px;cursor:pointer;font-size:0.8em;display:inline-flex;align-items:center;gap:5px;transition:all 0.2s ease;font-weight:500}
.btn:hover{background:var(--card-hover);border-color:var(--border2);transform:translateY(-1px);box-shadow:var(--shadow)}
.btn:active{transform:translateY(0)}
.btn svg{width:15px;height:15px;fill:currentColor;opacity:0.8}

/* Stat cards */
.stat-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:10px}
.stat-grid-extra{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 10px;text-align:center;transition:all 0.25s ease;position:relative;overflow:hidden}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:var(--shadow)}
.stat-card .label{font-size:0.68em;color:var(--text2);text-transform:uppercase;margin-bottom:4px;letter-spacing:0.8px;font-weight:600}
.stat-card .value{font-size:1.35em;font-weight:700;color:var(--heading);font-variant-numeric:tabular-nums}
.stat-card .sub{font-size:0.7em;color:var(--text2);margin-top:3px;font-variant-numeric:tabular-nums}

/* Network bar */
.net-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 18px;margin-bottom:20px;font-size:0.82em;display:flex;flex-wrap:wrap;gap:6px 20px;align-items:center;justify-content:center}
.net-card .ni{color:var(--text2);font-weight:500}.net-card .nv{color:var(--heading);font-weight:600;font-variant-numeric:tabular-nums}
.net-card .sep{width:1px;height:14px;background:var(--border);margin:0 2px}

/* Sections */
.section{margin-bottom:20px}
.section-title{font-size:1em;font-weight:600;margin-bottom:12px;color:var(--heading);display:flex;align-items:center;gap:8px;padding-left:2px}
.section-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent);margin-left:8px}

/* Info cards */
.info-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:10px}
.info-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;transition:all 0.25s ease}
.info-card:hover{border-color:var(--border2);box-shadow:var(--shadow)}
.info-card .card-title{font-size:0.82em;font-weight:600;color:var(--text);margin-bottom:10px;display:flex;align-items:center;gap:6px}
.info-card .row{display:flex;justify-content:space-between;font-size:0.82em;padding:3px 0}
.info-card .row .k{color:var(--text2)}.info-card .row .v{color:var(--heading);font-weight:600;font-variant-numeric:tabular-nums}
.info-card-full{grid-column:1/-1}
.progress-bar{width:100%;height:6px;background:var(--bg2);border-radius:4px;margin:6px 0 8px;overflow:hidden}
.progress-bar .fill{height:100%;border-radius:4px;transition:width 0.6s cubic-bezier(0.4,0,0.2,1)}
.fill-blue{background:linear-gradient(90deg,#4f8cff,#6c5ce7)}
.fill-green{background:linear-gradient(90deg,#00d68f,#00b894)}
.fill-orange{background:linear-gradient(90deg,#ffa94d,#ff6348)}

/* Tables */
.table-wrap{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:0.8em}
th{background:var(--bg2);color:var(--text2);font-weight:600;padding:10px 12px;text-align:left;font-size:0.75em;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;border-bottom:1px solid var(--border)}
td{padding:9px 12px;border-top:1px solid rgba(28,40,72,0.5);color:var(--text);white-space:nowrap;font-variant-numeric:tabular-nums}
tbody tr{transition:background 0.15s}
tbody tr:hover td{background:rgba(79,140,255,0.04)}
tbody tr:nth-child(even) td{background:rgba(15,21,38,0.3)}
tbody tr:nth-child(even):hover td{background:rgba(79,140,255,0.06)}
.st-online{color:var(--green);font-weight:600}
.st-offline{color:var(--red);font-weight:600}
.st-stopped{color:var(--text3);font-weight:600}
.st-tag{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.82em;font-weight:600;letter-spacing:0.2px}
.st-tag-ok{background:rgba(0,214,143,0.12);color:#00d68f;border:1px solid rgba(0,214,143,0.2)}
.st-tag-err{background:rgba(255,107,107,0.12);color:#ff6b6b;border:1px solid rgba(255,107,107,0.2)}
.st-tag-warn{background:rgba(255,169,77,0.12);color:#ffa94d;border:1px solid rgba(255,169,77,0.2)}
.st-tag-def{background:rgba(138,150,168,0.1);color:var(--text2);border:1px solid rgba(138,150,168,0.15)}
.runtime-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.latency-sparkline-placeholder{font-size:12px;color:var(--text3);min-height:28px;display:flex;align-items:center;justify-content:center}
.latency-sparkline-trigger{display:inline-flex;align-items:center;gap:8px;min-width:0;max-width:100%;outline:none}
.latency-sparkline-trigger.is-clickable{cursor:pointer}
.latency-sparkline-svg{display:block;flex-shrink:0;overflow:visible}
.latency-sparkline-floating-tooltip{position:fixed;z-index:2100;max-width:min(320px,calc(100vw - 32px));background:rgba(10,15,28,0.96);border:1px solid var(--border2);border-radius:12px;box-shadow:0 20px 50px rgba(0,0,0,0.35);padding:10px 12px;pointer-events:none}
.latency-sparkline-tooltip{font-size:12px;line-height:1.5;overflow-wrap:anywhere}
.latency-sparkline-tooltip-title{font-weight:600;margin-bottom:2px}
.latency-sparkline-tooltip-value{font-size:14px;font-weight:700;margin-bottom:4px}
.latency-sparkline-tooltip-divider{height:1px;margin:6px 0;background:rgba(128,128,128,0.18)}
.latency-sparkline-tooltip-time{margin-top:4px;color:var(--text2)}
.proxy-history-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.proxy-history-summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.proxy-history-summary-title{font-size:12px;color:var(--text2);margin-bottom:8px}
.proxy-history-summary-value{font-size:18px;font-weight:700;color:var(--heading);line-height:1.3}
.proxy-history-summary-sub{margin-top:6px;font-size:12px;color:var(--text2);line-height:1.4;word-break:break-word}
.proxy-history-chart-grid{display:grid;gap:12px}
.proxy-history-detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
.proxy-history-large-chart{overflow-x:auto;padding-bottom:4px}
.proxy-history-slider-card{border:1px solid var(--border);border-radius:10px;padding:12px 14px;background:var(--bg2)}
.proxy-history-slider-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px;font-size:12px;color:var(--text2);flex-wrap:wrap}
.proxy-history-event-list{margin-top:12px;display:grid;gap:8px}
.proxy-history-event-item{border:1px solid var(--border);border-radius:8px;padding:10px 12px;background:var(--bg2)}
.proxy-history-event-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:4px;font-size:12px;color:var(--text)}
.proxy-history-event-sub{display:flex;justify-content:space-between;align-items:center;gap:12px;font-size:12px;color:var(--text2);word-break:break-word}
.history-modal-backdrop{position:fixed;inset:0;display:none;align-items:center;justify-content:center;padding:24px;background:rgba(4,8,20,0.72);z-index:1800}
.history-modal{width:min(1180px,96vw);max-height:90vh;display:flex;flex-direction:column;background:var(--card);border:1px solid var(--border);border-radius:16px;box-shadow:0 24px 80px rgba(0,0,0,0.45)}
.history-modal-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:18px 20px 16px;border-bottom:1px solid var(--border)}
.history-modal-title{font-size:18px;font-weight:700;color:var(--heading)}
.history-modal-subtitle{font-size:12px;color:var(--text2);margin-top:4px}
.history-modal-close{background:var(--bg2);border:1px solid var(--border);color:var(--text);width:34px;height:34px;border-radius:10px;cursor:pointer;font-size:18px;line-height:1;transition:all .2s}
.history-modal-close:hover{background:var(--card-hover);border-color:var(--border2)}
.history-modal-body{padding:18px 20px 20px;overflow:auto;display:grid;gap:12px}
.history-modal-alert{border:1px solid var(--border);border-radius:10px;padding:10px 12px;background:var(--bg2);font-size:12px;color:var(--text2)}
.history-modal-alert.warning{color:#ffa94d;border-color:rgba(255,169,77,0.22)}
.history-control{background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:8px;font-size:12px;outline:none}
.history-control:focus{border-color:var(--accent)}
.history-control-group{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.history-slider-row{display:grid;grid-template-columns:84px 1fr auto;gap:10px;align-items:center;font-size:12px;margin-top:10px}
.history-slider-row input[type=range]{width:100%;accent-color:var(--accent)}

/* Pagination */
.pager{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;gap:10px;flex-wrap:wrap;border-top:1px solid var(--border);font-size:0.8em}
.pager-info{color:var(--text2);font-variant-numeric:tabular-nums}
.pager-controls{display:flex;align-items:center;gap:6px}
.pager-btn{background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:8px;cursor:pointer;font-size:0.85em;transition:all 0.15s;min-width:32px;text-align:center}
.pager-btn:hover:not(:disabled){background:var(--card-hover);border-color:var(--border2)}
.pager-btn:disabled{opacity:0.35;cursor:not-allowed}
.pager-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);font-weight:600}
.pager-size{display:flex;align-items:center;gap:6px}
.pager-size label{color:var(--text2);font-size:0.85em}
.pager-size select{background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:8px;font-size:0.85em;cursor:pointer;outline:none}
.pager-size select:focus{border-color:var(--accent)}

/* Footer */
.footer{text-align:center;color:var(--text3);font-size:0.75em;margin-top:28px;padding:18px 0;border-top:1px solid var(--border)}
.footer a{color:var(--accent);text-decoration:none}
.loading{text-align:center;padding:60px 20px;color:var(--text2);font-size:0.95em}
.loading .spinner{width:28px;height:28px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 14px}
@keyframes spin{to{transform:rotate(360deg)}}
.empty-row td{text-align:center;color:var(--text3);font-style:italic;padding:18px}

/* Fade-in */
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
#content{animation:fadeIn 0.4s ease}

/* ===== Light theme ===== */
body.light{--bg:#f5f7fa;--bg2:#edf0f5;--card:#ffffff;--card-hover:#f8f9fc;--border:#e2e6ee;--border2:#d0d5e0;--text:#3a4252;--text2:#7a8599;--text3:#a0a8b8;--heading:#1a2035;--accent:#4f8cff;--shadow:0 2px 12px rgba(0,0,0,0.06)}
.light .header{background:linear-gradient(135deg,rgba(79,140,255,0.06),rgba(108,92,231,0.04))}
.light .header::before{background:radial-gradient(circle at 30% 40%,rgba(79,140,255,0.04),transparent 60%)}
.light .badge{background:rgba(0,214,143,0.1);color:#00a870;border-color:rgba(0,168,112,0.2)}
.light .badge.error{background:rgba(255,107,107,0.1);color:#d63031;border-color:rgba(214,48,49,0.2)}
.light tbody tr:nth-child(even) td{background:rgba(237,240,245,0.4)}
.light tbody tr:hover td{background:rgba(79,140,255,0.04)}
.light tbody tr:nth-child(even):hover td{background:rgba(79,140,255,0.06)}
.light .st-tag-ok{background:rgba(0,214,143,0.08);color:#00a870;border-color:rgba(0,168,112,0.15)}
.light .st-tag-err{background:rgba(255,107,107,0.08);color:#d63031;border-color:rgba(214,48,49,0.15)}
.light .st-tag-warn{background:rgba(255,169,77,0.08);color:#d68910;border-color:rgba(214,137,16,0.15)}
.light .st-tag-def{background:rgba(122,133,153,0.06);color:var(--text2);border-color:rgba(122,133,153,0.1)}
.light .fill-blue{background:linear-gradient(90deg,#4f8cff,#7c6cf0)}
.light .fill-green{background:linear-gradient(90deg,#00c880,#00a870)}
.light .fill-orange{background:linear-gradient(90deg,#ffa040,#ff7043)}

@media(max-width:640px){
  .stat-grid{grid-template-columns:repeat(3,1fr)}
  .stat-grid-extra{grid-template-columns:repeat(2,1fr)}
  .info-grid{grid-template-columns:1fr}
  .runtime-grid{grid-template-columns:1fr}
  .net-card{flex-direction:column;gap:4px;text-align:center}
  .net-card .sep{display:none}
  body{padding:12px 8px}
  .toolbar{justify-content:center}
  .header{padding:20px 14px 18px}
  .header h1{font-size:1.3em}
}
</style>
</head>
<body>
<div class="container" id="app">
  <div class="loading" id="loading"><div class="spinner"></div>正在加载服务器状态...</div>
  <div id="content" style="display:none">
    <div class="toolbar">
      <span class="refresh-info"><span class="dot"></span>数据缓存: <span class="t" id="lastRefresh">-</span></span>
      <span class="refresh-info">下次页面刷新: <span class="t" id="nextCheckCountdown">-</span></span>
      <button class="btn" onclick="handleManualRefresh()" title="立即刷新"><svg viewBox="0 0 24 24"><path d="M17.65 6.35A7.958 7.958 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>刷新</button>
      <button class="btn" id="themeBtn" onclick="toggleTheme()" title="切换主题"><svg viewBox="0 0 24 24" id="themeIcon"><path d="M12 3a9 9 0 109 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 01-4.4 2.26 5.403 5.403 0 01-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/></svg></button>
    </div>

    <div class="header">
      <h1><span class="icon">⚡</span>Minecraft 服务器状态</h1>
      <span class="badge" id="globalBadge">运行正常</span>
    </div>

    <div class="stat-grid">
      <div class="stat-card"><div class="label">CPU使用率</div><div class="value" id="cpuUsage">-</div></div>
      <div class="stat-card"><div class="label">内存使用率</div><div class="value" id="memUsage">-</div></div>
      <div class="stat-card"><div class="label">磁盘使用率</div><div class="value" id="diskUsage">-</div></div>
      <div class="stat-card"><div class="label">在线服务器</div><div class="value" id="onlineServers">-</div></div>
      <div class="stat-card"><div class="label">活跃会话</div><div class="value" id="sessionCount">-</div></div>
    </div>
    <div class="stat-grid-extra">
      <div class="stat-card"><div class="label">Goroutines</div><div class="value" id="goroutineCount">-</div></div>
      <div class="stat-card"><div class="label">进程内存</div><div class="value" id="topProcMem">-</div><div class="sub" id="topProcCpu">-</div></div>
      <div class="stat-card"><div class="label">Go 堆内存</div><div class="value" id="topHeap">-</div><div class="sub" id="topHeapSys">-</div></div>
      <div class="stat-card"><div class="label">运行时间</div><div class="value" id="topUptime">-</div><div class="sub" id="topStartTime">-</div></div>
    </div>
    <div class="net-card">
      <span><span class="ni">总上传</span> <span class="nv" id="topNetUp">-</span></span>
      <span class="sep"></span>
      <span><span class="ni">总下载</span> <span class="nv" id="topNetDown">-</span></span>
      <span class="sep"></span>
      <span><span class="ni">↑</span> <span class="nv" id="topNetSpeedUp">-</span></span>
      <span class="sep"></span>
      <span><span class="ni">↓</span> <span class="nv" id="topNetSpeedDown">-</span></span>
      <span class="sep"></span>
      <span><span class="ni">包</span> <span class="nv" id="topNetPkts">-</span></span>
    </div>

    <div class="section">
      <div class="section-title">⚙️ 系统资源</div>
      <div class="info-grid">
        <div class="info-card">
          <div class="card-title">🖥 CPU</div>
          <div class="row"><span class="k">系统</span><span class="v" id="cpuPct">-</span></div>
          <div class="progress-bar"><div class="fill fill-blue" id="cpuBar" style="width:0%"></div></div>
          <div class="row"><span class="k">核心</span><span class="v" id="cpuCores">-</span></div>
          <div class="row"><span class="k">进程</span><span class="v" id="procCpu">-</span></div>
        </div>
        <div class="info-card">
          <div class="card-title">🧠 内存</div>
          <div class="row"><span class="k">使用率</span><span class="v" id="memPct">-</span></div>
          <div class="progress-bar"><div class="fill fill-orange" id="memBar" style="width:0%"></div></div>
          <div class="row"><span class="k">已用 / 总计</span><span class="v" id="memDetail">-</span></div>
        </div>
        <div class="info-card">
          <div class="card-title">💾 磁盘</div>
          <div class="row"><span class="k">使用率</span><span class="v" id="diskPct">-</span></div>
          <div class="progress-bar"><div class="fill fill-green" id="diskBar" style="width:0%"></div></div>
          <div class="row"><span class="k">已用 / 总计</span><span class="v" id="diskDetail">-</span></div>
        </div>
        <div class="info-card info-card-full">
          <div class="card-title">🌐 网络与运行</div>
          <div class="row"><span class="k">发送 / 接收</span><span class="v" id="netTotal">-</span></div>
          <div class="row"><span class="k">速度</span><span class="v" id="netSpeed">-</span></div>
          <div class="row"><span class="k">运行时间</span><span class="v" id="uptime">-</span></div>
          <div class="row"><span class="k">进程内存</span><span class="v" id="procMem">-</span></div>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">🖧 服务器状态</div>
      <div class="table-wrap">
        <table><thead><tr><th>服务器ID</th><th>状态</th><th>延迟</th><th>趋势</th><th>名称</th></tr></thead>
        <tbody id="serverTable"><tr class="empty-row"><td colspan="5">无数据</td></tr></tbody></table>
      </div>
    </div>

    <div class="section">
      <div class="section-title">💬 活跃会话</div>
      <div class="table-wrap">
        <table><thead><tr><th>服务器</th><th>玩家</th><th>地址</th><th>上传</th><th>下载</th><th>时长</th></tr></thead>
        <tbody id="sessionTable"><tr class="empty-row"><td colspan="6">无活跃会话</td></tr></tbody></table>
      </div>
    </div>

    <div class="section">
      <div class="section-title">📋 历史会话</div>
      <div class="table-wrap">
        <table><thead><tr><th>玩家</th><th>服务器</th><th>状态</th><th>原因</th><th>时间</th><th>上传</th><th>下载</th></tr></thead>
        <tbody id="historyTable"><tr class="empty-row"><td colspan="7">无历史记录</td></tr></tbody></table>
        <div class="pager" id="historyPager">
          <div class="pager-info" id="historyPagerInfo">-</div>
          <div class="pager-controls">
            <div class="pager-size"><label>每页</label><select id="historyPageSize" onchange="changePageSize(this.value)"><option value="10" selected>10</option><option value="20">20</option><option value="100">100</option><option value="200">200</option><option value="500">500</option><option value="1000">1000</option></select></div>
            <button class="pager-btn" id="hpFirst" onclick="goPage(1)" title="首页">«</button>
            <button class="pager-btn" id="hpPrev" onclick="goPage(hPage-1)" title="上一页">‹</button>
            <span id="hpPages"></span>
            <button class="pager-btn" id="hpNext" onclick="goPage(hPage+1)" title="下一页">›</button>
            <button class="pager-btn" id="hpLast" onclick="goPage(hTotalPages)" title="末页">»</button>
          </div>
        </div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">⚡ Go 运行时</div>
      <div class="runtime-grid">
        <div class="info-card">
          <div class="card-title">📊 协程与GC</div>
          <div class="row"><span class="k">Goroutines</span><span class="v" id="rtGoroutines">-</span></div>
          <div class="row"><span class="k">GC 次数</span><span class="v" id="rtGC">-</span></div>
        </div>
        <div class="info-card">
          <div class="card-title">📦 堆内存</div>
          <div class="row"><span class="k">分配</span><span class="v" id="rtHeapAlloc">-</span></div>
          <div class="row"><span class="k">系统</span><span class="v" id="rtHeapSys">-</span></div>
          <div class="row"><span class="k">使用中</span><span class="v" id="rtHeapInuse">-</span></div>
          <div class="row"><span class="k">栈</span><span class="v" id="rtStackInuse">-</span></div>
        </div>
      </div>
    </div>

    <div class="footer">
      <div id="updateTime">更新时间：-</div>
      <div style="margin-top:5px">Powered by AstBot Server Status Plugin</div>
    </div>
    <div id="sparklineTooltip" class="latency-sparkline-floating-tooltip" style="display:none"></div>
    <div id="historyModalBackdrop" class="history-modal-backdrop" onclick="closeHistoryModal(event)">
      <div class="history-modal" role="dialog" aria-modal="true" aria-labelledby="historyModalTitle" onclick="event.stopPropagation()">
        <div class="history-modal-header">
          <div>
            <div class="history-modal-title" id="historyModalTitle">延迟历史</div>
            <div class="history-modal-subtitle" id="historyModalSubtitle">-</div>
          </div>
          <button class="history-modal-close" type="button" aria-label="关闭" onclick="closeHistoryModal()">×</button>
        </div>
        <div class="history-modal-body">
          <div class="history-modal-alert">上方控制后端请求时间范围；下方滑块会在已加载的时间段内继续滚动 / 缩放查看。</div>
          <div class="proxy-history-toolbar">
            <div class="history-control-group">
              <select id="historyRangeKey" class="history-control" onchange="onHistoryRangeChange()">
                <option value="1h">最近 1 小时</option>
                <option value="6h">最近 6 小时</option>
                <option value="24h" selected>最近 24 小时</option>
                <option value="custom">自定义</option>
              </select>
              <input id="historyCustomStart" class="history-control" type="datetime-local" onchange="onHistoryRangeChange()" style="display:none">
              <input id="historyCustomEnd" class="history-control" type="datetime-local" onchange="onHistoryRangeChange()" style="display:none">
              <button class="btn" type="button" onclick="refreshHistoryModal()">刷新</button>
            </div>
            <div class="history-control-group">
              <span class="st-tag st-tag-def" id="historyWindowLabel">-</span>
              <span class="st-tag st-tag-warn" id="historyNextCheckCountdown">下次检测 -</span>
            </div>
          </div>
          <div id="historyModalError" class="history-modal-alert warning" style="display:none"></div>
          <div id="historySummaryGrid" class="proxy-history-summary-grid"></div>
          <div id="historyCharts" class="proxy-history-chart-grid"></div>
          <div id="historySliderCard" class="proxy-history-slider-card" style="display:none">
            <div class="proxy-history-slider-header">
              <span>当前视窗</span>
              <span id="historyVisibleWindowLabel">-</span>
            </div>
            <div class="history-slider-row"><span>起点</span><input id="historyViewportStart" type="range" min="0" max="100" step="1" value="0" oninput="onHistoryViewportChange()"><span id="historyViewportStartLabel">0%</span></div>
            <div class="history-slider-row"><span>终点</span><input id="historyViewportEnd" type="range" min="0" max="100" step="1" value="100" oninput="onHistoryViewportChange()"><span id="historyViewportEndLabel">100%</span></div>
          </div>
          <div id="historyDetailGrid" class="proxy-history-detail-grid"></div>
        </div>
      </div>
    </div>
   </div>
 </div>
 <script>
function fmtBytes(b){if(!b||b===0)return'0 B';var u=['B','KB','MB','GB','TB'],i=0,v=b;while(v>=1024&&i<u.length-1){v/=1024;i++}return v.toFixed(2)+' '+u[i]}
function fmtBytesShort(b){if(!b||b===0)return'0 B';var u=['B','KB','MB','GB','TB'],i=0,v=b;while(v>=1024&&i<u.length-1){v/=1024;i++}return(v>=100?v.toFixed(0):v.toFixed(1))+' '+u[i]}
function fmtSpeed(bps){if(!bps||bps===0)return'0 B/s';return fmtBytes(bps)+'/s'}
function fmtSpeedShort(bps){if(!bps||bps===0)return'0 B/s';return fmtBytesShort(bps)+'/s'}
function fmtPct(v){return(v||0).toFixed(1)+'%'}
function fmtNum(n){if(!n||n===0)return'0';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return String(n)}
function fmtDuration(sec){if(!sec||sec<=0)return'-';var d=Math.floor(sec/86400),h=Math.floor((sec%86400)/3600),m=Math.floor((sec%3600)/60),s=Math.floor(sec%60),r='';if(d>0)r+=d+'天';if(h>0)r+=h+'小时';if(m>0)r+=m+'分';if(!d)r+=s+'秒';return r||'-'}
function fmtDurationShort(sec){if(!sec||sec<=0)return'-';var d=Math.floor(sec/86400),h=Math.floor((sec%86400)/3600),m=Math.floor((sec%3600)/60),s=Math.floor(sec%60);if(d>0)return d+'天'+h+'时';if(h>0)return h+'时'+m+'分';return m+'分'+s+'秒'}
function fmtLatency(ms){if(ms===undefined||ms===null||ms<0)return'N/A';return ms+' ms'}
function fmtTime(t){if(!t)return'-';var d=new Date(t);return d.getFullYear()+'-'+P(d.getMonth()+1)+'-'+P(d.getDate())+' '+P(d.getHours())+':'+P(d.getMinutes())+':'+P(d.getSeconds())}
function fmtTimeShort(t){if(!t)return'-';var d=new Date(t);return P(d.getMonth()+1)+'-'+P(d.getDate())+' '+P(d.getHours())+':'+P(d.getMinutes())}
function P(n){return String(n).padStart(2,'0')}
function $(id){return document.getElementById(id)}
function esc(s){if(!s)return'';var d=document.createElement('div');d.textContent=s;return d.innerHTML}

function latestLatencySample(samples){return Array.isArray(samples)&&samples.length?samples[samples.length-1]:null}
var pageSnapshot={servers:[],latency_history:{}};
var sparklineStore={},sparklineSeq=0,historyFetchToken=0,wiRefreshIntervalMs=10000,lastFetchStartedAt=0;
var historyModalState={open:false,kind:'',target:null,rangeKey:'24h',loading:false,error:'',requestWindow:null,serverSamples:[],proxyMetrics:{tcp:[],http:[],udp:[]}};
function resetSparklineStore(){sparklineStore={};sparklineSeq=0}
function clampLatency(value){var latency=Number(value);if(!isFinite(latency)||latency<=0)return 0;return Math.min(Math.round(latency),3600000)}
function clampTimestamp(value){var timestamp=Number(value);if(!isFinite(timestamp)||timestamp<=0)return 0;return Math.round(timestamp)}
function normalizeSampleStatus(sample,latencyMs){if(sample&&sample.stopped)return'stopped';if(sample&&typeof sample.ok==='boolean')return sample.ok&&latencyMs>0?'ok':'error';if(sample&&typeof sample.online==='boolean'){if(!sample.online)return'offline';return latencyMs>0?'ok':'online'}return latencyMs>0?'ok':'error'}
function normalizeLatencySamples(samples,maxSamples){if(!Array.isArray(samples))return[];var limit=Math.min(Math.max(Number(maxSamples)||512,1),2000);return samples.slice(-limit).map(function(sample,index){var latencyMs=clampLatency(sample&&sample.latencyMs!==undefined?sample.latencyMs:sample&&sample.latency_ms),status=sample&&typeof sample.status==='string'?String(sample.status).trim():normalizeSampleStatus(sample,latencyMs);return{raw:sample&&sample.raw?sample.raw:(sample||{}),index:index,latencyMs:latencyMs,timestamp:clampTimestamp(sample&&sample.timestamp),status:status,source:sample&&typeof sample.source==='string'?String(sample.source).trim():''}}).sort(function(a,b){return a.timestamp===b.timestamp?a.index-b.index:a.timestamp-b.timestamp})}
function isHealthyLatencySample(sample){return!!sample&&sample.status==='ok'&&sample.latencyMs>0}
function getSampleColor(sample){if(!sample||sample.status==='stopped')return'#8c8c8c';if(sample.status==='offline'||sample.status==='error')return'#d03050';if(sample.status==='online')return'#2080f0';if(sample.latencyMs<50)return'#18a058';if(sample.latencyMs<100)return'#2080f0';if(sample.latencyMs<200)return'#f0a020';return'#d03050'}
function getSampleStatusLabel(sample){if(!sample)return'-';if(sample.status==='ok')return'成功';if(sample.status==='offline')return'离线';if(sample.status==='online')return'在线';if(sample.status==='stopped')return'已停止';return'失败'}
function getSampleLatencyLabel(sample){return sample&&isHealthyLatencySample(sample)?sample.latencyMs+' ms':'-'}
function getSampleHeadline(sample){if(!sample)return'-';return isHealthyLatencySample(sample)?sample.latencyMs+' ms':getSampleStatusLabel(sample)}
function buildLinePath(points){if(!points.length)return'';var path='M '+points[0].x.toFixed(2)+' '+points[0].y.toFixed(2);for(var i=1;i<points.length;i++)path+=' L '+points[i].x.toFixed(2)+' '+points[i].y.toFixed(2);return path}
function buildAreaPath(points,baselineY){if(!points.length)return'';var path='M '+points[0].x.toFixed(2)+' '+baselineY.toFixed(2);for(var i=0;i<points.length;i++)path+=' L '+points[i].x.toFixed(2)+' '+points[i].y.toFixed(2);path+=' L '+points[points.length-1].x.toFixed(2)+' '+baselineY.toFixed(2)+' Z';return path}
function buildSparklineModel(samples,width,height){var paddingX=4,paddingTop=4,paddingBottom=4,baselineY=height-paddingBottom,usableHeight=Math.max(baselineY-paddingTop,1),innerWidth=Math.max(width-paddingX*2,1),okValues=samples.filter(isHealthyLatencySample).map(function(sample){return sample.latencyMs}),okCount=okValues.length,failureCount=samples.length-okCount,min=okCount?Math.min.apply(null,okValues):0,max=okCount?Math.max.apply(null,okValues):0,avg=okCount?Math.round(okValues.reduce(function(sum,value){return sum+value},0)/okCount):0,range=Math.max(max-min,1),segments=[],points=[],current=[],latestSuccessfulPoint=null;for(var i=0;i<samples.length;i++){var sample=samples[i],x=samples.length===1?paddingX+innerWidth/2:paddingX+(innerWidth*i)/Math.max(samples.length-1,1);if(!isHealthyLatencySample(sample)){points.push({x:x,y:baselineY-3,index:i,sample:sample,isRenderable:false,markerTop:Math.max(paddingTop+2,baselineY-7),markerBottom:baselineY-1});if(current.length){segments.push(current);current=[]}continue}var y=Math.max(paddingTop,baselineY-((sample.latencyMs-min)/range)*usableHeight),point={x:x,y:y,index:i,sample:sample,isRenderable:true};points.push(point);current.push(point);latestSuccessfulPoint=point}if(current.length)segments.push(current);return{points:points,linePaths:segments.map(function(segment){return buildLinePath(segment)}).filter(Boolean),areaPaths:segments.map(function(segment){return buildAreaPath(segment,baselineY)}).filter(Boolean),failurePoints:points.filter(function(point){return!point.isRenderable}),latestSuccessfulPoint:latestSuccessfulPoint,baselineY:baselineY,midY:paddingTop+usableHeight/2,min:min,max:max,avg:avg,okCount:okCount,failureCount:failureCount}}
function getSparklineRangeLabel(samples){var first=samples[0],last=samples[samples.length-1];if(!first||!last||!first.timestamp||!last.timestamp)return'';return fmtTimeShort(first.timestamp)+' - '+fmtTimeShort(last.timestamp)}
function createSparklineMarkup(options){options=options||{};var width=Math.min(Math.max(Math.round(Number(options.width)||96),48),2048),height=Math.min(Math.max(Math.round(Number(options.height)||28),24),1024),label=options.label||'延迟历史',normalized=normalizeLatencySamples(options.samples,options.maxSamples),clickable=!!options.clickable,id='spk-'+(++sparklineSeq),entry={id:id,label:label,normalized:normalized,clickable:clickable,clickAction:options.clickAction||null,showLabel:options.showLabel!==false};sparklineStore[id]=entry;if(!normalized.length)return'<div class="latency-sparkline-trigger'+(clickable?' is-clickable':'')+'" data-sparkline-key="'+id+'"'+(clickable?' tabindex="0" role="button"':'')+'><div class="latency-sparkline-placeholder">'+esc(options.emptyText||'暂无')+'</div></div>';var gradientId=id+'-grad',model=buildSparklineModel(normalized,width,height),latest=latestLatencySample(normalized),strokeColor=getSampleColor(latest);entry.width=width;entry.height=height;entry.model=model;entry.latest=latest;entry.strokeColor=strokeColor;entry.rangeLabel=getSparklineRangeLabel(normalized);var html='<div class="latency-sparkline-trigger'+(clickable?' is-clickable':'')+'" data-sparkline-key="'+id+'"'+(clickable?' tabindex="0" role="button"':'')+'><svg width="'+width+'" height="'+height+'" viewBox="0 0 '+width+' '+height+'" class="latency-sparkline-svg"><defs><linearGradient id="'+gradientId+'" x1="0" y1="0" x2="0" y2="'+height+'"><stop offset="0%" stop-color="rgba(32,128,240,0.24)"/><stop offset="100%" stop-color="rgba(32,128,240,0.02)"/></linearGradient></defs><rect x="0.5" y="0.5" width="'+(width-1)+'" height="'+(height-1)+'" rx="6" fill="rgba(32,128,240,0.04)" stroke="rgba(128,128,128,0.16)"/><line x1="4" y1="4" x2="'+(width-4)+'" y2="4" stroke="rgba(128,128,128,0.12)" stroke-width="1"/><line x1="4" y1="'+model.midY.toFixed(2)+'" x2="'+(width-4)+'" y2="'+model.midY.toFixed(2)+'" stroke="rgba(128,128,128,0.16)" stroke-width="1" stroke-dasharray="3 3"/><line x1="4" y1="'+model.baselineY.toFixed(2)+'" x2="'+(width-4)+'" y2="'+model.baselineY.toFixed(2)+'" stroke="rgba(128,128,128,0.2)" stroke-width="1" stroke-dasharray="4 3"/>';for(var i=0;i<model.areaPaths.length;i++)html+='<path d="'+model.areaPaths[i]+'" fill="url(#'+gradientId+')"/>';for(var j=0;j<model.linePaths.length;j++)html+='<path d="'+model.linePaths[j]+'" fill="none" stroke="'+strokeColor+'" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round"/>';for(var k=0;k<model.failurePoints.length;k++){var fp=model.failurePoints[k];html+='<line x1="'+(fp.x-3).toFixed(2)+'" y1="'+fp.markerTop.toFixed(2)+'" x2="'+(fp.x+3).toFixed(2)+'" y2="'+fp.markerBottom.toFixed(2)+'" stroke="#d03050" stroke-width="1.6" stroke-linecap="round"/><line x1="'+(fp.x+3).toFixed(2)+'" y1="'+fp.markerTop.toFixed(2)+'" x2="'+(fp.x-3).toFixed(2)+'" y2="'+fp.markerBottom.toFixed(2)+'" stroke="#d03050" stroke-width="1.6" stroke-linecap="round"/>'}if(model.latestSuccessfulPoint)html+='<circle cx="'+model.latestSuccessfulPoint.x.toFixed(2)+'" cy="'+model.latestSuccessfulPoint.y.toFixed(2)+'" r="2.4" fill="'+strokeColor+'"/>';html+='<line class="latency-active-guide" x1="0" y1="4" x2="0" y2="'+model.baselineY.toFixed(2)+'" stroke="rgba(32,128,240,0.28)" stroke-width="1" stroke-dasharray="3 3" style="display:none"/><circle class="latency-active-dot" cx="0" cy="0" r="4.2" fill="#fff" stroke="'+strokeColor+'" stroke-width="2" style="display:none"/></svg>';if(entry.showLabel){html+='<div class="latency-sparkline-meta"><div class="latency-sparkline-latest" style="font-weight:600;color:'+getSampleColor(latest)+'">'+esc(getSampleHeadline(latest))+'</div><div class="latency-sparkline-count">'+normalized.length+' 点 · '+model.okCount+'/'+normalized.length+' 成功</div></div>'}html+='</div>';return html}
function nearestSparklineIndex(points,x){if(!points.length)return-1;var nearest=points[0],distance=Math.abs(nearest.x-x);for(var i=1;i<points.length;i++){var nextDistance=Math.abs(points[i].x-x);if(nextDistance<distance){nearest=points[i];distance=nextDistance}}return nearest.index}
function renderSparklineTooltipContent(entry,point){var sample=point&&point.sample?point.sample:entry.latest,latencyText=getSampleLatencyLabel(sample),html='<div class="latency-sparkline-tooltip"><div class="latency-sparkline-tooltip-title">'+esc(entry.label)+'</div><div class="latency-sparkline-tooltip-value" style="color:'+getSampleColor(sample)+'">'+esc(getSampleHeadline(sample))+'</div><div>时间: '+esc(fmtTime(sample&&sample.timestamp?sample.timestamp:0))+'</div><div>状态: '+esc(getSampleStatusLabel(sample))+'</div>';if(latencyText!=='-')html+='<div>延迟: '+esc(latencyText)+'</div>';if(sample&&sample.source)html+='<div>来源: '+esc(sample.source)+'</div>';html+='<div class="latency-sparkline-tooltip-divider"></div><div>样本: '+entry.normalized.length+'</div><div>成功: '+entry.model.okCount+' / 失败: '+entry.model.failureCount+'</div>';if(entry.model.okCount>0)html+='<div>最低 / 平均 / 最高: '+entry.model.min+' / '+entry.model.avg+' / '+entry.model.max+' ms</div>';if(entry.rangeLabel)html+='<div class="latency-sparkline-tooltip-time">跨度: '+esc(entry.rangeLabel)+'</div>';return html+'</div>'}
function positionSparklineTooltip(x,y){var tooltip=$('sparklineTooltip');if(!tooltip)return;var pad=12,rect=tooltip.getBoundingClientRect(),left=x+14,top=y+14;if(left+rect.width+pad>window.innerWidth)left=Math.max(pad,x-rect.width-14);if(top+rect.height+pad>window.innerHeight)top=Math.max(pad,y-rect.height-14);tooltip.style.left=left+'px';tooltip.style.top=top+'px'}
function setSparklineActiveElements(el,entry,point){var guide=el.querySelector('.latency-active-guide'),dot=el.querySelector('.latency-active-dot');if(!guide||!dot)return;if(!point){guide.style.display='none';dot.style.display='none';return}guide.setAttribute('x1',point.x.toFixed(2));guide.setAttribute('x2',point.x.toFixed(2));guide.style.display='';dot.setAttribute('cx',point.x.toFixed(2));dot.setAttribute('cy',point.y.toFixed(2));dot.setAttribute('stroke',point.isRenderable?entry.strokeColor:'#d03050');dot.style.display=''}
function showSparklineTooltip(el,key,clientX,clientY,forceIndex){var entry=sparklineStore[key],tooltip=$('sparklineTooltip');if(!entry||!tooltip||!entry.model||!entry.model.points.length)return;var rect=el.getBoundingClientRect(),index=typeof forceIndex==='number'?forceIndex:nearestSparklineIndex(entry.model.points,clientX-rect.left),point=entry.model.points[Math.max(0,index)];setSparklineActiveElements(el,entry,point);tooltip.innerHTML=renderSparklineTooltipContent(entry,point);tooltip.style.display='block';positionSparklineTooltip(typeof clientX==='number'?clientX:rect.left+rect.width/2,typeof clientY==='number'?clientY:rect.top+rect.height/2)}
function hideSparklineTooltip(el){var tooltip=$('sparklineTooltip');if(tooltip)tooltip.style.display='none';if(el){var key=el.getAttribute('data-sparkline-key'),entry=sparklineStore[key];if(entry)setSparklineActiveElements(el,entry,null)}}
function formatAbsoluteCountdownText(targetAt){var seconds=Math.max(0,Math.ceil(((Number(targetAt)||0)-Date.now())/1000)),minutes=Math.floor(seconds/60),remain=seconds%60;if(seconds<=0)return'即将';return minutes>0?minutes+'分'+P(remain)+'秒':remain+'秒'}
function getPageRefreshCountdownText(){if(!lastFetchStartedAt)return'-';return formatAbsoluteCountdownText(lastFetchStartedAt+wiRefreshIntervalMs)}
function getServerNextCheckCountdownText(server){if(!server||server.status!=='running')return'已停止';if(server.auto_ping_enabled!==true)return'未启用';var targetAt=Number(server.next_auto_ping_at||0);if(!targetAt)return'即将';return formatAbsoluteCountdownText(targetAt)}
function renderRefreshCountdown(){var toolbar=$('nextCheckCountdown'),modal=$('historyNextCheckCountdown');if(toolbar)toolbar.textContent=getPageRefreshCountdownText();if(modal){var text='-';if(historyModalState.kind==='server'&&historyModalState.target)text=getServerNextCheckCountdownText(historyModalState.target);modal.textContent='下次检测 '+text}}
function bindSparklineInteractions(root){var scope=root||document,nodes=scope.querySelectorAll('[data-sparkline-key]');Array.prototype.forEach.call(nodes,function(el){if(el.dataset.boundSparkline==='1')return;el.dataset.boundSparkline='1';el.addEventListener('mouseenter',function(event){showSparklineTooltip(el,el.getAttribute('data-sparkline-key'),event.clientX,event.clientY)});el.addEventListener('mousemove',function(event){showSparklineTooltip(el,el.getAttribute('data-sparkline-key'),event.clientX,event.clientY)});el.addEventListener('mouseleave',function(){hideSparklineTooltip(el)});el.addEventListener('focus',function(){var key=el.getAttribute('data-sparkline-key'),entry=sparklineStore[key];if(entry&&entry.model&&entry.model.points.length)showSparklineTooltip(el,key,el.getBoundingClientRect().left+el.getBoundingClientRect().width/2,el.getBoundingClientRect().top,entry.model.points.length-1)});el.addEventListener('blur',function(){hideSparklineTooltip(el)});el.addEventListener('click',function(event){var key=el.getAttribute('data-sparkline-key'),entry=sparklineStore[key];if(!entry||!entry.clickable||!entry.clickAction)return;event.stopPropagation();if(entry.clickAction.kind==='server')openServerHistoryModal(entry.clickAction.target)});el.addEventListener('keydown',function(event){if(event.key!=='Enter'&&event.key!==' ')return;var key=el.getAttribute('data-sparkline-key'),entry=sparklineStore[key];if(!entry||!entry.clickable||!entry.clickAction)return;event.preventDefault();event.stopPropagation();if(entry.clickAction.kind==='server')openServerHistoryModal(entry.clickAction.target)})})}

var statusMap={'disconnected':['正常断开','st-tag-ok'],'blacklist':['黑名单','st-tag-err'],'whitelist':['白名单拒绝','st-tag-warn'],'auth_failed':['验证失败','st-tag-err'],'kicked':['被踢出','st-tag-warn']};
function stTag(st){var info=statusMap[st||'disconnected']||[st||'断开','st-tag-def'];return '<span class="st-tag '+info[1]+'">'+esc(info[0])+'</span>'}

// Pagination state
var hPage=1,hLimit=10,hTotal=0,hTotalPages=1;
function getQuickHistoryWindow(key){var now=Date.now();if(key==='1h')return[now-3600000,now];if(key==='6h')return[now-21600000,now];return[now-86400000,now]}
function formatDateTimeLocal(value){var date=new Date(Number(value)||0);if(isNaN(date.getTime()))return'';return date.getFullYear()+'-'+P(date.getMonth()+1)+'-'+P(date.getDate())+'T'+P(date.getHours())+':'+P(date.getMinutes())}
function parseDateTimeLocal(value){if(!value)return 0;var date=new Date(value);return isNaN(date.getTime())?0:date.getTime()}
function syncHistoryRangeControls(){var rangeKey=historyModalState.rangeKey||'24h',startInput=$('historyCustomStart'),endInput=$('historyCustomEnd');$('historyRangeKey').value=rangeKey;var isCustom=rangeKey==='custom';startInput.style.display=isCustom?'':'none';endInput.style.display=isCustom?'':'none';if(isCustom&&!startInput.value&&!endInput.value){var range=getQuickHistoryWindow('24h');startInput.value=formatDateTimeLocal(range[0]);endInput.value=formatDateTimeLocal(range[1])}}
function getHistoryRequestWindow(){if((historyModalState.rangeKey||'24h')==='custom'){var start=parseDateTimeLocal($('historyCustomStart').value),end=parseDateTimeLocal($('historyCustomEnd').value);if(!start||!end)return null;return start<=end?[start,end]:[end,start]}return getQuickHistoryWindow(historyModalState.rangeKey||'24h')}
function getHistoryRequestLimit(){if(historyModalState.rangeKey==='1h')return 36;if(historyModalState.rangeKey==='6h')return 96;return 288}
function setHistoryModalError(message){historyModalState.error=message||'';$('historyModalError').style.display=message?'':'none';$('historyModalError').textContent=message||''}
function getHistoryVisibleWindow(range){if(!range)return null;var span=Math.max(range[1]-range[0],1),startPct=Math.min(Math.max(Number(historyModalState.viewportStart)||0,0),100),endPct=Math.min(Math.max(Number(historyModalState.viewportEnd)||100,0),100);if(startPct>endPct){var tmp=startPct;startPct=endPct;endPct=tmp}return[Math.round(range[0]+span*(startPct/100)),Math.round(range[0]+span*(endPct/100))]}
function filterSamplesByVisibleWindow(samples,range){samples=Array.isArray(samples)?samples:[];if(!range)return samples;return samples.filter(function(sample){var ts=Number(sample&&sample.timestamp||0);return ts>=range[0]&&ts<=range[1]})}
function openServerHistoryModal(server){if(!server||!server.id)return;historyModalState.open=true;historyModalState.kind='server';historyModalState.target={id:String(server.id),server_name:server.server_name||'',latency:server.latency,online:server.online,stopped:server.status!=='running',status:server.status||'',auto_ping_enabled:server.auto_ping_enabled===true,next_auto_ping_at:Number(server.next_auto_ping_at||0)};historyModalState.viewportStart=0;historyModalState.viewportEnd=100;historyModalState.serverSamples=[];$('historyModalBackdrop').style.display='flex';document.body.style.overflow='hidden';syncHistoryRangeControls();renderHistoryModalView();refreshHistoryModal()}
function closeHistoryModal(event){if(event&&event.target&&event.target!==$('historyModalBackdrop'))return;historyModalState.open=false;historyModalState.loading=false;historyModalState.error='';historyModalState.target=null;$('historyModalBackdrop').style.display='none';document.body.style.overflow='';setHistoryModalError('');hideSparklineTooltip()}
function onHistoryRangeChange(){historyModalState.rangeKey=$('historyRangeKey').value||'24h';historyModalState.viewportStart=0;historyModalState.viewportEnd=100;syncHistoryRangeControls();refreshHistoryModal()}
function onHistoryViewportChange(){var startValue=Math.min(Math.max(parseInt($('historyViewportStart').value,10)||0,0),100),endValue=Math.min(Math.max(parseInt($('historyViewportEnd').value,10)||100,0),100);if(startValue>endValue){if(document.activeElement===$('historyViewportStart'))endValue=startValue;else startValue=endValue;$('historyViewportStart').value=String(startValue);$('historyViewportEnd').value=String(endValue)}historyModalState.viewportStart=startValue;historyModalState.viewportEnd=endValue;renderHistoryModalView()}
function refreshHistoryModal(){if(!historyModalState.open||!historyModalState.target)return;syncHistoryRangeControls();var range=getHistoryRequestWindow();if(!range){historyModalState.serverSamples=[];historyModalState.requestWindow=null;historyModalState.loading=false;setHistoryModalError('请选择完整的开始和结束时间。');renderHistoryModalView();return}historyModalState.requestWindow=range;historyModalState.loading=true;setHistoryModalError('');renderHistoryModalView();var endpoint='/api/web/servers/'+encodeURIComponent(historyModalState.target.id)+'/latency-history',params=new URLSearchParams({from:String(range[0]),to:String(range[1]),limit:String(getHistoryRequestLimit())}),token=++historyFetchToken;fetch(endpoint+'?'+params.toString()).then(function(response){return response.json()}).then(function(res){if(token!==historyFetchToken||!historyModalState.open)return;if(!res||!res.success||!res.data){historyModalState.serverSamples=[];setHistoryModalError(res&&res.msg?res.msg:'历史数据加载失败');return}historyModalState.serverSamples=Array.isArray(res.data.samples)?res.data.samples:[];setHistoryModalError('')}).catch(function(error){if(token!==historyFetchToken||!historyModalState.open)return;historyModalState.serverSamples=[];setHistoryModalError(error&&error.message?error.message:'历史数据加载失败')}).finally(function(){if(token!==historyFetchToken)return;historyModalState.loading=false;renderHistoryModalView()})}

function findLastMatchingSample(samples,predicate){for(var index=samples.length-1;index>=0;index--){if(predicate(samples[index]))return samples[index]}return null}
function summarizeLatencySamples(samples){var normalized=normalizeLatencySamples(samples,2000),okSamples=normalized.filter(isHealthyLatencySample),values=okSamples.map(function(sample){return sample.latencyMs}),latest=normalized[normalized.length-1]||null,lastSuccess=findLastMatchingSample(normalized,isHealthyLatencySample),lastFailure=findLastMatchingSample(normalized,function(sample){return!!sample&&!isHealthyLatencySample(sample)});return{normalized:normalized,count:normalized.length,okCount:okSamples.length,failedCount:Math.max(normalized.length-okSamples.length,0),latest:latest,lastSuccess:lastSuccess,lastFailure:lastFailure,successRate:normalized.length?Math.round(okSamples.length/normalized.length*100)+'% ('+okSamples.length+'/'+normalized.length+')':'-',minAvgMax:values.length?Math.min.apply(null,values)+' / '+Math.round(values.reduce(function(sum,value){return sum+value},0)/values.length)+' / '+Math.max.apply(null,values)+' ms':'-'}}
function renderSummaryCard(title,value,sub){return '<div class="info-card"><div class="proxy-history-summary-title">'+esc(title)+'</div><div class="proxy-history-summary-value">'+esc(value||'-')+'</div><div class="proxy-history-summary-sub">'+esc(sub||'')+'</div></div>'}
function renderRecentEvents(samples){var recent=samples.slice(-6).reverse();if(!recent.length)return '<div class="proxy-history-event-list"><div class="proxy-history-event-item">当前时间范围没有历史数据</div></div>';return '<div class="proxy-history-event-list">'+recent.map(function(sample,index){return '<div class="proxy-history-event-item"><div class="proxy-history-event-header"><span>'+esc(fmtTime(sample&&sample.timestamp?sample.timestamp:0))+'</span><span>'+esc(getSampleStatusLabel(sample))+'</span></div><div class="proxy-history-event-sub"><span>'+esc(getSampleLatencyLabel(sample))+'</span><span>'+esc(sample&&sample.source?sample.source:'')+'</span></div></div>'}).join('')+'</div>'}
function renderMetricDetailCard(title,samples){var summary=summarizeLatencySamples(samples),latest=summary.latest;return '<div class="info-card"><div class="card-title">'+esc(title)+' 详细内容</div><div class="row"><span class="k">最新状态</span><span class="v">'+esc(getSampleStatusLabel(latest))+'</span></div><div class="row"><span class="k">最新延迟</span><span class="v">'+esc(getSampleLatencyLabel(latest))+'</span></div><div class="row"><span class="k">最新时间</span><span class="v">'+esc(fmtTime(latest&&latest.timestamp?latest.timestamp:0))+'</span></div><div class="row"><span class="k">成功率</span><span class="v">'+esc(summary.successRate)+'</span></div><div class="row"><span class="k">最后成功</span><span class="v">'+esc(fmtTime(summary.lastSuccess&&summary.lastSuccess.timestamp?summary.lastSuccess.timestamp:0))+'</span></div><div class="row"><span class="k">最后失败</span><span class="v">'+esc(fmtTime(summary.lastFailure&&summary.lastFailure.timestamp?summary.lastFailure.timestamp:0))+'</span></div>'+renderRecentEvents(summary.normalized)+'</div>'}
function renderChartCard(title,samples,width){if(historyModalState.loading&&(!Array.isArray(samples)||!samples.length))return '<div class="info-card"><div class="card-title">'+esc(title)+'</div><div class="latency-sparkline-placeholder">加载中</div></div>';return '<div class="info-card"><div class="card-title">'+esc(title)+'</div><div class="proxy-history-large-chart">'+createSparklineMarkup({samples:samples,label:title,width:width||960,height:260,showLabel:false,maxSamples:512,emptyText:historyModalState.loading?'加载中':'暂无'})+'</div></div>'}
function renderHistoryModalView(){if(!historyModalState.open)return;var target=historyModalState.target||{},range=historyModalState.requestWindow,visibleRange=getHistoryVisibleWindow(range),summaryHtml='',chartsHtml='',detailHtml='',windowLabel=range?fmtTime(range[0])+' - '+fmtTime(range[1]):'-',visibleWindowLabel=visibleRange?fmtTime(visibleRange[0])+' - '+fmtTime(visibleRange[1]):'-';$('historyWindowLabel').textContent=windowLabel;$('historyVisibleWindowLabel').textContent=visibleWindowLabel;$('historyViewportStart').value=String(Number(historyModalState.viewportStart)||0);$('historyViewportEnd').value=String(Number(historyModalState.viewportEnd)||100);$('historyViewportStartLabel').textContent=(Number(historyModalState.viewportStart)||0)+'%';$('historyViewportEndLabel').textContent=(Number(historyModalState.viewportEnd)||100)+'%';if(historyModalState.kind==='server'){var summary=summarizeLatencySamples(filterSamplesByVisibleWindow(historyModalState.serverSamples,visibleRange)),title=(target.server_name||target.id||'服务器')+' · 完整延迟历史';$('historyModalTitle').textContent=title;$('historyModalSubtitle').textContent='服务器 ID: '+(target.id||'-');summaryHtml+=renderSummaryCard('当前视窗',summary.count+' 点',visibleWindowLabel);summaryHtml+=renderSummaryCard('成功率',summary.successRate,summary.okCount+' 成功 / '+summary.failedCount+' 失败');summaryHtml+=renderSummaryCard('最新状态',getSampleStatusLabel(summary.latest),getSampleLatencyLabel(summary.latest));summaryHtml+=renderSummaryCard('最低 / 平均 / 最高',summary.minAvgMax,summary.lastSuccess?'最后成功 '+fmtTime(summary.lastSuccess.timestamp):'');chartsHtml=renderChartCard(title,summary.normalized,980);detailHtml=renderMetricDetailCard('服务器延迟',summary.normalized)}else{var metrics=normalizeProxyMetrics(historyModalState.proxyMetrics),visibleMetrics={tcp:filterSamplesByVisibleWindow(metrics.tcp,visibleRange),http:filterSamplesByVisibleWindow(metrics.http,visibleRange),udp:filterSamplesByVisibleWindow(metrics.udp,visibleRange)},proxyTitle=(target.name||'代理节点')+' · 完整延迟历史';$('historyModalTitle').textContent=proxyTitle;$('historyModalSubtitle').textContent=(target.type?String(target.type).toUpperCase():'-')+(target.group?' / '+target.group:'');summaryHtml+=renderSummaryCard('当前视窗',(visibleMetrics.tcp.length+visibleMetrics.http.length+visibleMetrics.udp.length)+' 点',visibleWindowLabel);historyMetricOrder.forEach(function(metric){var metricSummary=summarizeLatencySamples(visibleMetrics[metric]);summaryHtml+=renderSummaryCard(historyMetricLabels[metric],metricSummary.minAvgMax,metricSummary.okCount+' / '+metricSummary.count+' 成功')});chartsHtml=renderChartCard((target.name||'代理节点')+' · TCP 历史',visibleMetrics.tcp,980)+renderChartCard((target.name||'代理节点')+' · HTTP 历史',visibleMetrics.http,980)+renderChartCard((target.name||'代理节点')+' · UDP 历史',visibleMetrics.udp,980);detailHtml=historyMetricOrder.map(function(metric){return renderMetricDetailCard(historyMetricLabels[metric],visibleMetrics[metric])}).join('')}$('historySliderCard').style.display=range?'':'none';$('historySummaryGrid').innerHTML=summaryHtml;$('historyCharts').innerHTML=chartsHtml;$('historyDetailGrid').innerHTML=detailHtml;bindSparklineInteractions($('historyModalBackdrop'))}

function update(data){
  $('loading').style.display='none';
  $('content').style.display='block';
  var s=data.system_stats||{},cpu=s.cpu||{},mem=s.memory||{},disk=s.disk||{},net=s.network||{},proc=s.process||{},rt=s.go_runtime||{};

  $('cpuUsage').textContent=fmtPct(cpu.usage_percent);
  $('memUsage').textContent=fmtPct(mem.used_percent);
  $('diskUsage').textContent=fmtPct(disk.used_percent);
  $('onlineServers').textContent=(data.online_servers||0)+'/'+(data.total_servers||0);
  $('sessionCount').textContent=data.session_count||0;

  $('goroutineCount').textContent=rt.goroutine_count||0;
  $('topProcMem').textContent=fmtBytesShort(proc.memory_bytes);
  $('topProcCpu').textContent='CPU '+(proc.cpu_percent||0).toFixed(2)+'%';
  $('topHeap').textContent=fmtBytesShort(rt.heap_alloc);
  $('topHeapSys').textContent='sys '+fmtBytesShort(rt.heap_sys);
  $('topUptime').textContent=fmtDurationShort(s.uptime_seconds);
  $('topStartTime').textContent=s.start_time?'启动: '+fmtTimeShort(s.start_time):'';

  $('topNetUp').textContent=fmtBytesShort(net.bytes_sent);
  $('topNetDown').textContent=fmtBytesShort(net.bytes_recv);
  $('topNetSpeedUp').textContent=fmtSpeedShort(net.speed_out_bps);
  $('topNetSpeedDown').textContent=fmtSpeedShort(net.speed_in_bps);
  $('topNetPkts').textContent='↑'+fmtNum(net.packets_sent)+' ↓'+fmtNum(net.packets_recv);

  var badge=$('globalBadge');
  if(data.stats_error){badge.textContent='系统异常';badge.className='badge error'}
  else{badge.textContent='运行正常';badge.className='badge'}

  $('cpuPct').textContent=fmtPct(cpu.usage_percent);
  $('cpuBar').style.width=Math.min(cpu.usage_percent||0,100)+'%';
  $('cpuCores').textContent=(cpu.core_count||0)+' 核';
  $('procCpu').textContent=fmtPct(proc.cpu_percent);
  $('memPct').textContent=fmtPct(mem.used_percent);
  $('memBar').style.width=Math.min(mem.used_percent||0,100)+'%';
  $('memDetail').textContent=fmtBytes(mem.used)+' / '+fmtBytes(mem.total);
  $('diskPct').textContent=fmtPct(disk.used_percent);
  $('diskBar').style.width=Math.min(disk.used_percent||0,100)+'%';
  $('diskDetail').textContent=fmtBytes(disk.used)+' / '+fmtBytes(disk.total);
  $('netTotal').textContent=fmtBytes(net.bytes_sent)+' / '+fmtBytes(net.bytes_recv);
  $('netSpeed').textContent='↑ '+fmtSpeed(net.speed_out_bps)+' ↓ '+fmtSpeed(net.speed_in_bps);
  $('uptime').textContent=fmtDuration(s.uptime_seconds);
  $('procMem').textContent=fmtBytes(proc.memory_bytes)+' (PID '+(proc.pid||'-')+')';

  pageSnapshot={servers:data.servers||[],latency_history:data.latency_history||{}};
  resetSparklineStore();

  var servers=pageSnapshot.servers,latencyHistory=pageSnapshot.latency_history,sh='';
  if(!servers.length)sh='<tr class="empty-row"><td colspan="5">无数据</td></tr>';
  else servers.forEach(function(sv){
    var samples=latencyHistory[sv.id]||[],stopped=sv.status!=='running';
    var cls='st-offline',tx='离线';
    if(stopped){cls='st-stopped';tx='已停止'}else if(sv.online){cls='st-online';tx='在线'}
    sh+='<tr><td>'+esc(sv.id)+'</td><td class="'+cls+'">'+tx+'</td><td>'+fmtLatency(sv.latency)+'</td><td>'+createSparklineMarkup({samples:samples,label:(sv.server_name||sv.id)+' 延迟历史',width:138,height:34,showLabel:false,clickable:true,clickAction:{kind:'server',target:sv},emptyText:'暂无'})+'</td><td>'+esc(sv.server_name||'-')+'</td></tr>';
  });
  $('serverTable').innerHTML=sh;
  bindSparklineInteractions();
  if(historyModalState.open&&historyModalState.kind==='server'&&historyModalState.target){var currentServer=null;for(var i=0;i<servers.length;i++){if(servers[i]&&String(servers[i].id||'')===String(historyModalState.target.id||'')){currentServer=servers[i];break}}if(currentServer){historyModalState.target.status=currentServer.status||'';historyModalState.target.stopped=currentServer.status!=='running';historyModalState.target.online=currentServer.online===true;historyModalState.target.latency=Number(currentServer.latency||0);historyModalState.target.auto_ping_enabled=currentServer.auto_ping_enabled===true;historyModalState.target.next_auto_ping_at=Number(currentServer.next_auto_ping_at||0)}}
  if(historyModalState.open&&historyModalState.target){renderHistoryModalView()}

  var sess=data.active_sessions||[],ssh='';
  if(!sess.length)ssh='<tr class="empty-row"><td colspan="6">无活跃会话</td></tr>';
  else sess.forEach(function(s){
    ssh+='<tr><td>'+esc(s.server_id)+'</td><td>'+esc(s.display_name||'-')+'</td><td>'+esc(s.client_addr)+'</td><td>'+fmtBytes(s.bytes_up)+'</td><td>'+fmtBytes(s.bytes_down)+'</td><td>'+fmtDuration(s.duration_seconds)+'</td></tr>';
  });
  $('sessionTable').innerHTML=ssh;

  var hist=data.session_history||[],hh='';
  if(!hist.length)hh='<tr class="empty-row"><td colspan="7">无历史记录</td></tr>';
  else hist.forEach(function(h){
    var reason=h.status_reason||'';
    if(reason.length>30)reason=reason.substring(0,30)+'...';
    hh+='<tr><td>'+esc(h.display_name||'-')+'</td><td>'+esc(h.server_id)+'</td><td>'+stTag(h.status)+'</td><td title="'+esc(h.status_reason||'')+'">'+esc(reason||'-')+'</td><td>'+fmtTimeShort(h.start_time)+'</td><td>'+fmtBytesShort(h.bytes_up)+'</td><td>'+fmtBytesShort(h.bytes_down)+'</td></tr>';
  });
  $('historyTable').innerHTML=hh;

  // Update pagination state
  hTotal=data.history_total||0;
  hPage=data.history_page||1;
  hLimit=data.history_limit||10;
  hTotalPages=Math.max(1,Math.ceil(hTotal/hLimit));
  if(hPage>hTotalPages)hPage=hTotalPages;
  var start=(hPage-1)*hLimit+1,end=Math.min(hPage*hLimit,hTotal);
  $('historyPagerInfo').textContent=hTotal>0?('第 '+start+'-'+end+' 条，共 '+hTotal+' 条'):'暂无记录';
  $('hpFirst').disabled=hPage<=1;$('hpPrev').disabled=hPage<=1;
  $('hpNext').disabled=hPage>=hTotalPages;$('hpLast').disabled=hPage>=hTotalPages;
  // Render page buttons
  var pb='',maxBtns=5,half=Math.floor(maxBtns/2);
  var pStart=Math.max(1,hPage-half),pEnd=Math.min(hTotalPages,pStart+maxBtns-1);
  if(pEnd-pStart<maxBtns-1)pStart=Math.max(1,pEnd-maxBtns+1);
  for(var p=pStart;p<=pEnd;p++){
    pb+='<button class="pager-btn'+(p===hPage?' active':'')+'" onclick="goPage('+p+')">'+p+'</button>';
  }
  $('hpPages').innerHTML=pb;
  $('historyPageSize').value=String(hLimit);

  $('rtGoroutines').textContent=rt.goroutine_count||0;
  $('rtGC').textContent=rt.num_gc||0;
  $('rtHeapAlloc').textContent=fmtBytes(rt.heap_alloc);
  $('rtHeapSys').textContent=fmtBytes(rt.heap_sys);
  $('rtHeapInuse').textContent=fmtBytes(rt.heap_inuse);
  $('rtStackInuse').textContent=fmtBytes(rt.stack_inuse);
  $('updateTime').textContent='更新时间：'+fmtTime(data.generated_at);
  if(data.generated_at){var gt=new Date(data.generated_at);$('lastRefresh').textContent=P(gt.getHours())+':'+P(gt.getMinutes())+':'+P(gt.getSeconds());}
  renderRefreshCountdown();
}

function fetchData(){
  lastFetchStartedAt=Date.now();
  renderRefreshCountdown();
  var url='/api/web/index-api?history_limit='+hLimit+'&history_page='+hPage;
  fetch(url).then(function(r){return r.json()}).then(update).catch(function(e){
    console.error('Fetch error:',e);
    if($('content').style.display==='none'){$('loading').innerHTML='<div style="color:var(--red)">加载失败，请刷新页面</div>';}
  });
}
function handleManualRefresh(){fetchData()}
function goPage(p){p=Math.max(1,Math.min(p,hTotalPages));if(p!==hPage){hPage=p;fetchData()}}
function changePageSize(v){hLimit=parseInt(v)||10;hPage=1;fetchData()}
function initTheme(){var t=localStorage.getItem('wi-theme');if(t==='light')document.body.classList.add('light');updateThemeIcon()}
function toggleTheme(){document.body.classList.toggle('light');localStorage.setItem('wi-theme',document.body.classList.contains('light')?'light':'dark');updateThemeIcon()}
function updateThemeIcon(){var L=document.body.classList.contains('light');$('themeIcon').innerHTML=L?'<path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0a.996.996 0 000-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 000-1.41.996.996 0 00-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 000-1.41.996.996 0 00-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>':'<path d="M12 3a9 9 0 109 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 01-4.4 2.26 5.403 5.403 0 01-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/>'}
initTheme();
fetchData();
renderRefreshCountdown();
setInterval(renderRefreshCountdown,1000);
setInterval(fetchData,10000);
</script>
</body>
</html>`
