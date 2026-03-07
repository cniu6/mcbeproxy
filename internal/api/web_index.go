package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
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
	data        []byte      // cached JSON response
	updatedAt   time.Time   // when cache was last refreshed
	requestedAt time.Time   // when last request came in
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
	type pingResult struct {
		id   string
		info map[string]interface{}
	}
	results := make(chan pingResult, len(servers))
	var pingWG sync.WaitGroup
	for _, srv := range servers {
		s := srv
		pingWG.Add(1)
		go func() {
			defer pingWG.Done()
			info := a.buildServerPingFromConfig(s)
			results <- pingResult{id: s.ID, info: info}
		}()
	}
	go func() {
		pingWG.Wait()
		close(results)
	}()

	pings := make(map[string]map[string]interface{}, len(servers))
	for res := range results {
		pings[res.id] = res.info
	}

	wg.Wait()

	// Build filtered server list (no IP/port/sensitive fields, no "来源")
	type publicServerDTO struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		Latency    int64  `json:"latency"`
		Online     bool   `json:"online"`
		ServerName string `json:"server_name"`
		Stopped    bool   `json:"stopped"`
	}
	onlineCount := 0
	totalCount := len(servers)
	publicServers := make([]publicServerDTO, 0, len(servers))
	for _, srv := range servers {
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
			ID:         srv.ID,
			Status:     srv.Status,
			Latency:    latency,
			Online:     online,
			ServerName: serverName,
			Stopped:    stopped,
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


const webIndexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Minecraft 服务器状态</title>
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
      <button class="btn" onclick="fetchData()" title="立即刷新"><svg viewBox="0 0 24 24"><path d="M17.65 6.35A7.958 7.958 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>刷新</button>
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
        <table><thead><tr><th>服务器ID</th><th>状态</th><th>延迟</th><th>名称</th></tr></thead>
        <tbody id="serverTable"><tr class="empty-row"><td colspan="4">无数据</td></tr></tbody></table>
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

var statusMap={'disconnected':['正常断开','st-tag-ok'],'blacklist':['黑名单','st-tag-err'],'whitelist':['白名单拒绝','st-tag-warn'],'auth_failed':['验证失败','st-tag-err'],'kicked':['被踢出','st-tag-warn']};
function stTag(st){var info=statusMap[st||'disconnected']||[st||'断开','st-tag-def'];return '<span class="st-tag '+info[1]+'">'+esc(info[0])+'</span>'}

// Pagination state
var hPage=1,hLimit=10,hTotal=0,hTotalPages=1;

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

  var servers=data.servers||[],sh='';
  if(!servers.length)sh='<tr class="empty-row"><td colspan="4">无数据</td></tr>';
  else servers.forEach(function(sv){
    var cls='st-offline',tx='离线';
    if(sv.stopped){cls='st-stopped';tx='已停止'}else if(sv.online){cls='st-online';tx='在线'}
    sh+='<tr><td>'+esc(sv.id)+'</td><td class="'+cls+'">'+tx+'</td><td>'+fmtLatency(sv.latency)+'</td><td>'+esc(sv.server_name||'-')+'</td></tr>';
  });
  $('serverTable').innerHTML=sh;

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
}

function fetchData(){
  var url='/api/web/index-api?history_limit='+hLimit+'&history_page='+hPage;
  fetch(url).then(function(r){return r.json()}).then(update).catch(function(e){
    console.error('Fetch error:',e);
    if($('content').style.display==='none'){$('loading').innerHTML='<div style="color:var(--red)">加载失败，请刷新页面</div>';}
  });
}
function goPage(p){p=Math.max(1,Math.min(p,hTotalPages));if(p!==hPage){hPage=p;fetchData()}}
function changePageSize(v){hLimit=parseInt(v)||10;hPage=1;fetchData()}
function initTheme(){var t=localStorage.getItem('wi-theme');if(t==='light')document.body.classList.add('light');updateThemeIcon()}
function toggleTheme(){document.body.classList.toggle('light');localStorage.setItem('wi-theme',document.body.classList.contains('light')?'light':'dark');updateThemeIcon()}
function updateThemeIcon(){var L=document.body.classList.contains('light');$('themeIcon').innerHTML=L?'<path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0a.996.996 0 000-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 000-1.41.996.996 0 00-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 000-1.41.996.996 0 00-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>':'<path d="M12 3a9 9 0 109 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 01-4.4 2.26 5.403 5.403 0 01-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/>'}
initTheme();
fetchData();
setInterval(fetchData,10000);
</script>
</body>
</html>`
