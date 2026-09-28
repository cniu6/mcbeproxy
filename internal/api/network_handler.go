package api

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/netroute"
	"mcpeserverproxy/internal/proxy"
)

// SetNetworkStore wires the persisted network settings (interface + rules).
func (a *APIServer) SetNetworkStore(store *netroute.Store) {
	a.networkStore = store
}

type networkConfigDTO struct {
	netroute.Config
	// Resolved OS interface name when Interface was given as an IP.
	ResolvedInterface string `json:"resolved_interface,omitempty"`
	File              string `json:"file,omitempty"`
}

func (a *APIServer) getNetworkConfig(c *gin.Context) {
	cfg := netroute.Current()
	if cfg.Rules == nil {
		cfg.Rules = []netroute.Rule{}
	}
	dto := networkConfigDTO{Config: cfg}
	if cfg.Interface != "" {
		dto.ResolvedInterface = netroute.InterfaceName(cfg.Interface)
	}
	if a.networkStore != nil {
		dto.File = a.networkStore.Path()
	}
	respondSuccess(c, dto)
}

func (a *APIServer) updateNetworkConfig(c *gin.Context) {
	if a.networkStore == nil {
		respondError(c, http.StatusServiceUnavailable, "Network settings unavailable", "network store not initialized")
		return
	}
	var cfg netroute.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	saved, err := a.networkStore.Save(cfg)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Invalid network settings", err.Error())
		return
	}
	respondSuccessWithMsg(c, "已保存并生效", saved)
}

type networkInterfacesDTO struct {
	Interfaces []netroute.Interface `json:"interfaces"`
	FetchedAt  time.Time            `json:"fetched_at"`
	TTLMs      int64                `json:"ttl_ms"`
	CostMs     float64              `json:"cost_ms"`
	Error      string               `json:"error,omitempty"`
}

// getNetworkInterfaces serves the cached interface list. ?refresh=1 forces a
// re-scan (rate limited inside netroute); the cache TTL adapts to how long
// enumeration takes on this machine.
func (a *APIServer) getNetworkInterfaces(c *gin.Context) {
	force := c.Query("refresh") == "1" || strings.EqualFold(c.Query("refresh"), "true")
	list, at, err := netroute.ListInterfaces(force)
	ttl, cost := netroute.CacheInfo()
	dto := networkInterfacesDTO{
		Interfaces: list,
		FetchedAt:  at,
		TTLMs:      ttl.Milliseconds(),
		CostMs:     float64(cost.Microseconds()) / 1000,
	}
	if dto.Interfaces == nil {
		dto.Interfaces = []netroute.Interface{}
	}
	if err != nil {
		dto.Error = err.Error()
	}
	respondSuccess(c, dto)
}

type networkTestRequest struct {
	Target string `json:"target"` // "host:port", "host" or "[v6]:port"
	Host   string `json:"host"`
	Port   int    `json:"port"`
	// Probe, when "udp" or "tcp", also connects along the decided route:
	// udp sends a Minecraft (RakNet) ping, tcp opens a connection.
	Probe string `json:"probe,omitempty"`
}

type networkTestResult struct {
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Decision netroute.Decision `json:"decision"`
	// ResolvedInterface is the OS name the socket would be pinned to.
	ResolvedInterface string              `json:"resolved_interface,omitempty"`
	Probe             *networkProbeResult `json:"probe,omitempty"`
}

type networkProbeResult struct {
	Protocol   string `json:"protocol"`
	Via        string `json:"via"` // "direct" or the outbound node
	Success    bool   `json:"success"`
	LatencyMs  int64  `json:"latency_ms"`
	ServerName string `json:"server_name,omitempty"`
	Players    string `json:"players,omitempty"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// testNetworkRoute shows which rule a destination hits, without dialing.
func (a *APIServer) testNetworkRoute(c *gin.Context) {
	var req networkTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	host, port := strings.TrimSpace(req.Host), req.Port
	if t := strings.TrimSpace(req.Target); t != "" {
		host = t
		if h, p, ok := splitTarget(t); ok {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}
	if host == "" {
		respondError(c, http.StatusBadRequest, "Invalid request", "target or host is required")
		return
	}
	d := netroute.Decide(host, port)
	res := networkTestResult{Host: host, Port: port, Decision: d}
	if d.Interface != "" {
		res.ResolvedInterface = netroute.InterfaceName(d.Interface)
	}
	if probe := strings.ToLower(strings.TrimSpace(req.Probe)); probe == "udp" || probe == "tcp" {
		res.Probe = a.probeNetworkRoute(c.Request.Context(), probe, host, port, d)
	}
	respondSuccess(c, res)
}

// splitTarget accepts host:port, [v6]:port; a bare IPv6 has no port.
func splitTarget(t string) (host, port string, ok bool) {
	if strings.HasPrefix(t, "[") {
		if end := strings.Index(t, "]"); end > 0 {
			rest := t[end+1:]
			return t[1:end], strings.TrimPrefix(rest, ":"), strings.HasPrefix(rest, ":")
		}
	}
	if strings.Count(t, ":") == 1 {
		h, p, _ := strings.Cut(t, ":")
		return h, p, true
	}
	return t, "", false
}

// probeNetworkRoute really connects to host:port the way the rules decide:
// direct sockets are pinned to the decided interface by netroute; a proxy
// action goes through its outbound node.
func (a *APIServer) probeNetworkRoute(parent context.Context, proto, host string, port int, d netroute.Decision) *networkProbeResult {
	r := &networkProbeResult{Protocol: proto, Via: "direct"}
	if d.Action == netroute.ActionBlock {
		r.Error = "blocked by rule"
		return r
	}
	if port <= 0 {
		if proto != "udp" {
			r.Error = "port is required for tcp"
			return r
		}
		port = 19132
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	node := ""
	if d.Action == netroute.ActionProxy && d.Outbound != "" {
		node, r.Via = d.Outbound, d.Outbound
		if strings.HasPrefix(node, "@") || strings.Contains(node, ",") {
			r.Error = "rule routes to a group/list; test a single node on the outbound page"
			return r
		}
	}
	var mgr proxy.OutboundManager
	if a.proxyOutboundHandler != nil {
		mgr = a.proxyOutboundHandler.outboundMgr
	}
	if node != "" && mgr == nil {
		r.Error = "outbound manager not available"
		return r
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	start := time.Now()

	if proto == "tcp" {
		var conn net.Conn
		var err error
		if node != "" {
			td, ok := mgr.(interface {
				DialTCPContext(ctx context.Context, outboundName, destination string) (net.Conn, error)
			})
			if !ok {
				r.Error = "tcp through outbound not supported"
				return r
			}
			conn, err = td.DialTCPContext(ctx, node, address)
		} else {
			conn, err = netroute.DialContext(ctx, &net.Dialer{}, "tcp", address)
		}
		r.LatencyMs = time.Since(start).Milliseconds()
		if err != nil {
			r.Error = err.Error()
			return r
		}
		_ = conn.Close()
		r.Success = true
		return r
	}

	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	var pc net.PacketConn
	if node != "" {
		pc, err = mgr.DialPacketConn(ctx, node, address)
	} else {
		pc, err = netroute.ListenUDP(address)
	}
	if err != nil {
		r.LatencyMs = time.Since(start).Milliseconds()
		r.Error = err.Error()
		return r
	}
	defer pc.Close()
	ping := performMCBEPing(ctx, pc, udpAddr, 3*time.Second)
	r.Success, r.LatencyMs, r.Error = ping.Success, ping.LatencyMs, ping.Error
	r.ServerName, r.Players, r.Version = ping.ServerName, ping.Players, ping.Version
	if !r.Success && r.Error != "" {
		r.Error += " (UDP blocked on this route, or not a Minecraft server)"
	}
	return r
}
