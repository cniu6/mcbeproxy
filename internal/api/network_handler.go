package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/netroute"
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
}

type networkTestResult struct {
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Decision netroute.Decision `json:"decision"`
	// ResolvedInterface is the OS name the socket would be pinned to.
	ResolvedInterface string `json:"resolved_interface,omitempty"`
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
