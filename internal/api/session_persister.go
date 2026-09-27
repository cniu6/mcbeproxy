package api

import (
	"github.com/gin-gonic/gin"

	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/proxy"
)

// sessionPersisterStatsProvider is implemented by *proxy.ProxyServer.
type sessionPersisterStatsProvider interface {
	SessionPersisterStats() proxy.SessionPersisterStats
}

// registerSessionPersisterMetrics exports the persister counters to /metrics.
func (a *APIServer) registerSessionPersisterMetrics() {
	provider, ok := a.proxyController.(sessionPersisterStatsProvider)
	if !ok || a.promMetrics == nil {
		return
	}
	a.promMetrics.RegisterSessionPersister(func() monitor.SessionPersisterSnapshot {
		s := provider.SessionPersisterStats()
		return monitor.SessionPersisterSnapshot{Enqueued: s.Enqueued, Written: s.Written,
			InlineWrites: s.InlineWrites, Panics: s.Panics, QueueDepth: s.QueueDepth}
	})
}

// getSessionPersisterStats returns the session persistence counters.
// GET /api/debug/session-persister
func (a *APIServer) getSessionPersisterStats(c *gin.Context) {
	provider, ok := a.proxyController.(sessionPersisterStatsProvider)
	if !ok {
		respondSuccess(c, proxy.SessionPersisterStats{})
		return
	}
	respondSuccess(c, provider.SessionPersisterStats())
}
