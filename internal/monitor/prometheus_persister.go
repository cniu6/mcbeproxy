package monitor

import "github.com/prometheus/client_golang/prometheus"

// SessionPersisterSnapshot is what the session persistence pipeline reports.
type SessionPersisterSnapshot struct {
	Enqueued, Written, InlineWrites, Panics int64
	QueueDepth                              int
}

// RegisterSessionPersister exports the session persistence counters. stats is
// called at scrape time (atomic loads only).
func (pm *PrometheusMetrics) RegisterSessionPersister(stats func() SessionPersisterSnapshot) {
	if pm == nil || stats == nil {
		return
	}
	counter := func(name, help string, v func(SessionPersisterSnapshot) int64) prometheus.Collector {
		return prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help},
			func() float64 { return float64(v(stats())) })
	}
	pm.Registry.MustRegister(
		counter("mcpe_session_persist_enqueued_total", "Ended sessions queued for database persistence",
			func(s SessionPersisterSnapshot) int64 { return s.Enqueued }),
		counter("mcpe_session_persist_written_total", "Sessions written to the database",
			func(s SessionPersisterSnapshot) int64 { return s.Written }),
		counter("mcpe_session_persist_inline_total", "Sessions written inline because the persist queue was full (database too slow)",
			func(s SessionPersisterSnapshot) int64 { return s.InlineWrites }),
		counter("mcpe_session_persist_panics_total", "Session writes that panicked and were dropped",
			func(s SessionPersisterSnapshot) int64 { return s.Panics }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "mcpe_session_persist_queue_depth", Help: "Sessions waiting to be written"},
			func() float64 { return float64(stats().QueueDepth) }),
	)
}
