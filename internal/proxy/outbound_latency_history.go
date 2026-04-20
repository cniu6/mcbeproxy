package proxy

import (
	"strings"
	"time"
)

type OutboundLatencySample struct {
	Timestamp int64 `json:"timestamp"`
	LatencyMs int64 `json:"latency_ms"`
	OK        bool  `json:"ok"`
}

type outboundLatencyKey struct {
	name   string
	sortBy string
}

type outboundLatencyHistory struct {
	samples []OutboundLatencySample
}

type outboundLatencyOverrideRecorder interface {
	setOutboundLatencyAt(name, sortBy string, latencyMs int64, recordedAt time.Time, minIntervalOverrideMs int64)
}

func (h *outboundLatencyHistory) append(sample OutboundLatencySample, retention time.Duration, minIntervalMs int64, storageLimit int) {
	if h == nil {
		return
	}
	cutoff := time.UnixMilli(sample.Timestamp).Add(-retention).UnixMilli()
	filtered := h.filtered(cutoff)
	if len(filtered) > 0 && minIntervalMs > 0 {
		lastIndex := len(filtered) - 1
		if sample.Timestamp-filtered[lastIndex].Timestamp < minIntervalMs {
			filtered[lastIndex] = sample
			h.samples = filtered
			return
		}
	}
	filtered = append(filtered, sample)
	if storageLimit > 0 && len(filtered) > storageLimit {
		filtered = filtered[len(filtered)-storageLimit:]
	}
	h.samples = filtered
}

func (h *outboundLatencyHistory) filtered(cutoff int64) []OutboundLatencySample {
	if h == nil || len(h.samples) == 0 {
		return nil
	}
	result := make([]OutboundLatencySample, 0, len(h.samples))
	for _, sample := range h.samples {
		if sample.Timestamp < cutoff {
			continue
		}
		result = append(result, sample)
	}
	return result
}

func (h *outboundLatencyHistory) compact(cutoff int64) bool {
	if h == nil || len(h.samples) == 0 {
		return true
	}
	filtered := h.filtered(cutoff)
	if len(filtered) == 0 {
		h.samples = nil
		return true
	}
	h.samples = filtered
	return false
}

func (m *outboundManagerImpl) SetOutboundLatency(name, sortBy string, latencyMs int64) {
	m.setOutboundLatencyAt(name, sortBy, latencyMs, time.Now(), 0)
}

func (m *outboundManagerImpl) setOutboundLatencyAt(name, sortBy string, latencyMs int64, recordedAt time.Time, minIntervalOverrideMs int64) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	sortBy = normalizeSortBy(sortBy)
	if recordedAt.IsZero() {
		recordedAt = time.Now()
	}
	if latencyMs < 0 {
		latencyMs = 0
	}
	key := outboundLatencyKey{name: name, sortBy: sortBy}
	retention := m.latencyHistoryRetention()
	minIntervalMs := coalesceLatencyHistoryMinIntervalMs(m.latencyHistoryMinIntervalMs(), minIntervalOverrideMs)
	storageLimit := m.latencyHistoryStorageLimit()

	m.outboundLatencyMu.Lock()
	history := m.outboundHistory[key]
	if history == nil {
		history = &outboundLatencyHistory{}
		m.outboundHistory[key] = history
	}
	history.append(OutboundLatencySample{Timestamp: recordedAt.UnixMilli(), LatencyMs: latencyMs, OK: latencyMs > 0}, retention, minIntervalMs, storageLimit)
	m.outboundLatencyMu.Unlock()
}

func (m *outboundManagerImpl) GetOutboundLatencyHistory(name, sortBy string) []OutboundLatencySample {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	sortBy = normalizeSortBy(sortBy)
	key := outboundLatencyKey{name: name, sortBy: sortBy}
	cutoff := time.Now().Add(-m.latencyHistoryRetention()).UnixMilli()

	m.outboundLatencyMu.Lock()
	defer m.outboundLatencyMu.Unlock()

	history := m.outboundHistory[key]
	if history == nil {
		return nil
	}
	samples := history.filtered(cutoff)
	if len(samples) == 0 {
		delete(m.outboundHistory, key)
		return nil
	}
	if history.compact(cutoff) {
		delete(m.outboundHistory, key)
	}
	return samples
}

func (m *outboundManagerImpl) cleanupExpiredOutboundLatencyHistory(now time.Time) {
	cutoff := now.Add(-m.latencyHistoryRetention()).UnixMilli()
	m.outboundLatencyMu.Lock()
	defer m.outboundLatencyMu.Unlock()
	for key, history := range m.outboundHistory {
		if history == nil || history.compact(cutoff) {
			delete(m.outboundHistory, key)
		}
	}
}
