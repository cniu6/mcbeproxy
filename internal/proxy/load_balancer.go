// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/config"
)

const (
	// latencyEWMAAlpha is the smoothing factor for the per-node latency score.
	// A value below 0.5 keeps a single slow probe (or one fast outlier) from
	// immediately moving traffic off/onto a node, which is what caused players
	// to be shuffled between near-equal nodes on every auto-ping round.
	latencyEWMAAlpha = 0.35
	// latencySampleTTL drops scores for nodes that have not been measured
	// recently (deleted subscription nodes, long-disabled nodes).
	latencySampleTTL = 10 * time.Minute
	// latencyTableSoftLimit bounds the score map so dynamic group/node names
	// cannot grow it without limit.
	latencyTableSoftLimit = 2048
	// failurePenaltyMs is added to a node's score while it carries a last
	// error, so a node that just failed is only chosen when nothing better
	// exists. Selection filters normally remove unhealthy nodes already.
	failurePenaltyMs = 250.0
)

type latencySample struct {
	ewma     float64
	lastSeen time.Time
}

// LoadBalancer implements load balancing strategies for proxy outbound selection.
// Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7
type LoadBalancer struct {
	// roundRobin maps groupKey -> *atomic.Uint64 (next selection counter).
	// A sync.Map + per-key atomic removes the single global mutex that used to
	// serialize every round-robin selection across all groups.
	roundRobin sync.Map

	latencyMu   sync.Mutex
	latency     map[string]*latencySample
	selectCount uint64
}

// NewLoadBalancer creates a new LoadBalancer instance.
func NewLoadBalancer() *LoadBalancer {
	return &LoadBalancer{
		latency: make(map[string]*latencySample),
	}
}

// Select selects a node from the given list based on the specified strategy.
// Parameters:
//   - nodes: list of healthy nodes to select from
//   - strategy: load balance strategy (least-latency, round-robin, random, least-connections)
//   - sortBy: latency type for sorting (udp, tcp, http) - used by least-latency strategy
//   - groupKey: identifier for round-robin state tracking
//
// Returns nil if nodes is empty.
// Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7
func (lb *LoadBalancer) Select(nodes []*config.ProxyOutbound, strategy, sortBy, groupKey string) *config.ProxyOutbound {
	if len(nodes) == 0 {
		return nil
	}

	// Single node - no selection needed
	if len(nodes) == 1 {
		return nodes[0]
	}

	switch strategy {
	case config.LoadBalanceLeastLatency:
		return lb.selectLeastLatency(nodes, sortBy)
	case config.LoadBalanceRoundRobin:
		return lb.selectRoundRobin(nodes, groupKey)
	case config.LoadBalanceRandom:
		return lb.selectRandom(nodes)
	case config.LoadBalanceLeastConnections:
		return lb.selectLeastConnections(nodes)
	default:
		// Default to least-latency
		return lb.selectLeastLatency(nodes, sortBy)
	}
}

// nodeLatencyMs returns the raw last-measured latency for a node.
func nodeLatencyMs(node *config.ProxyOutbound, sortBy string) int64 {
	if node == nil {
		return 0
	}
	switch sortBy {
	case config.LoadBalanceSortTCP:
		return node.GetTCPLatencyMs()
	case config.LoadBalanceSortHTTP:
		return node.GetHTTPLatencyMs()
	case config.LoadBalanceSortUDP:
		fallthrough
	default:
		return node.GetUDPLatencyMs()
	}
}

func latencyKey(nodeName, sortBy string) string {
	return nodeName + "\x00" + sortBy
}

// observeLatencyLocked folds a fresh measurement into the per-node EWMA score.
// Caller must hold lb.latencyMu.
func (lb *LoadBalancer) observeLatencyLocked(nodeName, sortBy string, rawMs int64, now time.Time) float64 {
	key := latencyKey(nodeName, sortBy)
	sample := lb.latency[key]
	if sample == nil || sample.ewma <= 0 {
		sample = &latencySample{ewma: float64(rawMs)}
		lb.latency[key] = sample
	} else {
		sample.ewma = latencyEWMAAlpha*float64(rawMs) + (1-latencyEWMAAlpha)*sample.ewma
	}
	sample.lastSeen = now
	lb.selectCount++
	if len(lb.latency) > latencyTableSoftLimit || lb.selectCount%256 == 0 {
		lb.pruneLatencyLocked(now)
	}
	return sample.ewma
}

func (lb *LoadBalancer) pruneLatencyLocked(now time.Time) {
	cutoff := now.Add(-latencySampleTTL)
	for key, sample := range lb.latency {
		if sample == nil || sample.lastSeen.Before(cutoff) {
			delete(lb.latency, key)
		}
	}
}

// effectiveLatency returns the smoothed score, feeding the current raw value
// into the EWMA. Returns 0 when the node has never been measured.
func (lb *LoadBalancer) effectiveLatency(node *config.ProxyOutbound, sortBy string) float64 {
	raw := nodeLatencyMs(node, sortBy)
	if raw <= 0 {
		return 0
	}
	lb.latencyMu.Lock()
	defer lb.latencyMu.Unlock()
	return lb.observeLatencyLocked(node.Name, sortBy, raw, time.Now())
}

// selectLeastLatency selects the node with the lowest smoothed latency.
//
// Unlike the previous raw-minimum scan, a single noisy probe no longer moves
// all traffic: the EWMA damps it, nodes carrying a recent error are penalised,
// and equal scores are broken by the active connection count so near-equal
// nodes share load instead of always resolving to the first one.
// Requirements: 2.1, 2.5, 2.6, 2.7
func (lb *LoadBalancer) selectLeastLatency(nodes []*config.ProxyOutbound, sortBy string) *config.ProxyOutbound {
	if len(nodes) == 0 {
		return nil
	}

	now := time.Now()
	lb.latencyMu.Lock()
	defer lb.latencyMu.Unlock()

	var selected *config.ProxyOutbound
	var bestScore float64
	var bestConns int64
	hasData := false

	for _, node := range nodes {
		raw := nodeLatencyMs(node, sortBy)
		// Skip nodes with no latency data (0 means not measured)
		if raw <= 0 {
			continue
		}
		hasData = true

		score := lb.observeLatencyLocked(node.Name, sortBy, raw, now)
		if node.GetLastError() != "" {
			score += failurePenaltyMs
		}
		conns := node.GetConnCount()
		if selected == nil || score < bestScore || (score == bestScore && conns < bestConns) {
			selected = node
			bestScore = score
			bestConns = conns
		}
	}

	// If no node has latency data, return the first node (historic contract).
	if !hasData {
		return nodes[0]
	}
	if selected == nil {
		return nodes[0]
	}
	return selected
}

// selectRoundRobin selects nodes in sequential order, cycling through all nodes.
// Requirements: 2.2
func (lb *LoadBalancer) roundRobinCounter(groupKey string) *atomic.Uint64 {
	if value, ok := lb.roundRobin.Load(groupKey); ok {
		return value.(*atomic.Uint64)
	}
	counter := &atomic.Uint64{}
	actual, _ := lb.roundRobin.LoadOrStore(groupKey, counter)
	return actual.(*atomic.Uint64)
}

func (lb *LoadBalancer) selectRoundRobin(nodes []*config.ProxyOutbound, groupKey string) *config.ProxyOutbound {
	if len(nodes) == 0 {
		return nil
	}

	// One atomic increment per selection: no shared mutex, and node-list
	// changes are handled by the modulo instead of resetting the counter.
	index := int(lb.roundRobinCounter(groupKey).Add(1)-1) % len(nodes)
	return nodes[index]
}

// selectRandom randomly selects a node from the list.
// Requirements: 2.3
func (lb *LoadBalancer) selectRandom(nodes []*config.ProxyOutbound) *config.ProxyOutbound {
	if len(nodes) == 0 {
		return nil
	}

	return nodes[rand.IntN(len(nodes))]
}

// selectLeastConnections selects the node with the fewest active connections.
// Requirements: 2.4
func (lb *LoadBalancer) selectLeastConnections(nodes []*config.ProxyOutbound) *config.ProxyOutbound {
	if len(nodes) == 0 {
		return nil
	}

	var selected *config.ProxyOutbound
	var minConns int64
	var minLatency float64

	for _, node := range nodes {
		connCount := node.GetConnCount()
		// Equal connection counts are common right after a reload; break the
		// tie by the smoothed latency so the fastest node absorbs the burst.
		latency := lb.effectiveLatency(node, config.LoadBalanceSortUDP)
		if latency <= 0 {
			latency = math.MaxFloat64
		}

		if selected == nil || connCount < minConns || (connCount == minConns && latency < minLatency) {
			minConns = connCount
			minLatency = latency
			selected = node
		}
	}

	return selected
}

// ResetRoundRobin resets the round-robin index for a specific group.
// This is useful when the node list changes.
func (lb *LoadBalancer) ResetRoundRobin(groupKey string) {
	lb.roundRobin.Delete(groupKey)
}

// ResetAllRoundRobin resets all round-robin indices.
func (lb *LoadBalancer) ResetAllRoundRobin() {
	lb.roundRobin.Clear()
}

// GetRoundRobinIndex returns the next round-robin index for a group (for testing).
func (lb *LoadBalancer) GetRoundRobinIndex(groupKey string) int {
	value, ok := lb.roundRobin.Load(groupKey)
	if !ok {
		return 0
	}
	return int(value.(*atomic.Uint64).Load())
}

// ResetLatencyScores drops all smoothed latency samples.
func (lb *LoadBalancer) ResetLatencyScores() {
	lb.latencyMu.Lock()
	lb.latency = make(map[string]*latencySample)
	lb.latencyMu.Unlock()
}
