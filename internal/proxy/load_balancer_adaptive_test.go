package proxy

import (
	"sync"
	"testing"

	"mcpeserverproxy/internal/config"
)

func newAdaptiveNode(name string, latencyMs int64, conns int64) *config.ProxyOutbound {
	node := &config.ProxyOutbound{
		Name:         name,
		Type:         config.ProtocolShadowsocks,
		Server:       "example.com",
		Port:         1080,
		Enabled:      true,
		Method:       "aes-256-gcm",
		Password:     "test",
		UDPLatencyMs: latencyMs,
	}
	for i := int64(0); i < conns; i++ {
		node.IncrConnCount()
	}
	return node
}

// A single latency spike must not move traffic for one probe and immediately
// move it back: the EWMA keeps the previous node until the smoothed score
// actually crosses the competitor's.
func TestLoadBalancer_LeastLatencySmoothsSpike(t *testing.T) {
	lb := NewLoadBalancer()
	fast := newAdaptiveNode("fast", 50, 0)
	steady := newAdaptiveNode("steady", 100, 0)
	nodes := []*config.ProxyOutbound{fast, steady}

	if selected := lb.Select(nodes, config.LoadBalanceLeastLatency, config.LoadBalanceSortUDP, "g"); selected != fast {
		t.Fatalf("initial selection = %v, want fast", selected.Name)
	}

	// One slow probe for the fast node.
	fast.UDPLatencyMs = 400
	lb.Select(nodes, config.LoadBalanceLeastLatency, config.LoadBalanceSortUDP, "g")

	// Raw latency is back to normal, but the smoothed score still carries the
	// spike: the steady node should keep serving for a couple of rounds.
	fast.UDPLatencyMs = 50
	if selected := lb.Select(nodes, config.LoadBalanceLeastLatency, config.LoadBalanceSortUDP, "g"); selected != steady {
		t.Fatalf("first post-spike selection = %v, want steady", selected.Name)
	}
	if selected := lb.Select(nodes, config.LoadBalanceLeastLatency, config.LoadBalanceSortUDP, "g"); selected != steady {
		t.Fatalf("second post-spike selection = %v, want steady", selected.Name)
	}

	// Once the EWMA decays below the competitor, traffic returns to fast.
	if selected := lb.Select(nodes, config.LoadBalanceLeastLatency, config.LoadBalanceSortUDP, "g"); selected != fast {
		t.Fatalf("decayed selection = %v, want fast", selected.Name)
	}
}

func TestLoadBalancer_LeastLatencyPenalisesRecentError(t *testing.T) {
	lb := NewLoadBalancer()
	fast := newAdaptiveNode("fast", 40, 0)
	fast.SetLastError("connection reset")
	backup := newAdaptiveNode("backup", 60, 0)

	selected := lb.Select([]*config.ProxyOutbound{fast, backup}, config.LoadBalanceLeastLatency, config.LoadBalanceSortUDP, "g")
	if selected != backup {
		t.Fatalf("selection = %v, want backup (fast node carries an error)", selected.Name)
	}
}

func TestLoadBalancer_LeastConnectionsTieBreaksByLatency(t *testing.T) {
	lb := NewLoadBalancer()
	slow := newAdaptiveNode("slow", 200, 0)
	quick := newAdaptiveNode("quick", 40, 0)

	selected := lb.Select([]*config.ProxyOutbound{slow, quick}, config.LoadBalanceLeastConnections, config.LoadBalanceSortUDP, "g")
	if selected != quick {
		t.Fatalf("selection = %v, want quick when connection counts tie", selected.Name)
	}
}

func TestLoadBalancer_RoundRobinConcurrentIsBalanced(t *testing.T) {
	lb := NewLoadBalancer()
	nodes := []*config.ProxyOutbound{
		newAdaptiveNode("a", 10, 0),
		newAdaptiveNode("b", 10, 0),
		newAdaptiveNode("c", 10, 0),
	}

	const selections = 300
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := make(map[string]int, len(nodes))
	for i := 0; i < selections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			selected := lb.Select(nodes, config.LoadBalanceRoundRobin, config.LoadBalanceSortUDP, "g")
			if selected == nil {
				return
			}
			mu.Lock()
			counts[selected.Name]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, node := range nodes {
		if counts[node.Name] != selections/len(nodes) {
			t.Fatalf("node %s served %d times, want %d", node.Name, counts[node.Name], selections/len(nodes))
		}
	}
}

func TestLoadBalancer_ResetLatencyScores(t *testing.T) {
	lb := NewLoadBalancer()
	node := newAdaptiveNode("node", 500, 0)
	lb.Select([]*config.ProxyOutbound{node}, config.LoadBalanceLeastLatency, config.LoadBalanceSortUDP, "g")

	lb.ResetLatencyScores()
	node.UDPLatencyMs = 30
	if score := lb.effectiveLatency(node, config.LoadBalanceSortUDP); score != 30 {
		t.Fatalf("effective latency after reset = %v, want 30", score)
	}
}
