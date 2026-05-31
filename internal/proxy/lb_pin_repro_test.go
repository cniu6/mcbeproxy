package proxy

import (
	"testing"

	"mcpeserverproxy/internal/config"
)

func seedLBTestManager(t *testing.T, names ...string) *outboundManagerImpl {
	t.Helper()
	mgr := NewOutboundManager(nil).(*outboundManagerImpl)
	for _, name := range names {
		cfg := &config.ProxyOutbound{
			Name:     name,
			Type:     config.ProtocolShadowsocks,
			Server:   "bogus.invalid",
			Port:     443,
			Enabled:  true,
			Method:   "aes-256-gcm",
			Password: "dummy",
		}
		if err := mgr.AddOutbound(cfg); err != nil {
			t.Fatalf("seed outbound %s: %v", name, err)
		}
	}
	return mgr
}

// TestRoundRobinIgnoresAutoPin verifies the load-balance fix: an automatic pin
// (as set by auto-ping after picking a "best" node) must NOT override a
// round-robin strategy, otherwise traffic always sticks to the pinned node and
// load balancing never rotates.
func TestRoundRobinIgnoresAutoPin(t *testing.T) {
	mgr := seedLBTestManager(t, "node-a", "node-b")
	const sel = "port:test"
	mgr.SetServerSelectedNode(sel, "node-a") // automatic pin

	seen := map[string]int{}
	for i := 0; i < 12; i++ {
		out, err := mgr.SelectOutboundWithFailoverForServer(sel, "node-a,node-b", config.LoadBalanceRoundRobin, "tcp", nil)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		seen[out.Name]++
	}
	if len(seen) < 2 {
		t.Fatalf("round-robin did not rotate past auto-pin: %v", seen)
	}
}

// TestManualPinHonoredForRoundRobin verifies that an explicit manual switch is
// still honored even under round-robin, so a temporary operator override sticks.
func TestManualPinHonoredForRoundRobin(t *testing.T) {
	mgr := seedLBTestManager(t, "node-a", "node-b")
	const sel = "port:test"
	mgr.SetServerSelectedNodeManual(sel, "node-b") // manual pin

	for i := 0; i < 6; i++ {
		out, err := mgr.SelectOutboundWithFailoverForServer(sel, "node-a,node-b", config.LoadBalanceRoundRobin, "tcp", nil)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if out.Name != "node-b" {
			t.Fatalf("manual pin not honored under round-robin: got %s", out.Name)
		}
	}
}

// TestRoundRobinGroupRotation verifies round-robin over a group rotates across
// all members deterministically (group membership is stored in a map, whose
// iteration order is otherwise random).
func TestRoundRobinGroupRotation(t *testing.T) {
	mgr := seedLBTestManager(t)
	for _, name := range []string{"g-a", "g-b", "g-c"} {
		cfg := &config.ProxyOutbound{
			Name:     name,
			Group:    "grp",
			Type:     config.ProtocolShadowsocks,
			Server:   "bogus.invalid",
			Port:     443,
			Enabled:  true,
			Method:   "aes-256-gcm",
			Password: "dummy",
		}
		if err := mgr.AddOutbound(cfg); err != nil {
			t.Fatalf("seed group outbound %s: %v", name, err)
		}
	}

	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		out, err := mgr.SelectOutboundWithFailoverForServer("port:grp", "@grp", config.LoadBalanceRoundRobin, "tcp", nil)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		seen[out.Name]++
	}
	if len(seen) != 3 {
		t.Fatalf("expected round-robin to hit all 3 group nodes, got %v", seen)
	}
}
