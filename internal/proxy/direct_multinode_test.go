package proxy

import (
	"errors"
	"strings"
	"testing"

	"mcpeserverproxy/internal/config"
)

// TestSelectFromNodeList_DirectTokenAsHealthyCandidate verifies that the literal
// "direct" token inside a comma-separated multi-node list is treated as a valid
// healthy candidate rather than being reported as a missing outbound.
//
// Regression: before the fix the user's config "direct,HK-01,HK-02" would return
// ErrOutboundNotFound: nodes not found: [direct] whenever HK-01/HK-02 were
// unreachable, because selectFromNodeList looked "direct" up in m.outbounds and
// never found it. Now it synthesizes a virtual healthy outbound instead.
func TestSelectFromNodeList_DirectTokenAsHealthyCandidate(t *testing.T) {
	mgr := NewOutboundManager(nil)

	// Seed a real outbound that exists but will likely be unhealthy on test
	// machines (server "bogus.invalid" never resolves) so selection falls
	// through to the synthetic direct slot via least-latency.
	realCfg := &config.ProxyOutbound{
		Name:     "node-a",
		Type:     config.ProtocolShadowsocks,
		Server:   "bogus.invalid",
		Port:     443,
		Enabled:  true,
		Method:   "aes-256-gcm",
		Password: "dummy",
	}
	if err := mgr.AddOutbound(realCfg); err != nil {
		t.Fatalf("seed outbound: %v", err)
	}

	selected, err := mgr.SelectOutboundWithFailover("direct,node-a", "round-robin", "tcp", nil)
	if err != nil {
		t.Fatalf("expected selection to succeed including direct, got: %v", err)
	}
	if selected == nil {
		t.Fatal("expected non-nil outbound")
	}

	// With round-robin, we should see both candidates over multiple calls.
	// Run a few iterations to ensure "direct" can be picked.
	seenDirect := IsDirectSelection(selected)
	for i := 0; i < 8 && !seenDirect; i++ {
		next, err := mgr.SelectOutboundWithFailover("direct,node-a", "round-robin", "tcp", nil)
		if err != nil {
			t.Fatalf("selection failed on iteration %d: %v", i, err)
		}
		if IsDirectSelection(next) {
			seenDirect = true
		}
	}
	if !seenDirect {
		t.Fatal("expected 'direct' to be selected at least once from round-robin pool")
	}
}

// TestSelectFromNodeList_DirectOnlyList verifies that a list containing only
// the "direct" token still resolves to a healthy selection. This covers the
// edge case where the user wants direct connection but writes it inside a
// multi-node list syntax (e.g. "direct," with a trailing comma that gets
// trimmed to just "direct").
func TestSelectFromNodeList_DirectOnlyList(t *testing.T) {
	mgr := NewOutboundManager(nil)
	selected, err := mgr.SelectOutboundWithFailover("direct,", "round-robin", "tcp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !IsDirectSelection(selected) {
		t.Fatalf("expected direct selection, got name=%q", selected.Name)
	}
}

// TestSelectFromNodeList_NoDirectOnlyMissing verifies the error message is
// NOT polluted with "direct" when the user did not include that token.
func TestSelectFromNodeList_NoDirectOnlyMissing(t *testing.T) {
	mgr := NewOutboundManager(nil)
	_, err := mgr.SelectOutboundWithFailover("missing-a,missing-b", "round-robin", "tcp", nil)
	if err == nil {
		t.Fatal("expected error for all-missing list")
	}
	if !errors.Is(err, ErrOutboundNotFound) {
		t.Fatalf("expected ErrOutboundNotFound, got: %v", err)
	}
	if strings.Contains(err.Error(), "direct") {
		t.Fatalf("error should not reference 'direct' when it wasn't requested: %v", err)
	}
}

// TestIsDirectSelection_NilSafe guards against a regression where helper would
// panic on nil input.
func TestIsDirectSelection_NilSafe(t *testing.T) {
	if IsDirectSelection(nil) {
		t.Fatal("nil outbound should not be a direct selection")
	}
	if IsDirectSelection(&config.ProxyOutbound{Name: "real-node"}) {
		t.Fatal("non-direct outbound should not be a direct selection")
	}
	if !IsDirectSelection(newDirectVirtualOutbound()) {
		t.Fatal("synthetic direct outbound should be a direct selection")
	}
}

func TestSelectFromNodeList_IgnoresMetadataLikeOutboundNames(t *testing.T) {
	mgr := NewOutboundManager(nil)
	metaCfg := &config.ProxyOutbound{
		Name:     "剩余流量：1 GB",
		Type:     config.ProtocolShadowsocks,
		Server:   "meta.example.com",
		Port:     443,
		Enabled:  true,
		Method:   "aes-256-gcm",
		Password: "dummy",
	}
	realCfg := &config.ProxyOutbound{
		Name:     "node-a",
		Type:     config.ProtocolShadowsocks,
		Server:   "real.example.com",
		Port:     443,
		Enabled:  true,
		Method:   "aes-256-gcm",
		Password: "dummy",
	}
	if err := mgr.AddOutbound(metaCfg); err != nil {
		t.Fatalf("seed metadata-like outbound: %v", err)
	}
	if err := mgr.AddOutbound(realCfg); err != nil {
		t.Fatalf("seed real outbound: %v", err)
	}

	selected, err := mgr.SelectOutboundWithFailover("剩余流量：1 GB,node-a", "round-robin", "tcp", nil)
	if err != nil {
		t.Fatalf("expected selection to succeed, got: %v", err)
	}
	if selected == nil || selected.Name != "node-a" {
		t.Fatalf("expected node-a after metadata filtering, got %+v", selected)
	}
}

func TestGetOutboundsByGroup_FiltersMetadataLikeNodes(t *testing.T) {
	mgr := NewOutboundManager(nil)
	metaCfg := &config.ProxyOutbound{
		Name:     "套餐到期：2099-01-01",
		Type:     config.ProtocolShadowsocks,
		Server:   "meta.example.com",
		Port:     443,
		Enabled:  true,
		Method:   "aes-256-gcm",
		Password: "dummy",
		Group:    "g1",
	}
	realCfg := &config.ProxyOutbound{
		Name:     "node-a",
		Type:     config.ProtocolShadowsocks,
		Server:   "real.example.com",
		Port:     443,
		Enabled:  true,
		Method:   "aes-256-gcm",
		Password: "dummy",
		Group:    "g1",
	}
	if err := mgr.AddOutbound(metaCfg); err != nil {
		t.Fatalf("seed metadata-like outbound: %v", err)
	}
	if err := mgr.AddOutbound(realCfg); err != nil {
		t.Fatalf("seed real outbound: %v", err)
	}

	nodes := mgr.GetOutboundsByGroup("g1")
	if len(nodes) != 1 || nodes[0] == nil || nodes[0].Name != "node-a" {
		t.Fatalf("expected only node-a in group listing, got %+v", nodes)
	}
}
