package api

import (
	"mcpeserverproxy/internal/config"
	"path/filepath"
	"testing"
)

func TestSensitiveDefaultsPreserveProviderOptions(t *testing.T) {
	mgr := config.NewProxyOutboundConfigManager(filepath.Join(t.TempDir(), "nodes.json"))
	original := &config.ProxyOutbound{Name: "wg", Type: config.ProtocolWireGuard, Server: "127.0.0.1", Port: 51820, ProviderOptions: map[string]interface{}{"private-key": "secret", "nested": map[string]interface{}{"value": "original"}}}
	if err := mgr.AddOutbound(original); err != nil {
		t.Fatal(err)
	}
	h := &ProxyOutboundHandler{configMgr: mgr}
	edited := &config.ProxyOutbound{Name: "wg", Type: config.ProtocolWireGuard}
	h.applySensitiveFieldDefaults("wg", edited)
	if edited.ProviderOptions["private-key"] != "secret" {
		t.Fatal("private options lost")
	}
	edited.ProviderOptions["nested"].(map[string]interface{})["value"] = "changed"
	saved, _ := mgr.GetOutbound("wg")
	if saved.ProviderOptions["nested"].(map[string]interface{})["value"] != "original" {
		t.Fatal("options alias stored configuration")
	}
	explicit := &config.ProxyOutbound{Type: config.ProtocolWireGuard, ProviderOptions: map[string]interface{}{}}
	h.applySensitiveFieldDefaults("wg", explicit)
	if len(explicit.ProviderOptions) != 0 {
		t.Fatal("explicit options overwritten")
	}
	changedType := &config.ProxyOutbound{Type: config.ProtocolSOCKS5}
	h.applySensitiveFieldDefaults("wg", changedType)
	if changedType.ProviderOptions != nil {
		t.Fatal("old protocol options carried to new type")
	}
}
