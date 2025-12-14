package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// genUniqueOutboundList generates a list of valid ProxyOutbound configurations with unique names
func genUniqueOutboundList() gopter.Gen {
	return gen.IntRange(0, 10).FlatMap(func(count any) gopter.Gen {
		n := count.(int)
		if n == 0 {
			return gen.Const([]*ProxyOutbound{})
		}
		return gen.SliceOfN(n, genValidProxyOutbound()).Map(func(outbounds []*ProxyOutbound) []*ProxyOutbound {
			// Ensure unique names by appending index
			seen := make(map[string]bool)
			result := make([]*ProxyOutbound, 0, len(outbounds))
			for i, o := range outbounds {
				clone := o.Clone()
				// Make name unique
				baseName := clone.Name
				if baseName == "" {
					baseName = "outbound"
				}
				uniqueName := fmt.Sprintf("%s_%d", baseName, i)
				for seen[uniqueName] {
					i++
					uniqueName = fmt.Sprintf("%s_%d", baseName, i)
				}
				clone.Name = uniqueName
				seen[uniqueName] = true
				result = append(result, clone)
			}
			return result
		})
	}, reflect.TypeOf([]*ProxyOutbound{}))
}

// **Feature: singbox-outbound-proxy, Property 9: Config file loading preserves all outbounds**
// **Validates: Requirements 5.1**
//
// *For any* valid JSON configuration file containing proxy outbounds,
// loading the file should result in all outbounds being available in the ProxyOutboundConfigManager.
func TestProperty9_ConfigFileLoadingPreservesAllOutbounds(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("loading config file preserves all outbounds", prop.ForAll(
		func(outbounds []*ProxyOutbound) bool {
			// Create a temporary directory for the test
			tmpDir, err := os.MkdirTemp("", "proxy_outbound_test")
			if err != nil {
				t.Logf("Failed to create temp dir: %v", err)
				return false
			}
			defer os.RemoveAll(tmpDir)

			configPath := filepath.Join(tmpDir, "proxy_outbounds.json")

			// Write outbounds to JSON file
			data, err := json.MarshalIndent(outbounds, "", "  ")
			if err != nil {
				t.Logf("Failed to marshal outbounds: %v", err)
				return false
			}
			if err := os.WriteFile(configPath, data, 0644); err != nil {
				t.Logf("Failed to write config file: %v", err)
				return false
			}

			// Create manager and load
			manager := NewProxyOutboundConfigManager(configPath)
			if err := manager.Load(); err != nil {
				t.Logf("Failed to load config: %v", err)
				return false
			}

			// Verify all outbounds are loaded
			if manager.OutboundCount() != len(outbounds) {
				t.Logf("Count mismatch: expected %d, got %d", len(outbounds), manager.OutboundCount())
				return false
			}

			// Verify each outbound is present and equal
			for _, original := range outbounds {
				loaded, ok := manager.GetOutbound(original.Name)
				if !ok {
					t.Logf("Outbound %s not found after loading", original.Name)
					return false
				}
				if !original.Equal(loaded) {
					t.Logf("Outbound %s mismatch:\nOriginal: %+v\nLoaded: %+v", original.Name, original, loaded)
					return false
				}
			}

			return true
		},
		genUniqueOutboundList(),
	))

	properties.TestingRun(t)
}

// **Feature: singbox-outbound-proxy, Property 10: Config persistence round-trip**
// **Validates: Requirements 5.4**
//
// *For any* set of ProxyOutbound configurations, saving to file and then loading
// should produce an equivalent set of configurations.
func TestProperty10_ConfigPersistenceRoundTrip(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("save then load preserves all outbounds", prop.ForAll(
		func(outbounds []*ProxyOutbound) bool {
			// Create a temporary directory for the test
			tmpDir, err := os.MkdirTemp("", "proxy_outbound_test")
			if err != nil {
				t.Logf("Failed to create temp dir: %v", err)
				return false
			}
			defer os.RemoveAll(tmpDir)

			configPath := filepath.Join(tmpDir, "proxy_outbounds.json")

			// Create first manager and add all outbounds
			manager1 := NewProxyOutboundConfigManager(configPath)
			// Initialize with empty file first
			if err := os.WriteFile(configPath, []byte("[]"), 0644); err != nil {
				t.Logf("Failed to create initial config file: %v", err)
				return false
			}
			if err := manager1.Load(); err != nil {
				t.Logf("Failed to load initial config: %v", err)
				return false
			}

			// Add all outbounds
			for _, o := range outbounds {
				if err := manager1.AddOutbound(o); err != nil {
					t.Logf("Failed to add outbound %s: %v", o.Name, err)
					return false
				}
			}

			// Create second manager and load from the same file
			manager2 := NewProxyOutboundConfigManager(configPath)
			if err := manager2.Load(); err != nil {
				t.Logf("Failed to load config in second manager: %v", err)
				return false
			}

			// Verify counts match
			if manager2.OutboundCount() != len(outbounds) {
				t.Logf("Count mismatch: expected %d, got %d", len(outbounds), manager2.OutboundCount())
				return false
			}

			// Verify each outbound is present and equal
			for _, original := range outbounds {
				loaded, ok := manager2.GetOutbound(original.Name)
				if !ok {
					t.Logf("Outbound %s not found after round-trip", original.Name)
					return false
				}
				if !original.Equal(loaded) {
					t.Logf("Outbound %s mismatch after round-trip:\nOriginal: %+v\nLoaded: %+v", original.Name, original, loaded)
					return false
				}
			}

			return true
		},
		genUniqueOutboundList(),
	))

	properties.TestingRun(t)
}
