package config

import (
	"encoding/json"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// **Feature: mcpe-server-proxy, Property 6: Configuration Validation**
// **Validates: Requirements 3.7**
//
// *For any* server configuration, the Validate() function SHALL return an error
// if any of the required fields (id, name, target, port, listen_addr, protocol, enabled)
// are missing or invalid.
func TestProperty6_ConfigurationValidation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid non-empty strings
	nonEmptyString := gen.AnyString().SuchThat(func(s string) bool {
		return len(s) > 0
	})

	// Generator for valid port numbers
	validPort := gen.IntRange(1, 65535)

	// Generator for invalid port numbers (0 or negative, or > 65535)
	invalidPort := gen.OneGenOf(
		gen.IntRange(-1000, 0),
		gen.IntRange(65536, 100000),
	)

	// Property: Valid configurations should pass validation
	properties.Property("valid config passes validation", prop.ForAll(
		func(id, name, target, listenAddr, protocol string, port int) bool {
			config := &ServerConfig{
				ID:         id,
				Name:       name,
				Target:     target,
				Port:       port,
				ListenAddr: listenAddr,
				Protocol:   protocol,
				Enabled:    true,
			}
			return config.Validate() == nil
		},
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		validPort,
	))

	// Property: Missing ID should fail validation
	properties.Property("missing ID fails validation", prop.ForAll(
		func(name, target, listenAddr, protocol string, port int) bool {
			config := &ServerConfig{
				ID:         "", // Missing ID
				Name:       name,
				Target:     target,
				Port:       port,
				ListenAddr: listenAddr,
				Protocol:   protocol,
				Enabled:    true,
			}
			return config.Validate() != nil
		},
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		validPort,
	))

	// Property: Missing Name should fail validation
	properties.Property("missing Name fails validation", prop.ForAll(
		func(id, target, listenAddr, protocol string, port int) bool {
			config := &ServerConfig{
				ID:         id,
				Name:       "", // Missing Name
				Target:     target,
				Port:       port,
				ListenAddr: listenAddr,
				Protocol:   protocol,
				Enabled:    true,
			}
			return config.Validate() != nil
		},
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		validPort,
	))

	// Property: Missing Target should fail validation
	properties.Property("missing Target fails validation", prop.ForAll(
		func(id, name, listenAddr, protocol string, port int) bool {
			config := &ServerConfig{
				ID:         id,
				Name:       name,
				Target:     "", // Missing Target
				Port:       port,
				ListenAddr: listenAddr,
				Protocol:   protocol,
				Enabled:    true,
			}
			return config.Validate() != nil
		},
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		validPort,
	))

	// Property: Missing ListenAddr should fail validation
	properties.Property("missing ListenAddr fails validation", prop.ForAll(
		func(id, name, target, protocol string, port int) bool {
			config := &ServerConfig{
				ID:         id,
				Name:       name,
				Target:     target,
				Port:       port,
				ListenAddr: "", // Missing ListenAddr
				Protocol:   protocol,
				Enabled:    true,
			}
			return config.Validate() != nil
		},
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		validPort,
	))

	// Property: Missing Protocol should fail validation
	properties.Property("missing Protocol fails validation", prop.ForAll(
		func(id, name, target, listenAddr string, port int) bool {
			config := &ServerConfig{
				ID:         id,
				Name:       name,
				Target:     target,
				Port:       port,
				ListenAddr: listenAddr,
				Protocol:   "", // Missing Protocol
				Enabled:    true,
			}
			return config.Validate() != nil
		},
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		validPort,
	))

	// Property: Invalid port should fail validation
	properties.Property("invalid port fails validation", prop.ForAll(
		func(id, name, target, listenAddr, protocol string, port int) bool {
			config := &ServerConfig{
				ID:         id,
				Name:       name,
				Target:     target,
				Port:       port, // Invalid port
				ListenAddr: listenAddr,
				Protocol:   protocol,
				Enabled:    true,
			}
			return config.Validate() != nil
		},
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		nonEmptyString,
		invalidPort,
	))

	properties.TestingRun(t)
}

// **Feature: xbox-live-auth-proxy, Property 4: Configuration Field Parsing**
// **Validates: Requirements 5.1, 5.2**
//
// *For any* server configuration JSON containing xbox_auth_enabled and xbox_token_path fields,
// the Configuration Manager SHALL correctly parse and store these values in the ServerConfig struct.
func TestProperty4_ConfigurationFieldParsing(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for valid non-empty strings (for required fields)
	nonEmptyString := gen.AnyString().SuchThat(func(s string) bool {
		return len(s) > 0
	})

	// Generator for valid port numbers
	validPort := gen.IntRange(1, 65535)

	// Generator for optional token path (can be empty or non-empty)
	tokenPath := gen.AnyString()

	// Property: xbox_auth_enabled and xbox_token_path fields are correctly parsed from JSON
	properties.Property("xbox auth fields are correctly parsed", prop.ForAll(
		func(id, name, target, listenAddr, protocol string, port int, xboxAuthEnabled bool, xboxTokenPath string) bool {
			// Create a JSON representation of the config
			configJSON := map[string]interface{}{
				"id":                id,
				"name":              name,
				"target":            target,
				"port":              port,
				"listen_addr":       listenAddr,
				"protocol":          protocol,
				"enabled":           true,
				"xbox_auth_enabled": xboxAuthEnabled,
				"xbox_token_path":   xboxTokenPath,
			}

			// Serialize to JSON
			data, err := json.Marshal(configJSON)
			if err != nil {
				return false
			}

			// Deserialize using ServerConfigFromJSON
			config, err := ServerConfigFromJSON(data)
			if err != nil {
				return false
			}

			// Verify xbox_auth_enabled is correctly parsed
			if config.XboxAuthEnabled != xboxAuthEnabled {
				return false
			}

			// Verify xbox_token_path is correctly parsed
			if config.XboxTokenPath != xboxTokenPath {
				return false
			}

			return true
		},
		nonEmptyString, // id
		nonEmptyString, // name
		nonEmptyString, // target
		nonEmptyString, // listenAddr
		nonEmptyString, // protocol
		validPort,      // port
		gen.Bool(),     // xboxAuthEnabled
		tokenPath,      // xboxTokenPath
	))

	// Property: GetXboxTokenPath returns default when empty
	properties.Property("GetXboxTokenPath returns default when empty", prop.ForAll(
		func(id, name, target, listenAddr, protocol string, port int, xboxAuthEnabled bool) bool {
			config := &ServerConfig{
				ID:              id,
				Name:            name,
				Target:          target,
				Port:            port,
				ListenAddr:      listenAddr,
				Protocol:        protocol,
				Enabled:         true,
				XboxAuthEnabled: xboxAuthEnabled,
				XboxTokenPath:   "", // Empty path
			}

			// GetXboxTokenPath should return default "xbox_token.json" when empty
			return config.GetXboxTokenPath() == "xbox_token.json"
		},
		nonEmptyString, // id
		nonEmptyString, // name
		nonEmptyString, // target
		nonEmptyString, // listenAddr
		nonEmptyString, // protocol
		validPort,      // port
		gen.Bool(),     // xboxAuthEnabled
	))

	// Property: GetXboxTokenPath returns custom path when set
	properties.Property("GetXboxTokenPath returns custom path when set", prop.ForAll(
		func(id, name, target, listenAddr, protocol string, port int, xboxAuthEnabled bool, customPath string) bool {
			config := &ServerConfig{
				ID:              id,
				Name:            name,
				Target:          target,
				Port:            port,
				ListenAddr:      listenAddr,
				Protocol:        protocol,
				Enabled:         true,
				XboxAuthEnabled: xboxAuthEnabled,
				XboxTokenPath:   customPath,
			}

			// GetXboxTokenPath should return the custom path when set
			return config.GetXboxTokenPath() == customPath
		},
		nonEmptyString, // id
		nonEmptyString, // name
		nonEmptyString, // target
		nonEmptyString, // listenAddr
		nonEmptyString, // protocol
		validPort,      // port
		gen.Bool(),     // xboxAuthEnabled
		gen.AnyString().SuchThat(func(s string) bool { return len(s) > 0 }), // customPath (non-empty)
	))

	// Property: IsXboxAuthEnabled returns correct value
	properties.Property("IsXboxAuthEnabled returns correct value", prop.ForAll(
		func(id, name, target, listenAddr, protocol string, port int, xboxAuthEnabled bool) bool {
			config := &ServerConfig{
				ID:              id,
				Name:            name,
				Target:          target,
				Port:            port,
				ListenAddr:      listenAddr,
				Protocol:        protocol,
				Enabled:         true,
				XboxAuthEnabled: xboxAuthEnabled,
			}

			// IsXboxAuthEnabled should return the same value as XboxAuthEnabled
			return config.IsXboxAuthEnabled() == xboxAuthEnabled
		},
		nonEmptyString, // id
		nonEmptyString, // name
		nonEmptyString, // target
		nonEmptyString, // listenAddr
		nonEmptyString, // protocol
		validPort,      // port
		gen.Bool(),     // xboxAuthEnabled
	))

	properties.TestingRun(t)
}
