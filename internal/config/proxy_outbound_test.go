package config

import (
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// Generators for ProxyOutbound property tests

// genNonEmptyString generates non-empty strings using alphanumeric characters
func genNonEmptyString() gopter.Gen {
	return gen.AlphaString().Map(func(s string) string {
		if len(s) == 0 {
			return "a" // Ensure non-empty
		}
		if len(s) > 50 {
			return s[:50]
		}
		return s
	})
}

// genValidPort generates valid port numbers (1-65535)
func genValidPort() gopter.Gen {
	return gen.IntRange(1, 65535)
}

// genSSMethod generates valid Shadowsocks encryption methods
func genSSMethod() gopter.Gen {
	methods := []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
	}
	return gen.OneConstOf(methods[0], methods[1], methods[2], methods[3], methods[4], methods[5])
}

// genProtocolType generates valid protocol types
func genProtocolType() gopter.Gen {
	return gen.OneConstOf(
		ProtocolShadowsocks,
		ProtocolVMess,
		ProtocolTrojan,
		ProtocolVLESS,
		ProtocolHysteria2,
	)
}

// genValidShadowsocksOutbound generates valid Shadowsocks ProxyOutbound configurations
func genValidShadowsocksOutbound() gopter.Gen {
	return gopter.CombineGens(
		genNonEmptyString(), // name
		genNonEmptyString(), // server
		genValidPort(),      // port
		gen.Bool(),          // enabled
		genSSMethod(),       // method
		genNonEmptyString(), // password
		gen.Bool(),          // tls
		gen.AnyString(),     // sni
		gen.Bool(),          // insecure
		gen.AnyString(),     // fingerprint
	).Map(func(values []any) *ProxyOutbound {
		return &ProxyOutbound{
			Name:        values[0].(string),
			Type:        ProtocolShadowsocks,
			Server:      values[1].(string),
			Port:        values[2].(int),
			Enabled:     values[3].(bool),
			Method:      values[4].(string),
			Password:    values[5].(string),
			TLS:         values[6].(bool),
			SNI:         values[7].(string),
			Insecure:    values[8].(bool),
			Fingerprint: values[9].(string),
		}
	})
}

// genValidVMessOutbound generates valid VMess ProxyOutbound configurations
func genValidVMessOutbound() gopter.Gen {
	return gopter.CombineGens(
		genNonEmptyString(), // name
		genNonEmptyString(), // server
		genValidPort(),      // port
		gen.Bool(),          // enabled
		genNonEmptyString(), // uuid
		gen.IntRange(0, 64), // alterID
		gen.AnyString(),     // security
		gen.Bool(),          // tls
		gen.AnyString(),     // sni
		gen.Bool(),          // insecure
		gen.AnyString(),     // fingerprint
	).Map(func(values []any) *ProxyOutbound {
		return &ProxyOutbound{
			Name:        values[0].(string),
			Type:        ProtocolVMess,
			Server:      values[1].(string),
			Port:        values[2].(int),
			Enabled:     values[3].(bool),
			UUID:        values[4].(string),
			AlterID:     values[5].(int),
			Security:    values[6].(string),
			TLS:         values[7].(bool),
			SNI:         values[8].(string),
			Insecure:    values[9].(bool),
			Fingerprint: values[10].(string),
		}
	})
}

// genValidTrojanOutbound generates valid Trojan ProxyOutbound configurations
func genValidTrojanOutbound() gopter.Gen {
	return gopter.CombineGens(
		genNonEmptyString(), // name
		genNonEmptyString(), // server
		genValidPort(),      // port
		gen.Bool(),          // enabled
		genNonEmptyString(), // password
		gen.Bool(),          // tls
		gen.AnyString(),     // sni
		gen.Bool(),          // insecure
		gen.AnyString(),     // fingerprint
	).Map(func(values []any) *ProxyOutbound {
		return &ProxyOutbound{
			Name:        values[0].(string),
			Type:        ProtocolTrojan,
			Server:      values[1].(string),
			Port:        values[2].(int),
			Enabled:     values[3].(bool),
			Password:    values[4].(string),
			TLS:         values[5].(bool),
			SNI:         values[6].(string),
			Insecure:    values[7].(bool),
			Fingerprint: values[8].(string),
		}
	})
}

// genValidVLESSOutbound generates valid VLESS ProxyOutbound configurations
func genValidVLESSOutbound() gopter.Gen {
	return gopter.CombineGens(
		genNonEmptyString(), // name
		genNonEmptyString(), // server
		genValidPort(),      // port
		gen.Bool(),          // enabled
		genNonEmptyString(), // uuid
		gen.AnyString(),     // flow
		gen.Bool(),          // tls
		gen.AnyString(),     // sni
		gen.Bool(),          // insecure
		gen.AnyString(),     // fingerprint
	).Map(func(values []any) *ProxyOutbound {
		return &ProxyOutbound{
			Name:        values[0].(string),
			Type:        ProtocolVLESS,
			Server:      values[1].(string),
			Port:        values[2].(int),
			Enabled:     values[3].(bool),
			UUID:        values[4].(string),
			Flow:        values[5].(string),
			TLS:         values[6].(bool),
			SNI:         values[7].(string),
			Insecure:    values[8].(bool),
			Fingerprint: values[9].(string),
		}
	})
}

// genValidHysteria2Outbound generates valid Hysteria2 ProxyOutbound configurations
func genValidHysteria2Outbound() gopter.Gen {
	return gopter.CombineGens(
		genNonEmptyString(), // name
		genNonEmptyString(), // server
		genValidPort(),      // port
		gen.Bool(),          // enabled
		genNonEmptyString(), // password
		gen.AnyString(),     // obfs
		gen.AnyString(),     // obfsPassword
		gen.Bool(),          // tls
		gen.AnyString(),     // sni
		gen.Bool(),          // insecure
		gen.AnyString(),     // fingerprint
	).Map(func(values []any) *ProxyOutbound {
		return &ProxyOutbound{
			Name:         values[0].(string),
			Type:         ProtocolHysteria2,
			Server:       values[1].(string),
			Port:         values[2].(int),
			Enabled:      values[3].(bool),
			Password:     values[4].(string),
			Obfs:         values[5].(string),
			ObfsPassword: values[6].(string),
			TLS:          values[7].(bool),
			SNI:          values[8].(string),
			Insecure:     values[9].(bool),
			Fingerprint:  values[10].(string),
		}
	})
}

// genValidProxyOutbound generates valid ProxyOutbound configurations for any protocol
func genValidProxyOutbound() gopter.Gen {
	return gen.OneGenOf(
		genValidShadowsocksOutbound(),
		genValidVMessOutbound(),
		genValidTrojanOutbound(),
		genValidVLESSOutbound(),
		genValidHysteria2Outbound(),
	)
}

// **Feature: singbox-outbound-proxy, Property 13: JSON serialization round-trip**
// **Validates: Requirements 7.4**
//
// *For any* valid ProxyOutbound configuration, serializing to JSON and then parsing
// should produce an equivalent configuration.
func TestProperty13_JSONSerializationRoundTrip(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("JSON round-trip preserves all fields", prop.ForAll(
		func(original *ProxyOutbound) bool {
			// Serialize to JSON
			jsonData, err := original.ToJSON()
			if err != nil {
				t.Logf("ToJSON failed: %v", err)
				return false
			}

			// Deserialize from JSON
			parsed, err := FromJSON(jsonData)
			if err != nil {
				t.Logf("FromJSON failed: %v", err)
				return false
			}

			// Compare all fields (excluding runtime state)
			if !original.Equal(parsed) {
				t.Logf("Round-trip mismatch:\nOriginal: %+v\nParsed: %+v", original, parsed)
				return false
			}

			return true
		},
		genValidProxyOutbound(),
	))

	properties.TestingRun(t)
}

// **Feature: singbox-outbound-proxy, Property 14: Validation error contains field name**
// **Validates: Requirements 7.3**
//
// *For any* ProxyOutbound configuration with a missing required field,
// the validation error message should contain the name of the missing field.
func TestProperty14_ValidationErrorContainsFieldName(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Test missing name field
	properties.Property("missing name error contains 'name'", prop.ForAll(
		func(server string, port int) bool {
			p := &ProxyOutbound{
				Name:     "", // Missing
				Type:     ProtocolShadowsocks,
				Server:   server,
				Port:     port,
				Method:   "aes-256-gcm",
				Password: "test",
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "name")
		},
		genNonEmptyString(),
		genValidPort(),
	))

	// Test missing type field
	properties.Property("missing type error contains 'type'", prop.ForAll(
		func(name, server string, port int) bool {
			p := &ProxyOutbound{
				Name:   name,
				Type:   "", // Missing
				Server: server,
				Port:   port,
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "type")
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genValidPort(),
	))

	// Test missing server field
	properties.Property("missing server error contains 'server'", prop.ForAll(
		func(name string, port int) bool {
			p := &ProxyOutbound{
				Name:   name,
				Type:   ProtocolShadowsocks,
				Server: "", // Missing
				Port:   port,
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "server")
		},
		genNonEmptyString(),
		genValidPort(),
	))

	// Test invalid port field
	properties.Property("invalid port error contains 'port'", prop.ForAll(
		func(name, server string) bool {
			p := &ProxyOutbound{
				Name:   name,
				Type:   ProtocolShadowsocks,
				Server: server,
				Port:   0, // Invalid
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "port")
		},
		genNonEmptyString(),
		genNonEmptyString(),
	))

	// Test missing method for Shadowsocks
	properties.Property("missing SS method error contains 'method'", prop.ForAll(
		func(name, server, password string, port int) bool {
			p := &ProxyOutbound{
				Name:     name,
				Type:     ProtocolShadowsocks,
				Server:   server,
				Port:     port,
				Method:   "", // Missing
				Password: password,
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "method")
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genNonEmptyString(),
		genValidPort(),
	))

	// Test missing password for Shadowsocks
	properties.Property("missing SS password error contains 'password'", prop.ForAll(
		func(name, server string, port int) bool {
			p := &ProxyOutbound{
				Name:     name,
				Type:     ProtocolShadowsocks,
				Server:   server,
				Port:     port,
				Method:   "aes-256-gcm",
				Password: "", // Missing
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "password")
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genValidPort(),
	))

	// Test missing uuid for VMess
	properties.Property("missing VMess uuid error contains 'uuid'", prop.ForAll(
		func(name, server string, port int) bool {
			p := &ProxyOutbound{
				Name:   name,
				Type:   ProtocolVMess,
				Server: server,
				Port:   port,
				UUID:   "", // Missing
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "uuid")
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genValidPort(),
	))

	// Test missing password for Trojan
	properties.Property("missing Trojan password error contains 'password'", prop.ForAll(
		func(name, server string, port int) bool {
			p := &ProxyOutbound{
				Name:     name,
				Type:     ProtocolTrojan,
				Server:   server,
				Port:     port,
				Password: "", // Missing
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "password")
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genValidPort(),
	))

	// Test missing uuid for VLESS
	properties.Property("missing VLESS uuid error contains 'uuid'", prop.ForAll(
		func(name, server string, port int) bool {
			p := &ProxyOutbound{
				Name:   name,
				Type:   ProtocolVLESS,
				Server: server,
				Port:   port,
				UUID:   "", // Missing
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "uuid")
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genValidPort(),
	))

	// Test missing password for Hysteria2
	properties.Property("missing Hysteria2 password error contains 'password'", prop.ForAll(
		func(name, server string, port int) bool {
			p := &ProxyOutbound{
				Name:     name,
				Type:     ProtocolHysteria2,
				Server:   server,
				Port:     port,
				Password: "", // Missing
			}
			err := p.Validate()
			return err != nil && strings.Contains(err.Error(), "password")
		},
		genNonEmptyString(),
		genNonEmptyString(),
		genValidPort(),
	))

	properties.TestingRun(t)
}
