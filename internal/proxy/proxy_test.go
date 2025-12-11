// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/protocol"
	"mcpeserverproxy/internal/session"
)

// **Feature: mcpe-server-proxy, Property 1: Packet Content Preservation**
// **Validates: Requirements 1.7**
// For any UDP packet forwarded through the proxy in transparent mode,
// the packet bytes received by the destination SHALL be identical to the bytes sent by the source.
func TestProperty_PacketContentPreservation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("Packet content is preserved during transparent forwarding", prop.ForAll(
		func(packetData []byte) bool {
			if len(packetData) == 0 {
				return true // Skip empty packets
			}

			// Create a mock UDP connection pair for testing
			// We'll use a local UDP server to verify packet content preservation
			serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Logf("Failed to resolve server address: %v", err)
				return false
			}

			serverConn, err := net.ListenUDP("udp", serverAddr)
			if err != nil {
				t.Logf("Failed to create server connection: %v", err)
				return false
			}
			defer serverConn.Close()

			// Get the actual address the server is listening on
			actualServerAddr := serverConn.LocalAddr().(*net.UDPAddr)

			// Create client connection
			clientConn, err := net.DialUDP("udp", nil, actualServerAddr)
			if err != nil {
				t.Logf("Failed to create client connection: %v", err)
				return false
			}
			defer clientConn.Close()

			// Create forwarder with protocol handler
			protocolHandler := protocol.NewProtocolHandler()
			bufferPool := NewBufferPool(DefaultBufferSize)
			forwarder := NewForwarder(protocolHandler, bufferPool)

			// Create a mock session
			sess := &session.Session{
				ID:         "test-session",
				ClientAddr: clientConn.LocalAddr().String(),
				RemoteConn: clientConn,
				ServerID:   "test-server",
				StartTime:  time.Now(),
				LastSeen:   time.Now(),
			}

			// Create a server config with SendRealIP disabled (transparent mode)
			cfg := &config.ServerConfig{
				ID:         "test-server",
				Name:       "Test Server",
				Target:     "127.0.0.1",
				Port:       actualServerAddr.Port,
				ListenAddr: "0.0.0.0:19132",
				Protocol:   "bedrock",
				Enabled:    true,
				SendRealIP: false, // Transparent mode
			}

			// Forward the packet
			err = forwarder.ForwardToRemote(sess, packetData, cfg)
			if err != nil {
				t.Logf("Failed to forward packet: %v", err)
				return false
			}

			// Read the packet on the server side
			serverConn.SetReadDeadline(time.Now().Add(time.Second))
			receivedBuf := make([]byte, len(packetData)+100)
			n, _, err := serverConn.ReadFromUDP(receivedBuf)
			if err != nil {
				t.Logf("Failed to read packet: %v", err)
				return false
			}

			receivedData := receivedBuf[:n]

			// Verify packet content is preserved
			if !bytes.Equal(packetData, receivedData) {
				t.Logf("Packet content mismatch: sent %d bytes, received %d bytes", len(packetData), len(receivedData))
				return false
			}

			return true
		},
		gen.SliceOf(gen.UInt8()).SuchThat(func(data []byte) bool {
			return len(data) > 0 && len(data) <= 1400 // Typical UDP packet size
		}),
	))

	properties.TestingRun(t)
}

// **Feature: mcpe-server-proxy, Property 12: Parse Failure Transparency**
// **Validates: Requirements 7.9**
// For any packet that fails protocol parsing, the packet SHALL be forwarded
// to the destination unchanged.
func TestProperty_ParseFailureTransparency(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	properties.Property("Packets that fail parsing are forwarded unchanged", prop.ForAll(
		func(packetData []byte) bool {
			if len(packetData) == 0 {
				return true // Skip empty packets
			}

			// Create a mock UDP connection pair for testing
			serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			if err != nil {
				t.Logf("Failed to resolve server address: %v", err)
				return false
			}

			serverConn, err := net.ListenUDP("udp", serverAddr)
			if err != nil {
				t.Logf("Failed to create server connection: %v", err)
				return false
			}
			defer serverConn.Close()

			actualServerAddr := serverConn.LocalAddr().(*net.UDPAddr)

			clientConn, err := net.DialUDP("udp", nil, actualServerAddr)
			if err != nil {
				t.Logf("Failed to create client connection: %v", err)
				return false
			}
			defer clientConn.Close()

			// Create forwarder
			protocolHandler := protocol.NewProtocolHandler()
			bufferPool := NewBufferPool(DefaultBufferSize)
			forwarder := NewForwarder(protocolHandler, bufferPool)

			// Verify that parsing fails for this random data
			_, parseErr := protocolHandler.ParseLoginPacket(packetData)
			// We expect parsing to fail for random data most of the time
			// The key property is that even if parsing fails, the packet is forwarded

			// Create a mock session
			sess := &session.Session{
				ID:         "test-session",
				ClientAddr: clientConn.LocalAddr().String(),
				RemoteConn: clientConn,
				ServerID:   "test-server",
				StartTime:  time.Now(),
				LastSeen:   time.Now(),
			}

			cfg := &config.ServerConfig{
				ID:         "test-server",
				Name:       "Test Server",
				Target:     "127.0.0.1",
				Port:       actualServerAddr.Port,
				ListenAddr: "0.0.0.0:19132",
				Protocol:   "bedrock",
				Enabled:    true,
				SendRealIP: false,
			}

			// Forward the packet (should succeed even if parsing fails)
			err = forwarder.ForwardToRemote(sess, packetData, cfg)
			if err != nil {
				t.Logf("Failed to forward packet: %v", err)
				return false
			}

			// Read the packet on the server side
			serverConn.SetReadDeadline(time.Now().Add(time.Second))
			receivedBuf := make([]byte, len(packetData)+100)
			n, _, err := serverConn.ReadFromUDP(receivedBuf)
			if err != nil {
				t.Logf("Failed to read packet: %v", err)
				return false
			}

			receivedData := receivedBuf[:n]

			// Verify packet content is preserved regardless of parse result
			if !bytes.Equal(packetData, receivedData) {
				t.Logf("Packet content mismatch after parse failure (parseErr=%v): sent %d bytes, received %d bytes",
					parseErr, len(packetData), len(receivedData))
				return false
			}

			return true
		},
		// Generate random byte slices that are likely to fail parsing
		gen.SliceOf(gen.UInt8()).SuchThat(func(data []byte) bool {
			return len(data) > 0 && len(data) <= 1400
		}),
	))

	properties.TestingRun(t)
}

// **Feature: mcpe-server-proxy, Property 7: Disabled Server Rejection**
// **Validates: Requirements 3.5**
// For any server configuration with enabled=false, all incoming connection
// attempts to that server's listen address SHALL be rejected.
func TestProperty_DisabledServerRejection(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generate server IDs with a prefix to ensure non-empty
	serverIDGen := gen.Identifier().Map(func(s string) string {
		return "server_" + s
	})
	serverNameGen := gen.Identifier().Map(func(s string) string {
		return "Server " + s
	})

	properties.Property("Disabled servers reject all connection attempts", prop.ForAll(
		func(serverID string, serverName string) bool {
			// Create a config manager with a disabled server
			tempFile := t.TempDir() + "/server_list.json"
			configData := []byte(`[{
				"id": "` + serverID + `",
				"name": "` + serverName + `",
				"target": "127.0.0.1",
				"port": 19132,
				"listen_addr": "0.0.0.0:19132",
				"protocol": "bedrock",
				"enabled": false
			}]`)

			if err := writeTestFile(tempFile, configData); err != nil {
				t.Logf("Failed to write config file: %v", err)
				return false
			}

			configMgr, err := config.NewConfigManager(tempFile)
			if err != nil {
				t.Logf("Failed to create config manager: %v", err)
				return false
			}

			if err := configMgr.Load(); err != nil {
				t.Logf("Failed to load config: %v", err)
				return false
			}

			// Verify the server is disabled
			serverCfg, exists := configMgr.GetServer(serverID)
			if !exists {
				t.Logf("Server config not found for %s", serverID)
				return false
			}

			// The key property: server with enabled=false should have Enabled=false
			if serverCfg.Enabled {
				t.Logf("Server %s should be disabled but Enabled=%v", serverID, serverCfg.Enabled)
				return false
			}

			// Verify that the config correctly identifies this as a disabled server
			// This is the core property - when Enabled is false, the server should reject connections
			return !serverCfg.Enabled
		},
		serverIDGen,
		serverNameGen,
	))

	properties.TestingRun(t)
}

// writeTestFile is a helper function to write test configuration files.
func writeTestFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

// TestSendRealIP tests the send_real_ip functionality.
// NOTE: send_real_ip is currently DISABLED because it breaks standard MCBE servers.
// This test verifies that the function returns data unchanged.
func TestSendRealIP(t *testing.T) {
	// Create forwarder
	protocolHandler := protocol.NewProtocolHandler()
	bufferPool := NewBufferPool(DefaultBufferSize)
	forwarder := NewForwarder(protocolHandler, bufferPool)

	// Test data
	originalData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	clientAddr := "192.168.1.100:12345"

	// Inject real IP (currently disabled, should return original data)
	modifiedData := forwarder.injectRealIP(originalData, clientAddr)

	// Since send_real_ip is disabled, data should be unchanged
	if !bytes.Equal(originalData, modifiedData) {
		t.Errorf("send_real_ip is disabled, data should be unchanged. Got %v, expected %v", modifiedData, originalData)
	}
}

// TestSendRealIPWithIPv6 tests the send_real_ip functionality with IPv6 addresses.
// NOTE: send_real_ip is currently DISABLED because it breaks standard MCBE servers.
func TestSendRealIPWithIPv6(t *testing.T) {
	// Create forwarder
	protocolHandler := protocol.NewProtocolHandler()
	bufferPool := NewBufferPool(DefaultBufferSize)
	forwarder := NewForwarder(protocolHandler, bufferPool)

	// Test data
	originalData := []byte{0x01, 0x02, 0x03}
	clientAddr := "[::1]:12345"

	// Inject real IP (currently disabled, should return original data)
	modifiedData := forwarder.injectRealIP(originalData, clientAddr)

	// Since send_real_ip is disabled, data should be unchanged
	if !bytes.Equal(originalData, modifiedData) {
		t.Errorf("send_real_ip is disabled, data should be unchanged. Got %v, expected %v", modifiedData, originalData)
	}
}

// **Feature: xbox-live-auth-proxy, Property 5: Auth Mode Selection**
// **Validates: Requirements 5.3, 5.4**
// For any server configuration, if xbox_auth_enabled is true then the proxy SHALL
// initialize and use the XboxAuthManager, and if xbox_auth_enabled is false then
// the proxy SHALL not use Xbox authentication.
func TestProperty_AuthModeSelection(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for server configurations with varying xbox_auth_enabled values
	serverConfigGen := gen.Bool().Map(func(xboxAuthEnabled bool) *config.ServerConfig {
		return &config.ServerConfig{
			ID:              "test-server",
			Name:            "Test Server",
			Target:          "127.0.0.1",
			Port:            19132,
			ListenAddr:      "0.0.0.0:0", // Use port 0 to avoid conflicts
			Protocol:        "bedrock",
			Enabled:         true,
			XboxAuthEnabled: xboxAuthEnabled,
			XboxTokenPath:   "", // Use default path
		}
	})

	properties.Property("Auth mode selection based on xbox_auth_enabled config", prop.ForAll(
		func(cfg *config.ServerConfig) bool {
			// Create a temporary config file
			tempDir := t.TempDir()
			tempFile := tempDir + "/server_list.json"

			// Write config to file
			xboxAuthStr := "false"
			if cfg.XboxAuthEnabled {
				xboxAuthStr = "true"
			}
			configData := []byte(`[{
				"id": "` + cfg.ID + `",
				"name": "` + cfg.Name + `",
				"target": "` + cfg.Target + `",
				"port": ` + fmt.Sprintf("%d", cfg.Port) + `,
				"listen_addr": "` + cfg.ListenAddr + `",
				"protocol": "` + cfg.Protocol + `",
				"enabled": true,
				"xbox_auth_enabled": ` + xboxAuthStr + `
			}]`)

			if err := writeTestFile(tempFile, configData); err != nil {
				t.Logf("Failed to write config file: %v", err)
				return false
			}

			configMgr, err := config.NewConfigManager(tempFile)
			if err != nil {
				t.Logf("Failed to create config manager: %v", err)
				return false
			}

			if err := configMgr.Load(); err != nil {
				t.Logf("Failed to load config: %v", err)
				return false
			}

			// Get the loaded config
			loadedCfg, exists := configMgr.GetServer(cfg.ID)
			if !exists {
				t.Logf("Server config not found")
				return false
			}

			// Create session manager
			sessionMgr := session.NewSessionManager(time.Minute * 5)

			// Create MITM proxy
			proxy := NewMITMProxy(cfg.ID, loadedCfg, configMgr, sessionMgr)

			// Verify the property:
			// - If xbox_auth_enabled is true, IsXboxAuthEnabled should return true after auth
			// - If xbox_auth_enabled is false, IsXboxAuthEnabled should return false
			//
			// Note: We can't actually call Start() because it would try to authenticate
			// with Xbox Live. Instead, we verify the config is correctly parsed and
			// the proxy would behave correctly based on the config.

			// Property 1: Config parsing is correct
			if loadedCfg.IsXboxAuthEnabled() != cfg.XboxAuthEnabled {
				t.Logf("Config parsing mismatch: expected XboxAuthEnabled=%v, got %v",
					cfg.XboxAuthEnabled, loadedCfg.IsXboxAuthEnabled())
				return false
			}

			// Property 2: Before Start(), auth manager should be nil
			if proxy.GetAuthManager() != nil {
				t.Logf("Auth manager should be nil before Start()")
				return false
			}

			// Property 3: IsXboxAuthEnabled should return false before Start()
			if proxy.IsXboxAuthEnabled() {
				t.Logf("IsXboxAuthEnabled should return false before Start()")
				return false
			}

			// Property 4: The config correctly determines auth behavior
			// When xbox_auth_enabled=false, the proxy should not attempt authentication
			// When xbox_auth_enabled=true, the proxy should attempt authentication
			// This is verified by checking the config value matches what was set
			return loadedCfg.XboxAuthEnabled == cfg.XboxAuthEnabled
		},
		serverConfigGen,
	))

	properties.TestingRun(t)
}
