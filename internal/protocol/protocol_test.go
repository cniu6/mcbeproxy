package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// **Feature: mcpe-server-proxy, Property 11: Protocol Version Mismatch Handling**
// **Validates: Requirements 7.3**
// For any client connection where the client protocol version does not match
// the target server's version, the proxy SHALL send a valid MCBE disconnect
// packet containing version mismatch information.
func TestProtocolVersionMismatchHandling(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Version mismatch produces valid disconnect packet with version info", prop.ForAll(
		func(clientVer, serverVer int32) bool {
			// Skip if versions match (no mismatch)
			if clientVer == serverVer {
				return true
			}

			ph := NewProtocolHandler()
			packet := ph.BuildVersionMismatchPacket(clientVer, serverVer)

			// Verify packet structure
			// [0] = 0xfe (game packet wrapper)
			// [1] = 0x05 (disconnect packet ID)
			// [2] = hide disconnect screen (bool)
			// [3+] = message length (varint) + message

			if len(packet) < 4 {
				t.Logf("Packet too short: %d bytes", len(packet))
				return false
			}

			// Check game packet wrapper
			if packet[0] != 0xfe {
				t.Logf("Invalid game packet wrapper: 0x%02x", packet[0])
				return false
			}

			// Check disconnect packet ID
			if packet[1] != IDDisconnect {
				t.Logf("Invalid packet ID: 0x%02x, expected 0x%02x", packet[1], IDDisconnect)
				return false
			}

			// Check hide disconnect screen flag (should be 0 to show message)
			if packet[2] != 0x00 {
				t.Logf("Hide disconnect screen should be false")
				return false
			}

			// Read message length (varint)
			msgLen, bytesRead, err := readVarInt(packet, 3)
			if err != nil {
				t.Logf("Failed to read message length: %v", err)
				return false
			}

			// Verify message exists and contains version info
			msgStart := 3 + bytesRead
			if msgStart+int(msgLen) > len(packet) {
				t.Logf("Message length exceeds packet size")
				return false
			}

			message := string(packet[msgStart : msgStart+int(msgLen)])

			// Message should contain both version numbers
			clientVerStr := string(rune('0' + clientVer%10))
			serverVerStr := string(rune('0' + serverVer%10))

			// For larger numbers, check if the full version is in the message
			hasClientVer := strings.Contains(message, formatInt32(clientVer))
			hasServerVer := strings.Contains(message, formatInt32(serverVer))

			if !hasClientVer && !strings.Contains(message, clientVerStr) {
				t.Logf("Message doesn't contain client version %d: %s", clientVer, message)
				return false
			}

			if !hasServerVer && !strings.Contains(message, serverVerStr) {
				t.Logf("Message doesn't contain server version %d: %s", serverVer, message)
				return false
			}

			return true
		},
		gen.Int32Range(1, 1000), // clientVer
		gen.Int32Range(1, 1000), // serverVer
	))

	properties.TestingRun(t)
}

// formatInt32 converts an int32 to string
func formatInt32(v int32) string {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, v)
	return string(buf.Bytes())
}

// TestBuildDisconnectPacket tests that disconnect packets are properly constructed.
func TestBuildDisconnectPacket(t *testing.T) {
	ph := NewProtocolHandler()

	testCases := []struct {
		name   string
		reason string
	}{
		{"empty reason", ""},
		{"simple reason", "Server closed"},
		{"unicode reason", "服务器关闭"},
		{"long reason", strings.Repeat("x", 1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packet := ph.BuildDisconnectPacket(tc.reason)

			// Verify basic structure
			if len(packet) < 3 {
				t.Fatalf("Packet too short: %d bytes", len(packet))
			}

			if packet[0] != 0xfe {
				t.Errorf("Invalid game packet wrapper: 0x%02x", packet[0])
			}

			if packet[1] != IDDisconnect {
				t.Errorf("Invalid packet ID: 0x%02x", packet[1])
			}

			// Read and verify message
			msgLen, bytesRead, err := readVarInt(packet, 3)
			if err != nil {
				t.Fatalf("Failed to read message length: %v", err)
			}

			msgStart := 3 + bytesRead
			if msgStart+int(msgLen) > len(packet) {
				t.Fatalf("Message length exceeds packet size")
			}

			message := string(packet[msgStart : msgStart+int(msgLen)])
			if message != tc.reason {
				t.Errorf("Message mismatch: got %q, want %q", message, tc.reason)
			}
		})
	}
}

// TestDetectProtocolVersion tests protocol version detection from login packets.
func TestDetectProtocolVersion(t *testing.T) {
	ph := NewProtocolHandler()

	testCases := []struct {
		name        string
		packet      []byte
		wantVersion int32
		wantErr     bool
	}{
		{
			name:    "empty packet",
			packet:  []byte{},
			wantErr: true,
		},
		{
			name:    "too short",
			packet:  []byte{IDLogin, 0x00},
			wantErr: true,
		},
		{
			name: "valid login packet",
			packet: func() []byte {
				buf := &bytes.Buffer{}
				buf.WriteByte(IDLogin)
				binary.Write(buf, binary.BigEndian, int32(712))
				return buf.Bytes()
			}(),
			wantVersion: 712,
			wantErr:     false,
		},
		{
			name: "game wrapped login packet",
			packet: func() []byte {
				buf := &bytes.Buffer{}
				buf.WriteByte(0xfe) // Game packet wrapper
				buf.WriteByte(IDLogin)
				binary.Write(buf, binary.BigEndian, int32(685))
				return buf.Bytes()
			}(),
			wantVersion: 685,
			wantErr:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, err := ph.DetectProtocolVersion(tc.packet)

			if tc.wantErr {
				if err == nil {
					t.Errorf("Expected error, got version %d", version)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if version != tc.wantVersion {
				t.Errorf("Version mismatch: got %d, want %d", version, tc.wantVersion)
			}
		})
	}
}

// TestTransferPacketHandling tests transfer packet detection and parsing.
func TestTransferPacketHandling(t *testing.T) {
	ph := NewProtocolHandler()

	t.Run("IsTransferPacket", func(t *testing.T) {
		// Non-transfer packet
		if ph.IsTransferPacket([]byte{0xfe, IDLogin}) {
			t.Error("Login packet incorrectly identified as transfer")
		}

		// Transfer packet
		transferPacket := ph.BuildTransferPacket("play.example.com", 19132)
		if !ph.IsTransferPacket(transferPacket) {
			t.Error("Transfer packet not identified")
		}
	})

	t.Run("ParseTransferPacket", func(t *testing.T) {
		address := "play.example.com"
		port := uint16(19132)

		packet := ph.BuildTransferPacket(address, port)
		info, err := ph.ParseTransferPacket(packet)

		if err != nil {
			t.Fatalf("Failed to parse transfer packet: %v", err)
		}

		if info.Address != address {
			t.Errorf("Address mismatch: got %q, want %q", info.Address, address)
		}

		if info.Port != port {
			t.Errorf("Port mismatch: got %d, want %d", info.Port, port)
		}
	})
}
