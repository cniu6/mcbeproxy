// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/protocol"
	"mcpeserverproxy/internal/session"
)

// Forwarder handles transparent packet forwarding between clients and remote servers.
type Forwarder struct {
	protocolHandler *protocol.ProtocolHandler
	bufferPool      *BufferPool
}

// NewForwarder creates a new packet forwarder.
func NewForwarder(protocolHandler *protocol.ProtocolHandler, bufferPool *BufferPool) *Forwarder {
	return &Forwarder{
		protocolHandler: protocolHandler,
		bufferPool:      bufferPool,
	}
}

// ForwardToRemote forwards a packet from client to the remote server.
// It operates in transparent mode, preserving original packet bytes without modification
// unless send_real_ip is enabled.
func (f *Forwarder) ForwardToRemote(sess *session.Session, data []byte, cfg *config.ServerConfig) error {
	if sess.RemoteConn == nil {
		return nil
	}

	// Update bytes up counter
	sess.AddBytesUp(int64(len(data)))

	// Try to extract player info from login packets (read-only operation)
	f.tryExtractPlayerInfo(sess, data)

	// Prepare data for forwarding
	forwardData := data

	// Fix OpenConnectionRequest2 server address
	// The client sends the proxy address, but we need to send the remote server address
	if len(data) > 17 && data[0] == 0x07 { // OpenConnectionRequest2
		forwardData = f.fixOpenConnectionRequest2(data, cfg)
	}

	// If send_real_ip is enabled, inject client IP into the packet
	if cfg.SendRealIP {
		forwardData = f.injectRealIP(forwardData, sess.ClientAddr)
	}

	// Forward packet to remote server (transparent forwarding)
	_, err := sess.RemoteConn.Write(forwardData)
	return err
}

// fixOpenConnectionRequest2 fixes the server address in OpenConnectionRequest2 packet.
// The client sends the proxy address, but we need to send the remote server address.
func (f *Forwarder) fixOpenConnectionRequest2(data []byte, cfg *config.ServerConfig) []byte {
	// OpenConnectionRequest2 structure:
	// [0] = packet ID (0x07)
	// [1-16] = magic (16 bytes)
	// [17] = address type (4 = IPv4, 6 = IPv6)
	// [18-21] = IP address (4 bytes for IPv4, inverted)
	// [22-23] = port (2 bytes, big endian)
	// [24-25] = MTU size (2 bytes, big endian)
	// [26-33] = client GUID (8 bytes)

	if len(data) < 26 {
		logger.Debug("OpenConnectionRequest2 too short: %d bytes", len(data))
		return data // Too short, return as-is
	}

	// Check if it's IPv4
	if data[17] != 4 {
		logger.Debug("OpenConnectionRequest2 not IPv4: type=%d", data[17])
		return data // Not IPv4, return as-is
	}

	// Get the target address
	targetAddr := cfg.GetTargetAddr()
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		logger.Debug("Failed to split target address %s: %v", targetAddr, err)
		return data
	}

	// Resolve the hostname to IP if needed
	ips, err := net.LookupIP(host)
	if err != nil {
		logger.Debug("Failed to resolve host %s: %v", host, err)
		return data
	}

	// Find an IPv4 address
	var ipv4 net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			ipv4 = v4
			break
		}
	}

	if ipv4 == nil {
		logger.Debug("No IPv4 address found for %s", host)
		return data // No IPv4 address found
	}

	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		logger.Debug("Failed to lookup port %s: %v", portStr, err)
		return data
	}

	// Log original address in packet
	origIP := fmt.Sprintf("%d.%d.%d.%d", ^data[18], ^data[19], ^data[20], ^data[21])
	origPort := uint16(data[22])<<8 | uint16(data[23])
	logger.Debug("OpenConnectionRequest2 original: %s:%d", origIP, origPort)

	// Create a copy of the data
	result := make([]byte, len(data))
	copy(result, data)

	// Fix the IP address (bytes 18-21)
	// RakNet uses inverted IP bytes (XOR with 0xFF)
	result[18] = ^ipv4[0]
	result[19] = ^ipv4[1]
	result[20] = ^ipv4[2]
	result[21] = ^ipv4[3]

	// Fix the port (bytes 22-23, big endian)
	result[22] = byte(port >> 8)
	result[23] = byte(port)

	logger.Debug("OpenConnectionRequest2 fixed: %s:%d -> %s:%d", origIP, origPort, ipv4.String(), port)

	return result
}

// ForwardToClient forwards a packet from remote server to the client.
// It operates in transparent mode, preserving original packet bytes without modification.
func (f *Forwarder) ForwardToClient(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, sess *session.Session) error {
	// Update bytes down counter
	sess.AddBytesDown(int64(len(data)))

	// Try to extract player info from server responses too
	// Some servers may echo player info in certain packets
	if !sess.IsLoginExtracted() && len(data) > 10 {
		f.tryExtractPlayerInfoFromResponse(sess, data)
	}

	// Forward packet to client (transparent forwarding - no modification)
	_, err := conn.WriteToUDP(data, clientAddr)
	return err
}

// tryExtractPlayerInfoFromResponse attempts to extract player info from server response packets.
func (f *Forwarder) tryExtractPlayerInfoFromResponse(sess *session.Session, data []byte) {
	// Check if this packet contains player info patterns
	if containsLoginData(data) {
		playerInfo := f.protocolHandler.TryExtractPlayerInfoFromRaw(data)
		if playerInfo != nil && (playerInfo.UUID != "" || playerInfo.DisplayName != "") {
			logger.Info("Player identified from server response: %s (UUID: %s) from %s",
				playerInfo.DisplayName, playerInfo.UUID, sess.ClientAddr)
			sess.SetPlayerInfo(playerInfo.UUID, playerInfo.DisplayName)
		}
	}
}

// tryExtractPlayerInfo attempts to extract player information from login packets.
// This is a read-only operation that does not modify the packet.
//
// NOTE: MCBE uses encryption after the RakNet handshake, so login packet contents
// are encrypted and cannot be read by a transparent proxy. This function attempts
// to extract info from unencrypted portions of the handshake, but success is limited.
func (f *Forwarder) tryExtractPlayerInfo(sess *session.Session, data []byte) {
	// Only try to extract if we don't have player info yet
	if sess.IsLoginExtracted() {
		return
	}

	if len(data) == 0 {
		return
	}

	// Check if this is a RakNet framed packet that might contain login data
	// RakNet frames are in range 0x80-0x8f
	isFramed := len(data) > 0 && data[0] >= 0x80 && data[0] <= 0x8f

	// Check if this packet contains login data patterns
	hasLoginData := containsLoginData(data)

	// Only log handshake packets, not every packet
	if data[0] == 0x05 { // OpenConnectionRequest1
		logger.Debug("OpenConnectionRequest1 from %s, size=%d", sess.ClientAddr, len(data))
	} else if data[0] == 0x07 && len(data) >= 27 { // OpenConnectionRequest2
		mtu := uint16(data[len(data)-10])<<8 | uint16(data[len(data)-9])
		logger.Debug("OpenConnectionRequest2 from %s, MTU=%d", sess.ClientAddr, mtu)
	}

	// Accumulate data for fragmented login packets
	if isFramed || hasLoginData {
		sess.AppendLoginData(data)
	}

	// Try to extract from current packet first
	if hasLoginData {
		playerInfo := f.protocolHandler.TryExtractPlayerInfoFromRaw(data)
		if playerInfo != nil && (playerInfo.UUID != "" || playerInfo.DisplayName != "") {
			// Requirement 2.4: Log format "Player connected: name=%s, uuid=%s, xuid=%s, client=%s"
			logger.Info("Player connected: name=%s, uuid=%s, xuid=%s, client=%s",
				playerInfo.DisplayName, playerInfo.UUID, playerInfo.XUID, sess.ClientAddr)
			sess.SetPlayerInfo(playerInfo.UUID, playerInfo.DisplayName)
			sess.ClearLoginBuffer()
			return
		}
	}

	// Try to extract from accumulated buffer (for fragmented packets)
	accumulatedData := sess.GetLoginBuffer()
	if len(accumulatedData) > 100 { // Only try if we have enough data
		playerInfo := f.protocolHandler.TryExtractPlayerInfoFromRaw(accumulatedData)
		if playerInfo != nil && (playerInfo.UUID != "" || playerInfo.DisplayName != "") {
			// Requirement 2.4: Log format "Player connected: name=%s, uuid=%s, xuid=%s, client=%s"
			logger.Info("Player connected: name=%s, uuid=%s, xuid=%s, client=%s",
				playerInfo.DisplayName, playerInfo.UUID, playerInfo.XUID, sess.ClientAddr)
			sess.SetPlayerInfo(playerInfo.UUID, playerInfo.DisplayName)
			sess.ClearLoginBuffer()
			return
		}
	}

	// Clear buffer if it gets too large (prevent memory leak)
	if len(accumulatedData) > 65536 {
		sess.ClearLoginBuffer()
	}
}

// containsLoginData checks if the packet might contain login data.
func containsLoginData(data []byte) bool {
	// Look for common patterns in login packets
	dataStr := string(data)

	// Check for JSON patterns in login data
	if strings.Contains(dataStr, "displayName") ||
		strings.Contains(dataStr, "identity") ||
		strings.Contains(dataStr, "extraData") ||
		strings.Contains(dataStr, "chain") {
		return true
	}

	// Check for JWT header pattern (base64 encoded '{"')
	// "eyJ" is the base64 encoding of '{"' which starts all JWT headers
	if strings.Contains(dataStr, "eyJ") {
		return true
	}

	// Check for game packet wrapper with login packet ID
	// 0xfe = game packet wrapper, followed by 0x01 = login packet
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0xfe && data[i+1] == 0x01 {
			return true
		}
	}

	return false
}

// injectRealIP injects the client's real IP address into the packet.
// This is used when send_real_ip is enabled in the server configuration.
//
// NOTE: This feature requires the remote server to support the PROXY protocol
// or a custom header format. Standard Minecraft servers do NOT support this.
// Only enable this if your target server has been modified to parse the header.
//
// Currently disabled to prevent connection issues with standard servers.
// The original packet is returned unchanged.
func (f *Forwarder) injectRealIP(data []byte, clientAddr string) []byte {
	// DISABLED: Standard MCBE servers don't support real IP injection.
	// Injecting custom headers breaks the RakNet protocol handshake.
	//
	// To enable this feature, the target server must be modified to:
	// 1. Detect the custom header format
	// 2. Extract the real IP before processing the RakNet packet
	//
	// For now, return the original data unchanged to ensure connectivity.
	return data

	/* Original implementation (breaks standard servers):
	// Parse the client address to extract IP
	host, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		return data
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return data
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		ipv4 = ip.To16()
	}

	// Custom header format: [0xFE] [0xFF] [IP_LEN] [IP_BYTES...] [ORIGINAL_DATA...]
	headerLen := 3 + len(ipv4)
	result := make([]byte, headerLen+len(data))
	result[0] = 0xFE
	result[1] = 0xFF
	result[2] = byte(len(ipv4))
	copy(result[3:3+len(ipv4)], ipv4)
	copy(result[headerLen:], data)
	return result
	*/
}

// BuildDisconnectPacket creates a disconnect packet with the given reason.
func (f *Forwarder) BuildDisconnectPacket(reason string) []byte {
	return f.protocolHandler.BuildDisconnectPacket(reason)
}

// BuildVersionMismatchPacket creates a disconnect packet for version mismatch.
func (f *Forwarder) BuildVersionMismatchPacket(clientVer, serverVer int32) []byte {
	return f.protocolHandler.BuildVersionMismatchPacket(clientVer, serverVer)
}

// ParsePacketForInfo attempts to parse a packet and extract any useful information.
// If parsing fails, it returns nil error to allow transparent forwarding.
func (f *Forwarder) ParsePacketForInfo(data []byte) (*protocol.PlayerInfo, error) {
	return f.protocolHandler.ParseLoginPacket(data)
}

// IsTransferPacket checks if the packet is a transfer packet.
func (f *Forwarder) IsTransferPacket(data []byte) bool {
	return f.protocolHandler.IsTransferPacket(data)
}

// ParseTransferPacket extracts transfer information from a transfer packet.
func (f *Forwarder) ParseTransferPacket(data []byte) (*protocol.TransferInfo, error) {
	return f.protocolHandler.ParseTransferPacket(data)
}

// ForwardRaw forwards raw data without any processing.
// This is used when packet parsing fails to ensure transparent forwarding.
func (f *Forwarder) ForwardRaw(conn *net.UDPConn, addr *net.UDPAddr, data []byte) error {
	_, err := conn.WriteToUDP(data, addr)
	return err
}

// ForwardRawToRemote forwards raw data to the remote server without processing.
func (f *Forwarder) ForwardRawToRemote(remoteConn *net.UDPConn, data []byte) error {
	_, err := remoteConn.Write(data)
	return err
}

// ExtractRealIP extracts the real IP from a packet with injected IP header.
// Returns the original data and the extracted IP, or nil if no header present.
func ExtractRealIP(data []byte) ([]byte, net.IP) {
	if len(data) < 4 {
		return data, nil
	}

	// Check for our custom header marker
	if data[0] != 0xFE || data[1] != 0xFF {
		return data, nil
	}

	ipLen := int(data[2])
	if ipLen != 4 && ipLen != 16 {
		return data, nil
	}

	if len(data) < 3+ipLen {
		return data, nil
	}

	ip := net.IP(data[3 : 3+ipLen])
	originalData := data[3+ipLen:]

	return originalData, ip
}

// CalculateChecksum calculates a simple checksum for packet verification.
func CalculateChecksum(data []byte) uint32 {
	var sum uint32
	for i := 0; i+3 < len(data); i += 4 {
		sum += binary.BigEndian.Uint32(data[i : i+4])
	}
	// Handle remaining bytes
	remaining := len(data) % 4
	if remaining > 0 {
		var last uint32
		for i := 0; i < remaining; i++ {
			last |= uint32(data[len(data)-remaining+i]) << (24 - 8*i)
		}
		sum += last
	}
	return sum
}
