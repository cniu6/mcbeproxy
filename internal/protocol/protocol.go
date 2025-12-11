// Package protocol provides MCBE/RakNet protocol handling using gophertunnel.
package protocol

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MCBE Protocol packet IDs
const (
	// RakNet packet IDs
	IDUnconnectedPing         byte = 0x01
	IDUnconnectedPingOpenConn byte = 0x02
	IDUnconnectedPong         byte = 0x1c
	IDOpenConnectionRequest1  byte = 0x05
	IDOpenConnectionReply1    byte = 0x06
	IDOpenConnectionRequest2  byte = 0x07
	IDOpenConnectionReply2    byte = 0x08
	IDConnectionRequest       byte = 0x09
	IDConnectionRequestAccept byte = 0x10
	IDNewIncomingConnection   byte = 0x13
	IDDisconnectNotification  byte = 0x15

	// MCBE game packet IDs (after RakNet layer)
	IDLogin      byte = 0x01
	IDPlayStatus byte = 0x02
	IDDisconnect byte = 0x05
	IDTransfer   byte = 0x55

	// Frame types
	FrameReliable            byte = 0x84
	FrameReliableOrdered     byte = 0x86
	FrameReliableSequenced   byte = 0x88
	FrameUnreliable          byte = 0x80
	FrameUnreliableSequenced byte = 0x82
)

// RakNet magic bytes used in connection handshake
var RakNetMagic = []byte{
	0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
}

// Common errors
var (
	ErrInvalidPacket     = errors.New("invalid packet")
	ErrPacketTooShort    = errors.New("packet too short")
	ErrInvalidMagic      = errors.New("invalid RakNet magic")
	ErrVersionMismatch   = errors.New("protocol version mismatch")
	ErrLoginParseFailed  = errors.New("failed to parse login packet")
	ErrNotLoginPacket    = errors.New("not a login packet")
	ErrNotTransferPacket = errors.New("not a transfer packet")
)

// PlayerInfo contains extracted player information from login packet.
type PlayerInfo struct {
	UUID        string
	DisplayName string
	XUID        string
	Protocol    int32
}

// TransferInfo contains transfer packet information.
type TransferInfo struct {
	Address string
	Port    uint16
}

// ProtocolHandler handles MCBE/RakNet protocol parsing and packet construction.
// It integrates with gophertunnel concepts for protocol handling.
type ProtocolHandler struct {
	// CurrentProtocolVersion is the latest supported protocol version
	CurrentProtocolVersion int32
}

// NewProtocolHandler creates a new protocol handler.
func NewProtocolHandler() *ProtocolHandler {
	return &ProtocolHandler{
		// Minecraft Bedrock 1.21.x protocol version
		CurrentProtocolVersion: 712,
	}
}

// DetectProtocolVersion detects the protocol version from a packet.
// It attempts to extract the protocol version from login packets or
// connection request packets.
func (ph *ProtocolHandler) DetectProtocolVersion(data []byte) (int32, error) {
	if len(data) < 1 {
		return 0, ErrPacketTooShort
	}

	// Check if this is a framed packet (RakNet reliability layer)
	packetID := data[0]

	// Handle framed packets
	if isFramedPacket(packetID) {
		// Extract the inner packet from the frame
		innerData, err := extractInnerPacket(data)
		if err != nil {
			return 0, err
		}
		if len(innerData) > 0 {
			data = innerData
			packetID = data[0]
		}
	}

	// Check for game packet wrapper (0xfe)
	if packetID == 0xfe && len(data) > 1 {
		// Game packet - decompress/unwrap if needed
		gameData := data[1:]
		if len(gameData) > 0 {
			return ph.extractVersionFromGamePacket(gameData)
		}
	}

	// Try to extract from login packet directly
	if packetID == IDLogin {
		return ph.extractVersionFromLogin(data)
	}

	return 0, ErrInvalidPacket
}

// extractVersionFromGamePacket extracts protocol version from game packet data.
func (ph *ProtocolHandler) extractVersionFromGamePacket(data []byte) (int32, error) {
	if len(data) < 5 {
		return 0, ErrPacketTooShort
	}

	// First byte should be packet ID (login = 0x01)
	if data[0] != IDLogin {
		return 0, ErrNotLoginPacket
	}

	return ph.extractVersionFromLogin(data)
}

// extractVersionFromLogin extracts protocol version from login packet.
func (ph *ProtocolHandler) extractVersionFromLogin(data []byte) (int32, error) {
	if len(data) < 5 {
		return 0, ErrPacketTooShort
	}

	// Login packet structure:
	// [0] = packet ID (0x01)
	// [1-4] = protocol version (big endian int32)
	version := int32(binary.BigEndian.Uint32(data[1:5]))
	return version, nil
}

// ParseLoginPacket extracts player information from a login packet.
// This operates in read-only mode without modifying packet contents.
func (ph *ProtocolHandler) ParseLoginPacket(data []byte) (*PlayerInfo, error) {
	if len(data) < 1 {
		return nil, ErrPacketTooShort
	}

	packetID := data[0]

	// Handle framed packets (RakNet reliability layer)
	if isFramedPacket(packetID) {
		innerData, err := extractInnerPacket(data)
		if err != nil {
			return nil, err
		}
		if len(innerData) > 0 {
			data = innerData
			packetID = data[0]
		}
	}

	// Check for game packet wrapper (0xfe)
	if packetID == 0xfe && len(data) > 1 {
		// Game packet - may be compressed
		gameData := data[1:]

		// Try to decompress if it looks compressed
		decompressed, err := ph.tryDecompress(gameData)
		if err == nil && len(decompressed) > 0 {
			data = decompressed
		} else {
			data = gameData
		}

		if len(data) > 0 {
			packetID = data[0]
		}
	}

	if packetID != IDLogin {
		return nil, ErrNotLoginPacket
	}

	return ph.parseLoginData(data)
}

// tryDecompress attempts to decompress game packet data.
// MCBE uses zlib compression for game packets.
func (ph *ProtocolHandler) tryDecompress(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, ErrPacketTooShort
	}

	// Try zlib decompression first (most common for MCBE)
	zlibReader, err := zlib.NewReader(bytes.NewReader(data))
	if err == nil {
		defer zlibReader.Close()
		var buf bytes.Buffer
		_, err = io.Copy(&buf, zlibReader)
		if err == nil && buf.Len() > 0 {
			return buf.Bytes(), nil
		}
	}

	// Try flate (raw deflate) as fallback
	flateReader := flate.NewReader(bytes.NewReader(data))
	defer flateReader.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, flateReader)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// parseLoginData parses the actual login packet data.
func (ph *ProtocolHandler) parseLoginData(data []byte) (*PlayerInfo, error) {
	if len(data) < 9 {
		return nil, ErrPacketTooShort
	}

	info := &PlayerInfo{}

	// Extract protocol version (bytes 1-4, big endian)
	info.Protocol = int32(binary.BigEndian.Uint32(data[1:5]))

	// The rest of the login packet contains:
	// - Chain data length (varint)
	// - Chain data (JWT tokens containing player info)
	// - Client data length (varint)
	// - Client data (JWT token)

	// Read the payload length (bytes 5-8, little endian uint32)
	if len(data) < 9 {
		return nil, ErrPacketTooShort
	}
	payloadLen := binary.LittleEndian.Uint32(data[5:9])

	// Validate payload length
	if len(data) < 9+int(payloadLen) {
		// Partial packet - try to extract what we can
		return ph.extractPlayerInfoFromPartialPayload(data[9:], info)
	}

	payload := data[9 : 9+payloadLen]
	return ph.extractPlayerInfoFromPayload(payload, info)
}

// extractPlayerInfoFromPayload extracts player info from the JWT payload.
func (ph *ProtocolHandler) extractPlayerInfoFromPayload(payload []byte, info *PlayerInfo) (*PlayerInfo, error) {
	// The payload contains chain data followed by client data
	// Chain data structure:
	// - Little endian uint32: chain length
	// - Chain JSON containing JWT tokens

	if len(payload) < 4 {
		return info, nil // Return partial info
	}

	chainLen := binary.LittleEndian.Uint32(payload[0:4])
	if len(payload) < 4+int(chainLen) {
		return ph.extractFromChainData(payload[4:], info)
	}

	chainData := payload[4 : 4+chainLen]
	return ph.extractFromChainData(chainData, info)
}

// extractPlayerInfoFromPartialPayload handles partial payload extraction.
func (ph *ProtocolHandler) extractPlayerInfoFromPartialPayload(payload []byte, info *PlayerInfo) (*PlayerInfo, error) {
	if len(payload) < 4 {
		return info, nil
	}
	return ph.extractFromChainData(payload[4:], info)
}

// extractFromChainData extracts player info from chain JSON data.
func (ph *ProtocolHandler) extractFromChainData(chainData []byte, info *PlayerInfo) (*PlayerInfo, error) {
	// Chain data is JSON: {"chain":["jwt1","jwt2",...]}
	// Each JWT contains base64 encoded JSON with player info

	chainStr := string(chainData)

	// Try to parse as JSON first
	var chainJSON struct {
		Chain []string `json:"chain"`
	}

	if err := json.Unmarshal(chainData, &chainJSON); err == nil {
		// Parse each JWT in the chain
		for _, jwt := range chainJSON.Chain {
			playerInfo := ph.parseJWT(jwt)
			if playerInfo.DisplayName != "" {
				info.DisplayName = playerInfo.DisplayName
			}
			if playerInfo.UUID != "" {
				info.UUID = playerInfo.UUID
			}
			if playerInfo.XUID != "" {
				info.XUID = playerInfo.XUID
			}
		}
		return info, nil
	}

	// Fallback: Simple extraction using string patterns
	info.DisplayName = extractJSONString(chainStr, "displayName")
	if info.DisplayName == "" {
		info.DisplayName = extractJSONString(chainStr, "DisplayName")
	}

	info.UUID = extractJSONString(chainStr, "identity")
	if info.UUID == "" {
		info.UUID = extractJSONString(chainStr, "Identity")
	}

	info.XUID = extractJSONString(chainStr, "XUID")

	return info, nil
}

// parseJWT parses a JWT token and extracts player info from the payload.
func (ph *ProtocolHandler) parseJWT(jwt string) PlayerInfo {
	info := PlayerInfo{}

	// JWT format: header.payload.signature
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return info
	}

	// Decode the payload (second part)
	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return info
		}
	}

	// Parse the JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return info
	}

	// Extract extraData if present (contains player info)
	if extraData, ok := claims["extraData"].(map[string]interface{}); ok {
		if displayName, ok := extraData["displayName"].(string); ok {
			info.DisplayName = displayName
		}
		if identity, ok := extraData["identity"].(string); ok {
			info.UUID = identity
		}
		if xuid, ok := extraData["XUID"].(string); ok {
			info.XUID = xuid
		}
	}

	// Also check top-level claims
	if displayName, ok := claims["displayName"].(string); ok && info.DisplayName == "" {
		info.DisplayName = displayName
	}
	if identity, ok := claims["identity"].(string); ok && info.UUID == "" {
		info.UUID = identity
	}

	return info
}

// extractJSONString extracts a string value from JSON-like data.
// This is a simple extraction that doesn't require full JSON parsing.
func extractJSONString(data, key string) string {
	// Look for "key":"value" or "key": "value" patterns
	patterns := []string{
		fmt.Sprintf(`"%s":"`, key),
		fmt.Sprintf(`"%s": "`, key),
	}

	for _, pattern := range patterns {
		idx := bytes.Index([]byte(data), []byte(pattern))
		if idx >= 0 {
			start := idx + len(pattern)
			end := start
			for end < len(data) && data[end] != '"' {
				if data[end] == '\\' && end+1 < len(data) {
					end += 2 // Skip escaped character
					continue
				}
				end++
			}
			if end > start {
				return data[start:end]
			}
		}
	}
	return ""
}

// isFramedPacket checks if the packet ID indicates a RakNet framed packet.
func isFramedPacket(packetID byte) bool {
	// RakNet frame types are in range 0x80-0x8f
	return packetID >= 0x80 && packetID <= 0x8f
}

// extractInnerPacket extracts the inner packet from a RakNet frame.
func extractInnerPacket(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, ErrPacketTooShort
	}

	// RakNet frame structure:
	// [0] = frame type
	// [1-3] = sequence number (3 bytes, little endian)
	// [4+] = frame data

	// Frame data structure:
	// [0] = reliability + flags (1 byte)
	// [1-2] = bit length (2 bytes, big endian)
	// [3+] = reliable message number (if reliable, 3 bytes)
	// [+] = sequencing index (if sequenced, 3 bytes)
	// [+] = ordering index + channel (if ordered, 4 bytes)
	// [+] = split info (if split, 10 bytes)
	// [+] = actual packet data

	offset := 4 // Skip frame type and sequence number

	if offset >= len(data) {
		return nil, ErrPacketTooShort
	}

	reliability := (data[offset] & 0xe0) >> 5
	hasSplit := (data[offset] & 0x10) != 0
	offset++

	if offset+2 > len(data) {
		return nil, ErrPacketTooShort
	}

	// Bit length (big endian)
	bitLength := binary.BigEndian.Uint16(data[offset : offset+2])
	byteLength := (bitLength + 7) / 8
	offset += 2

	// Skip reliable message number if reliable
	if reliability >= 2 && reliability <= 4 {
		offset += 3
	}

	// Skip sequencing index if sequenced
	if reliability == 1 || reliability == 4 {
		offset += 3
	}

	// Skip ordering info if ordered
	if reliability == 1 || reliability == 3 || reliability == 4 || reliability == 7 {
		offset += 4
	}

	// Skip split info if split
	if hasSplit {
		offset += 10
	}

	if offset >= len(data) {
		return nil, ErrPacketTooShort
	}

	endOffset := offset + int(byteLength)
	if endOffset > len(data) {
		endOffset = len(data)
	}

	return data[offset:endOffset], nil
}

// BuildDisconnectPacket constructs a valid MCBE disconnect packet with the given reason.
// The packet follows MCBE protocol specification for disconnect packets.
func (ph *ProtocolHandler) BuildDisconnectPacket(reason string) []byte {
	// Disconnect packet structure:
	// [0] = 0xfe (game packet wrapper)
	// [1] = packet ID (0x05 = disconnect)
	// [2] = hide disconnect screen (bool, varint)
	// [3+] = message (string with length prefix)

	// Calculate message length as varint
	messageBytes := []byte(reason)
	messageLen := len(messageBytes)

	// Build the packet
	buf := &bytes.Buffer{}

	// Game packet wrapper
	buf.WriteByte(0xfe)

	// Disconnect packet ID
	buf.WriteByte(IDDisconnect)

	// Hide disconnect screen (false = 0, show the message)
	buf.WriteByte(0x00)

	// Message length as varint
	writeVarInt(buf, int32(messageLen))

	// Message content
	buf.Write(messageBytes)

	return buf.Bytes()
}

// BuildVersionMismatchPacket constructs a disconnect packet for protocol version mismatch.
// It includes information about both client and server versions.
func (ph *ProtocolHandler) BuildVersionMismatchPacket(clientVer, serverVer int32) []byte {
	reason := fmt.Sprintf("Outdated client! Please use version %d (your version: %d)", serverVer, clientVer)
	if clientVer > serverVer {
		reason = fmt.Sprintf("Outdated server! Server version: %d (your version: %d)", serverVer, clientVer)
	}
	return ph.BuildDisconnectPacket(reason)
}

// BuildPlayStatusPacket constructs a play status packet.
// Status codes:
// 0 = Login success
// 1 = Failed client
// 2 = Failed server
// 3 = Player spawn
// 4 = Failed invalid tenant
// 5 = Failed vanilla edu
// 6 = Failed edu vanilla
// 7 = Failed server full
func (ph *ProtocolHandler) BuildPlayStatusPacket(status int32) []byte {
	buf := &bytes.Buffer{}

	// Game packet wrapper
	buf.WriteByte(0xfe)

	// Play status packet ID
	buf.WriteByte(IDPlayStatus)

	// Status (big endian int32)
	binary.Write(buf, binary.BigEndian, status)

	return buf.Bytes()
}

// writeVarInt writes a variable-length integer to the buffer.
func writeVarInt(buf *bytes.Buffer, value int32) {
	uvalue := uint32(value)
	for {
		b := byte(uvalue & 0x7f)
		uvalue >>= 7
		if uvalue != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if uvalue == 0 {
			break
		}
	}
}

// readVarInt reads a variable-length integer from data starting at offset.
// Returns the value and the number of bytes read.
func readVarInt(data []byte, offset int) (int32, int, error) {
	if offset >= len(data) {
		return 0, 0, ErrPacketTooShort
	}

	var result uint32
	var shift uint
	var bytesRead int

	for {
		if offset+bytesRead >= len(data) {
			return 0, 0, ErrPacketTooShort
		}

		b := data[offset+bytesRead]
		bytesRead++

		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7

		if shift >= 35 {
			return 0, 0, ErrInvalidPacket
		}
	}

	return int32(result), bytesRead, nil
}

// IsTransferPacket checks if the packet is a transfer packet.
func (ph *ProtocolHandler) IsTransferPacket(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	packetID := data[0]

	// Handle game packet wrapper
	if packetID == 0xfe && len(data) > 1 {
		packetID = data[1]
	}

	// Handle framed packets
	if isFramedPacket(packetID) {
		innerData, err := extractInnerPacket(data)
		if err != nil {
			return false
		}
		if len(innerData) > 0 {
			packetID = innerData[0]
			// Check for game packet wrapper in inner data
			if packetID == 0xfe && len(innerData) > 1 {
				packetID = innerData[1]
			}
		}
	}

	return packetID == IDTransfer
}

// ParseTransferPacket extracts transfer information from a transfer packet.
func (ph *ProtocolHandler) ParseTransferPacket(data []byte) (*TransferInfo, error) {
	if len(data) < 2 {
		return nil, ErrPacketTooShort
	}

	packetID := data[0]
	offset := 0

	// Handle game packet wrapper
	if packetID == 0xfe {
		offset = 1
		if len(data) <= offset {
			return nil, ErrPacketTooShort
		}
		packetID = data[offset]
		offset++
	} else if isFramedPacket(packetID) {
		// Handle framed packets
		innerData, err := extractInnerPacket(data)
		if err != nil {
			return nil, err
		}
		data = innerData
		offset = 0
		if len(data) > 0 {
			packetID = data[0]
			offset = 1
			// Check for game packet wrapper
			if packetID == 0xfe && len(data) > 1 {
				packetID = data[1]
				offset = 2
			}
		}
	} else {
		offset = 1
	}

	if packetID != IDTransfer {
		return nil, ErrNotTransferPacket
	}

	// Transfer packet structure:
	// [0] = packet ID (0x55)
	// [1+] = address (string with varint length prefix)
	// [+] = port (uint16, little endian)

	// Read address length
	addrLen, bytesRead, err := readVarInt(data, offset)
	if err != nil {
		return nil, err
	}
	offset += bytesRead

	if offset+int(addrLen) > len(data) {
		return nil, ErrPacketTooShort
	}

	address := string(data[offset : offset+int(addrLen)])
	offset += int(addrLen)

	// Read port
	if offset+2 > len(data) {
		return nil, ErrPacketTooShort
	}

	port := binary.LittleEndian.Uint16(data[offset : offset+2])

	return &TransferInfo{
		Address: address,
		Port:    port,
	}, nil
}

// BuildTransferPacket constructs a transfer packet to redirect the client.
func (ph *ProtocolHandler) BuildTransferPacket(address string, port uint16) []byte {
	buf := &bytes.Buffer{}

	// Game packet wrapper
	buf.WriteByte(0xfe)

	// Transfer packet ID
	buf.WriteByte(IDTransfer)

	// Address (string with varint length prefix)
	writeVarInt(buf, int32(len(address)))
	buf.WriteString(address)

	// Port (little endian uint16)
	binary.Write(buf, binary.LittleEndian, port)

	return buf.Bytes()
}

// TryExtractPlayerInfoFromRaw attempts to extract player info from raw packet data
// by searching for known patterns in the data.
func (ph *ProtocolHandler) TryExtractPlayerInfoFromRaw(data []byte) *PlayerInfo {
	if len(data) < 10 {
		return nil
	}

	info := &PlayerInfo{}

	// First, try to decompress the data if it looks compressed
	decompressed := ph.tryDecompressData(data)
	if decompressed != nil && len(decompressed) > len(data) {
		data = decompressed
	}

	dataStr := string(data)

	// Look for displayName in the raw data
	info.DisplayName = extractJSONString(dataStr, "displayName")
	if info.DisplayName == "" {
		info.DisplayName = extractJSONString(dataStr, "DisplayName")
	}

	// Look for identity (UUID)
	info.UUID = extractJSONString(dataStr, "identity")
	if info.UUID == "" {
		info.UUID = extractJSONString(dataStr, "Identity")
	}

	// Look for XUID
	info.XUID = extractJSONString(dataStr, "XUID")

	// Try to find and parse JWT tokens in the data
	if info.DisplayName == "" && info.UUID == "" {
		// Look for JWT pattern (base64.base64.base64)
		jwtTokens := findAllJWTsInData(dataStr)
		for _, jwt := range jwtTokens {
			jwtInfo := ph.parseJWT(jwt)
			if jwtInfo.DisplayName != "" && info.DisplayName == "" {
				info.DisplayName = jwtInfo.DisplayName
			}
			if jwtInfo.UUID != "" && info.UUID == "" {
				info.UUID = jwtInfo.UUID
			}
			if jwtInfo.XUID != "" && info.XUID == "" {
				info.XUID = jwtInfo.XUID
			}
		}
	}

	if info.DisplayName == "" && info.UUID == "" {
		return nil
	}

	return info
}

// tryDecompressData attempts to decompress data using various methods.
func (ph *ProtocolHandler) tryDecompressData(data []byte) []byte {
	// Skip if too short
	if len(data) < 10 {
		return nil
	}

	// Try to find compressed data starting point
	// MCBE packets may have headers before compressed data
	for offset := 0; offset < len(data) && offset < 20; offset++ {
		// Try zlib (starts with 0x78)
		if data[offset] == 0x78 && offset+1 < len(data) {
			result, err := ph.tryDecompress(data[offset:])
			if err == nil && len(result) > 0 {
				return result
			}
		}
	}

	return nil
}

// findAllJWTsInData finds all JWT tokens in the data.
func findAllJWTsInData(data string) []string {
	var jwts []string

	// Look for eyJ pattern which is the base64 encoding of {"
	// This is how JWT headers typically start
	idx := 0
	for {
		start := strings.Index(data[idx:], "eyJ")
		if start == -1 {
			break
		}
		start += idx

		// Find the JWT boundaries
		jwt := extractJWTAt(data, start)
		if jwt != "" {
			jwts = append(jwts, jwt)
		}

		idx = start + 3
		if idx >= len(data) {
			break
		}
	}

	return jwts
}

// extractJWTAt extracts a JWT token starting at the given position.
func extractJWTAt(data string, start int) string {
	// JWT format: header.payload.signature
	// Each part is base64url encoded

	end := start
	dotCount := 0

	for end < len(data) {
		c := data[end]
		if c == '.' {
			dotCount++
			if dotCount > 2 {
				break
			}
		} else if !isBase64URLChar(c) {
			break
		}
		end++
	}

	if dotCount >= 2 && end > start+10 {
		jwt := data[start:end]
		// Validate it has 3 parts
		parts := strings.Split(jwt, ".")
		if len(parts) >= 3 && len(parts[0]) > 5 && len(parts[1]) > 5 {
			return jwt
		}
	}

	return ""
}

// isBase64URLChar checks if a character is valid in base64url encoding.
func isBase64URLChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '=' || c == '+'
}

// findJWTInData looks for JWT token patterns in the data.
func findJWTInData(data string) string {
	// JWT format: xxxxx.yyyyy.zzzzz (base64url encoded parts)
	// Look for patterns that look like JWT
	parts := strings.Split(data, ".")
	for i := 0; i < len(parts)-2; i++ {
		// Check if this could be a JWT (3 consecutive base64-like parts)
		part1 := parts[i]
		part2 := parts[i+1]
		part3 := parts[i+2]

		// Find the start of part1 (look for beginning of base64)
		start := strings.LastIndexAny(part1, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\"[{")
		if start >= 0 && start < len(part1)-1 {
			part1 = part1[start+1:]
		}

		// Find the end of part3 (look for end of base64)
		end := strings.IndexAny(part3, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\"]}")
		if end > 0 {
			part3 = part3[:end]
		}

		// Check if parts look like base64
		if isBase64Like(part1) && isBase64Like(part2) && len(part1) > 10 && len(part2) > 10 {
			jwt := part1 + "." + part2 + "." + part3
			return jwt
		}
	}
	return ""
}

// isBase64Like checks if a string looks like base64 encoded data.
func isBase64Like(s string) bool {
	if len(s) < 4 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			c == '-' || c == '_' || c == '=') {
			return false
		}
	}
	return true
}
