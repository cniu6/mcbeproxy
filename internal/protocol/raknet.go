// Package protocol provides MCBE/RakNet protocol handling.
package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"time"
)

// RakNet reliability types
const (
	ReliabilityUnreliable          byte = 0
	ReliabilityUnreliableSequenced byte = 1
	ReliabilityReliable            byte = 2
	ReliabilityReliableOrdered     byte = 3
	ReliabilityReliableSequenced   byte = 4
)

// RakNet connection states
const (
	StateDisconnected = iota
	StateConnecting
	StateConnected
)

// Additional errors for RakNet handling
var (
	ErrFragmentMissing   = errors.New("missing fragment")
	ErrFragmentDuplicate = errors.New("duplicate fragment")
	ErrInvalidFragment   = errors.New("invalid fragment")
	ErrConnectionTimeout = errors.New("connection timeout")
)

// UnconnectedPing represents an unconnected ping packet.
type UnconnectedPing struct {
	SendTimestamp int64
	ClientGUID    int64
}

// UnconnectedPong represents an unconnected pong packet.
type UnconnectedPong struct {
	SendTimestamp int64
	ServerGUID    int64
	ServerID      string // MOTD string
}

// Fragment represents a packet fragment for reassembly.
type Fragment struct {
	SplitID    uint16
	SplitIndex uint32
	SplitCount uint32
	Data       []byte
	Received   time.Time
}

// FragmentAssembler handles packet fragment reassembly.
type FragmentAssembler struct {
	fragments map[uint16]map[uint32]*Fragment // splitID -> splitIndex -> fragment
	mu        sync.Mutex
	timeout   time.Duration
}

// RakNetHandler handles RakNet layer protocol operations.
type RakNetHandler struct {
	ServerGUID        int64
	ServerID          string // MOTD string
	fragmentAssembler *FragmentAssembler
	mu                sync.RWMutex
}

// NewRakNetHandler creates a new RakNet handler.
func NewRakNetHandler(serverGUID int64, serverID string) *RakNetHandler {
	return &RakNetHandler{
		ServerGUID: serverGUID,
		ServerID:   serverID,
		fragmentAssembler: &FragmentAssembler{
			fragments: make(map[uint16]map[uint32]*Fragment),
			timeout:   30 * time.Second,
		},
	}
}

// HandleUnconnectedPing handles an unconnected ping packet and returns a pong response.
func (rh *RakNetHandler) HandleUnconnectedPing(data []byte) ([]byte, error) {
	if len(data) < 33 {
		return nil, ErrPacketTooShort
	}

	// Unconnected ping structure:
	// [0] = packet ID (0x01 or 0x02)
	// [1-8] = send timestamp (int64, big endian)
	// [9-24] = magic (16 bytes)
	// [25-32] = client GUID (int64, big endian)

	packetID := data[0]
	if packetID != IDUnconnectedPing && packetID != IDUnconnectedPingOpenConn {
		return nil, ErrInvalidPacket
	}

	// Verify magic
	if !bytes.Equal(data[9:25], RakNetMagic) {
		return nil, ErrInvalidMagic
	}

	sendTimestamp := int64(binary.BigEndian.Uint64(data[1:9]))

	// Build pong response
	return rh.buildUnconnectedPong(sendTimestamp), nil
}

// buildUnconnectedPong builds an unconnected pong packet.
func (rh *RakNetHandler) buildUnconnectedPong(sendTimestamp int64) []byte {
	rh.mu.RLock()
	serverID := rh.ServerID
	serverGUID := rh.ServerGUID
	rh.mu.RUnlock()

	// Unconnected pong structure:
	// [0] = packet ID (0x1c)
	// [1-8] = send timestamp (int64, big endian)
	// [9-16] = server GUID (int64, big endian)
	// [17-32] = magic (16 bytes)
	// [33-34] = server ID length (uint16, big endian)
	// [35+] = server ID string

	buf := &bytes.Buffer{}

	// Packet ID
	buf.WriteByte(IDUnconnectedPong)

	// Send timestamp
	binary.Write(buf, binary.BigEndian, sendTimestamp)

	// Server GUID
	binary.Write(buf, binary.BigEndian, serverGUID)

	// Magic
	buf.Write(RakNetMagic)

	// Server ID (MOTD) with length prefix
	serverIDBytes := []byte(serverID)
	binary.Write(buf, binary.BigEndian, uint16(len(serverIDBytes)))
	buf.Write(serverIDBytes)

	return buf.Bytes()
}

// UpdateServerID updates the server MOTD string.
func (rh *RakNetHandler) UpdateServerID(serverID string) {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	rh.ServerID = serverID
}

// HandleConnectionRequest handles connection handshake packets.
// Returns the appropriate response packet or nil if no response is needed.
func (rh *RakNetHandler) HandleConnectionRequest(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, ErrPacketTooShort
	}

	packetID := data[0]

	switch packetID {
	case IDOpenConnectionRequest1:
		return rh.handleOpenConnectionRequest1(data)
	case IDOpenConnectionRequest2:
		return rh.handleOpenConnectionRequest2(data)
	case IDConnectionRequest:
		return rh.handleConnectionRequest(data)
	default:
		return nil, nil // Not a connection request packet
	}
}

// handleOpenConnectionRequest1 handles the first connection request.
func (rh *RakNetHandler) handleOpenConnectionRequest1(data []byte) ([]byte, error) {
	// OpenConnectionRequest1 structure:
	// [0] = packet ID (0x05)
	// [1-16] = magic (16 bytes)
	// [17] = protocol version
	// [18+] = MTU padding

	if len(data) < 18 {
		return nil, ErrPacketTooShort
	}

	// Verify magic
	if !bytes.Equal(data[1:17], RakNetMagic) {
		return nil, ErrInvalidMagic
	}

	// Calculate MTU from packet size
	mtuSize := uint16(len(data) + 28) // Add UDP/IP header size

	// Build OpenConnectionReply1
	return rh.buildOpenConnectionReply1(mtuSize), nil
}

// buildOpenConnectionReply1 builds the first connection reply.
func (rh *RakNetHandler) buildOpenConnectionReply1(mtuSize uint16) []byte {
	// OpenConnectionReply1 structure:
	// [0] = packet ID (0x06)
	// [1-16] = magic (16 bytes)
	// [17-24] = server GUID (int64, big endian)
	// [25] = use security (bool)
	// [26-27] = MTU size (uint16, big endian)

	buf := &bytes.Buffer{}

	buf.WriteByte(IDOpenConnectionReply1)
	buf.Write(RakNetMagic)
	binary.Write(buf, binary.BigEndian, rh.ServerGUID)
	buf.WriteByte(0x00) // No security
	binary.Write(buf, binary.BigEndian, mtuSize)

	return buf.Bytes()
}

// handleOpenConnectionRequest2 handles the second connection request.
func (rh *RakNetHandler) handleOpenConnectionRequest2(data []byte) ([]byte, error) {
	// OpenConnectionRequest2 structure:
	// [0] = packet ID (0x07)
	// [1-16] = magic (16 bytes)
	// [17-23] = server address (7 bytes for IPv4)
	// [24-25] = MTU size (uint16, big endian)
	// [26-33] = client GUID (int64, big endian)

	if len(data) < 34 {
		return nil, ErrPacketTooShort
	}

	// Verify magic
	if !bytes.Equal(data[1:17], RakNetMagic) {
		return nil, ErrInvalidMagic
	}

	mtuSize := binary.BigEndian.Uint16(data[24:26])
	clientGUID := int64(binary.BigEndian.Uint64(data[26:34]))

	// Build OpenConnectionReply2
	return rh.buildOpenConnectionReply2(mtuSize, clientGUID), nil
}

// buildOpenConnectionReply2 builds the second connection reply.
func (rh *RakNetHandler) buildOpenConnectionReply2(mtuSize uint16, clientGUID int64) []byte {
	// OpenConnectionReply2 structure:
	// [0] = packet ID (0x08)
	// [1-16] = magic (16 bytes)
	// [17-24] = server GUID (int64, big endian)
	// [25-31] = client address (7 bytes for IPv4)
	// [32-33] = MTU size (uint16, big endian)
	// [34] = use encryption (bool)

	buf := &bytes.Buffer{}

	buf.WriteByte(IDOpenConnectionReply2)
	buf.Write(RakNetMagic)
	binary.Write(buf, binary.BigEndian, rh.ServerGUID)

	// Client address placeholder (IPv4: 4 + port: 2 + family: 1 = 7 bytes)
	buf.WriteByte(0x04)           // IPv4 family
	buf.Write([]byte{0, 0, 0, 0}) // IP placeholder
	buf.Write([]byte{0, 0})       // Port placeholder

	binary.Write(buf, binary.BigEndian, mtuSize)
	buf.WriteByte(0x00) // No encryption

	return buf.Bytes()
}

// handleConnectionRequest handles the connection request packet.
func (rh *RakNetHandler) handleConnectionRequest(data []byte) ([]byte, error) {
	// ConnectionRequest structure:
	// [0] = packet ID (0x09)
	// [1-8] = client GUID (int64, big endian)
	// [9-16] = timestamp (int64, big endian)
	// [17] = use security (bool)

	if len(data) < 18 {
		return nil, ErrPacketTooShort
	}

	clientGUID := int64(binary.BigEndian.Uint64(data[1:9]))
	timestamp := int64(binary.BigEndian.Uint64(data[9:17]))

	// Build ConnectionRequestAccepted
	return rh.buildConnectionRequestAccepted(clientGUID, timestamp), nil
}

// buildConnectionRequestAccepted builds the connection accepted packet.
func (rh *RakNetHandler) buildConnectionRequestAccepted(clientGUID int64, timestamp int64) []byte {
	buf := &bytes.Buffer{}

	buf.WriteByte(IDConnectionRequestAccept)

	// Client address (7 bytes for IPv4)
	buf.WriteByte(0x04)           // IPv4 family
	buf.Write([]byte{0, 0, 0, 0}) // IP placeholder
	buf.Write([]byte{0, 0})       // Port placeholder

	// System index (2 bytes)
	binary.Write(buf, binary.BigEndian, uint16(0))

	// Internal addresses (10 addresses * 7 bytes each)
	for i := 0; i < 10; i++ {
		buf.WriteByte(0x04) // IPv4 family
		buf.Write([]byte{0, 0, 0, 0})
		buf.Write([]byte{0, 0})
	}

	// Request timestamp
	binary.Write(buf, binary.BigEndian, timestamp)

	// Reply timestamp
	binary.Write(buf, binary.BigEndian, time.Now().UnixMilli())

	return buf.Bytes()
}

// GetPacketReliability extracts the reliability type from a framed packet.
func (rh *RakNetHandler) GetPacketReliability(data []byte) int {
	if len(data) < 5 {
		return -1
	}

	// Check if this is a framed packet
	packetID := data[0]
	if !isFramedPacket(packetID) {
		return -1
	}

	// Reliability is in the first byte after the sequence number
	// Frame structure: [type][seq0][seq1][seq2][reliability|flags]...
	reliabilityByte := data[4]
	reliability := (reliabilityByte & 0xe0) >> 5

	return int(reliability)
}

// ReassembleFragments attempts to reassemble fragmented packets.
// Returns the complete packet if all fragments are received, nil otherwise.
func (rh *RakNetHandler) ReassembleFragments(fragments [][]byte) ([]byte, error) {
	if len(fragments) == 0 {
		return nil, ErrFragmentMissing
	}

	// Parse fragment info from each fragment
	parsedFragments := make([]*Fragment, 0, len(fragments))

	for _, fragData := range fragments {
		frag, err := rh.parseFragment(fragData)
		if err != nil {
			continue // Skip invalid fragments
		}
		parsedFragments = append(parsedFragments, frag)
	}

	if len(parsedFragments) == 0 {
		return nil, ErrInvalidFragment
	}

	// Group by split ID
	splitID := parsedFragments[0].SplitID
	splitCount := parsedFragments[0].SplitCount

	// Verify all fragments belong to the same split
	fragmentMap := make(map[uint32]*Fragment)
	for _, frag := range parsedFragments {
		if frag.SplitID != splitID {
			continue
		}
		if frag.SplitIndex >= splitCount {
			continue
		}
		fragmentMap[frag.SplitIndex] = frag
	}

	// Check if we have all fragments
	if uint32(len(fragmentMap)) != splitCount {
		return nil, ErrFragmentMissing
	}

	// Sort and concatenate
	indices := make([]uint32, 0, len(fragmentMap))
	for idx := range fragmentMap {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return indices[i] < indices[j]
	})

	var result bytes.Buffer
	for _, idx := range indices {
		result.Write(fragmentMap[idx].Data)
	}

	return result.Bytes(), nil
}

// parseFragment parses fragment information from a framed packet.
func (rh *RakNetHandler) parseFragment(data []byte) (*Fragment, error) {
	if len(data) < 5 {
		return nil, ErrPacketTooShort
	}

	// Check if this is a framed packet
	if !isFramedPacket(data[0]) {
		return nil, ErrInvalidFragment
	}

	offset := 4 // Skip frame type and sequence number

	if offset >= len(data) {
		return nil, ErrPacketTooShort
	}

	reliabilityByte := data[offset]
	reliability := (reliabilityByte & 0xe0) >> 5
	hasSplit := (reliabilityByte & 0x10) != 0
	offset++

	if !hasSplit {
		return nil, ErrInvalidFragment // Not a split packet
	}

	// Skip bit length
	if offset+2 > len(data) {
		return nil, ErrPacketTooShort
	}
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

	// Read split info
	if offset+10 > len(data) {
		return nil, ErrPacketTooShort
	}

	splitCount := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	splitID := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	splitIndex := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Extract fragment data
	endOffset := offset + int(byteLength)
	if endOffset > len(data) {
		endOffset = len(data)
	}

	return &Fragment{
		SplitID:    splitID,
		SplitIndex: splitIndex,
		SplitCount: splitCount,
		Data:       data[offset:endOffset],
		Received:   time.Now(),
	}, nil
}

// AddFragment adds a fragment to the assembler and returns the complete packet if ready.
func (fa *FragmentAssembler) AddFragment(frag *Fragment) ([]byte, bool) {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	// Initialize split ID map if needed
	if fa.fragments[frag.SplitID] == nil {
		fa.fragments[frag.SplitID] = make(map[uint32]*Fragment)
	}

	// Add fragment
	fa.fragments[frag.SplitID][frag.SplitIndex] = frag

	// Check if complete
	if uint32(len(fa.fragments[frag.SplitID])) != frag.SplitCount {
		return nil, false
	}

	// Assemble
	indices := make([]uint32, 0, len(fa.fragments[frag.SplitID]))
	for idx := range fa.fragments[frag.SplitID] {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		return indices[i] < indices[j]
	})

	var result bytes.Buffer
	for _, idx := range indices {
		result.Write(fa.fragments[frag.SplitID][idx].Data)
	}

	// Clean up
	delete(fa.fragments, frag.SplitID)

	return result.Bytes(), true
}

// Cleanup removes stale fragments that have exceeded the timeout.
func (fa *FragmentAssembler) Cleanup() {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	now := time.Now()
	for splitID, frags := range fa.fragments {
		for _, frag := range frags {
			if now.Sub(frag.Received) > fa.timeout {
				delete(fa.fragments, splitID)
				break
			}
		}
	}
}

// IsUnconnectedPacket checks if the packet is an unconnected RakNet packet.
func IsUnconnectedPacket(data []byte) bool {
	if len(data) < 1 {
		return false
	}

	packetID := data[0]
	return packetID == IDUnconnectedPing ||
		packetID == IDUnconnectedPingOpenConn ||
		packetID == IDUnconnectedPong ||
		packetID == IDOpenConnectionRequest1 ||
		packetID == IDOpenConnectionReply1 ||
		packetID == IDOpenConnectionRequest2 ||
		packetID == IDOpenConnectionReply2
}

// IsConnectionPacket checks if the packet is a connection-related packet.
func IsConnectionPacket(data []byte) bool {
	if len(data) < 1 {
		return false
	}

	packetID := data[0]
	return packetID == IDConnectionRequest ||
		packetID == IDConnectionRequestAccept ||
		packetID == IDNewIncomingConnection ||
		packetID == IDDisconnectNotification
}
