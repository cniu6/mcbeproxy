// Package session provides session management for client connections.
package session

import (
	"encoding/json"
	"mcpeserverproxy/internal/logger"
	"net"
	"sync"
	"time"
)

// Session represents a client connection session with statistics.
type Session struct {
	ID          string       `json:"id"`
	ClientAddr  string       `json:"client_addr"`
	RemoteConn  *net.UDPConn `json:"-"` // Excluded from JSON serialization
	ServerID    string       `json:"server_id"`
	UUID        string       `json:"uuid,omitempty"`
	DisplayName string       `json:"display_name,omitempty"`
	XUID        string       `json:"xuid,omitempty"` // Xbox User ID (Requirements 2.1, 2.3, 2.5)
	BytesUp     int64        `json:"bytes_up"`
	BytesDown   int64        `json:"bytes_down"`
	StartTime   time.Time    `json:"start_time"`
	LastSeen    time.Time    `json:"last_seen"`
	mu          sync.Mutex   `json:"-"`

	// Login packet reassembly buffer for fragmented RakNet packets
	LoginBuffer     []byte     `json:"-"`
	LoginBufferLock sync.Mutex `json:"-"`
	LoginExtracted  bool       `json:"-"` // Whether we've already extracted login info
}

// AddBytesUp adds bytes to the upload counter in a thread-safe manner.
func (s *Session) AddBytesUp(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BytesUp += n
}

// AddBytesDown adds bytes to the download counter in a thread-safe manner.
func (s *Session) AddBytesDown(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BytesDown += n
}

// UpdateLastSeen updates the last seen timestamp to current time.
func (s *Session) UpdateLastSeen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSeen = time.Now()
}

// SetPlayerInfo sets the player UUID, display name, and XUID.
// Logs the player connect event per requirement 9.5.
// Requirements: 2.1, 2.2, 2.3, 2.5
func (s *Session) SetPlayerInfo(uuid, displayName string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only log if this is the first time setting player info
	if s.UUID == "" && uuid != "" {
		// Requirement 2.4: Log format "Player connected: name=%s, uuid=%s, xuid=%s, client=%s"
		// XUID is empty for non-MITM proxy mode
		logger.LogPlayerConnect(displayName, uuid, "", s.ClientAddr)
	}

	s.UUID = uuid
	s.DisplayName = displayName
	s.LoginExtracted = true
}

// SetPlayerInfoWithXUID sets the player UUID, display name, and XUID.
// This is the enhanced version that includes XUID for Xbox Live authentication.
// Requirements: 2.1, 2.2, 2.3, 2.5
func (s *Session) SetPlayerInfoWithXUID(uuid, displayName, xuid string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only log if this is the first time setting player info
	if s.UUID == "" && uuid != "" {
		// Requirement 2.4: Log format "Player connected: name=%s, uuid=%s, xuid=%s, client=%s"
		logger.LogPlayerConnect(displayName, uuid, xuid, s.ClientAddr)
	}

	s.UUID = uuid
	s.DisplayName = displayName
	s.XUID = xuid
	s.LoginExtracted = true
}

// GetXUID returns the player's Xbox User ID.
func (s *Session) GetXUID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.XUID
}

// AppendLoginData appends data to the login buffer for packet reassembly.
func (s *Session) AppendLoginData(data []byte) {
	s.LoginBufferLock.Lock()
	defer s.LoginBufferLock.Unlock()
	s.LoginBuffer = append(s.LoginBuffer, data...)
}

// GetLoginBuffer returns a copy of the current login buffer.
func (s *Session) GetLoginBuffer() []byte {
	s.LoginBufferLock.Lock()
	defer s.LoginBufferLock.Unlock()
	if s.LoginBuffer == nil {
		return nil
	}
	buf := make([]byte, len(s.LoginBuffer))
	copy(buf, s.LoginBuffer)
	return buf
}

// ClearLoginBuffer clears the login buffer to free memory.
func (s *Session) ClearLoginBuffer() {
	s.LoginBufferLock.Lock()
	defer s.LoginBufferLock.Unlock()
	s.LoginBuffer = nil
}

// IsLoginExtracted returns whether login info has been extracted.
func (s *Session) IsLoginExtracted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.LoginExtracted
}

// ToDTO converts the session to a DTO for API responses.
func (s *Session) ToDTO() SessionDTO {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionDTO{
		ID:          s.ID,
		ClientAddr:  s.ClientAddr,
		ServerID:    s.ServerID,
		UUID:        s.UUID,
		DisplayName: s.DisplayName,
		XUID:        s.XUID,
		BytesUp:     s.BytesUp,
		BytesDown:   s.BytesDown,
		StartTime:   s.StartTime,
		Duration:    int64(time.Since(s.StartTime).Seconds()),
	}
}

// SessionDTO is the data transfer object for session API responses.
type SessionDTO struct {
	ID          string    `json:"id"`
	ClientAddr  string    `json:"client_addr"`
	ServerID    string    `json:"server_id"`
	UUID        string    `json:"uuid,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	XUID        string    `json:"xuid,omitempty"`
	BytesUp     int64     `json:"bytes_up"`
	BytesDown   int64     `json:"bytes_down"`
	StartTime   time.Time `json:"start_time"`
	Duration    int64     `json:"duration_seconds"`
}

// SessionRecord represents a session record for database persistence.
type SessionRecord struct {
	ID          string    `json:"id"`
	ClientAddr  string    `json:"client_addr"`
	ServerID    string    `json:"server_id"`
	UUID        string    `json:"uuid,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	XUID        string    `json:"xuid,omitempty"` // Xbox User ID (Requirements 2.5)
	BytesUp     int64     `json:"bytes_up"`
	BytesDown   int64     `json:"bytes_down"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time,omitempty"`
	Metadata    string    `json:"metadata,omitempty"` // JSON encoded additional data
}

// ToJSON serializes the session record to JSON.
func (sr *SessionRecord) ToJSON() ([]byte, error) {
	return json.Marshal(sr)
}

// SessionRecordFromJSON deserializes a session record from JSON.
func SessionRecordFromJSON(data []byte) (*SessionRecord, error) {
	var sr SessionRecord
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}
