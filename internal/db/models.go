// Package db provides database access and persistence functionality.
package db

import (
	"encoding/json"
	"time"
)

// PlayerRecord represents a player record in the database.
// DisplayName is the primary key since UUID can change between sessions.
type PlayerRecord struct {
	DisplayName   string    `json:"display_name"`
	UUID          string    `json:"uuid"`
	XUID          string    `json:"xuid"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	TotalBytes    int64     `json:"total_bytes"`
	TotalPlaytime int64     `json:"total_playtime"` // seconds
	Metadata      string    `json:"metadata,omitempty"`
}

// ToJSON serializes the player record to JSON.
func (pr *PlayerRecord) ToJSON() ([]byte, error) {
	return json.Marshal(pr)
}

// PlayerRecordFromJSON deserializes a player record from JSON.
func PlayerRecordFromJSON(data []byte) (*PlayerRecord, error) {
	var pr PlayerRecord
	if err := json.Unmarshal(data, &pr); err != nil {
		return nil, err
	}
	return &pr, nil
}

// PlayerDTO is the data transfer object for player API responses.
type PlayerDTO struct {
	DisplayName   string    `json:"display_name"`
	UUID          string    `json:"uuid"`
	XUID          string    `json:"xuid"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	TotalBytes    int64     `json:"total_bytes"`
	TotalPlaytime int64     `json:"total_playtime_seconds"`
}

// ToDTO converts the player record to a DTO for API responses.
func (pr *PlayerRecord) ToDTO() PlayerDTO {
	return PlayerDTO{
		DisplayName:   pr.DisplayName,
		UUID:          pr.UUID,
		XUID:          pr.XUID,
		FirstSeen:     pr.FirstSeen,
		LastSeen:      pr.LastSeen,
		TotalBytes:    pr.TotalBytes,
		TotalPlaytime: pr.TotalPlaytime,
	}
}

// APIKey represents an API key for authentication.
type APIKey struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used,omitempty"`
	IsAdmin   bool      `json:"is_admin"`
}

// APIAccessLog represents an API access log entry.
type APIAccessLog struct {
	ID        int64     `json:"id"`
	APIKey    string    `json:"api_key"`
	Endpoint  string    `json:"endpoint"`
	Timestamp time.Time `json:"timestamp"`
}
