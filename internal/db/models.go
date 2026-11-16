// Package db provides database access and persistence functionality.
package db

import (
	"time"

	"mcpeserverproxy/internal/session"
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
		UUID:          playerUUID(pr.UUID, pr.XUID),
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

// 新版客户端登录不带 identity，旧记录 UUID 为空；按 XUID 补出，与旧记录同一算法。
func playerUUID(uuid, xuid string) string {
	if uuid != "" {
		return uuid
	}
	return session.UUIDFromXUID(xuid)
}
