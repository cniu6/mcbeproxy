// Package db provides database access and persistence functionality.
package db

import (
	"encoding/json"
	"time"
)

// BlacklistEntry represents a blacklist entry in the database.
type BlacklistEntry struct {
	ID          int64      `json:"id"`
	DisplayName string     `json:"display_name"`
	Reason      string     `json:"reason,omitempty"`
	ServerID    string     `json:"server_id,omitempty"` // empty for global
	AddedAt     time.Time  `json:"added_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AddedBy     string     `json:"added_by,omitempty"`
}

// ToJSON serializes the blacklist entry to JSON.
func (be *BlacklistEntry) ToJSON() ([]byte, error) {
	return json.Marshal(be)
}

// BlacklistEntryFromJSON deserializes a blacklist entry from JSON.
func BlacklistEntryFromJSON(data []byte) (*BlacklistEntry, error) {
	var be BlacklistEntry
	if err := json.Unmarshal(data, &be); err != nil {
		return nil, err
	}
	return &be, nil
}

// IsExpired checks if the blacklist entry has expired.
func (be *BlacklistEntry) IsExpired() bool {
	if be.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*be.ExpiresAt)
}

// WhitelistEntry represents a whitelist entry in the database.
type WhitelistEntry struct {
	ID          int64     `json:"id"`
	DisplayName string    `json:"display_name"`
	ServerID    string    `json:"server_id,omitempty"` // empty for global
	AddedAt     time.Time `json:"added_at"`
	AddedBy     string    `json:"added_by,omitempty"`
}

// ToJSON serializes the whitelist entry to JSON.
func (we *WhitelistEntry) ToJSON() ([]byte, error) {
	return json.Marshal(we)
}

// WhitelistEntryFromJSON deserializes a whitelist entry from JSON.
func WhitelistEntryFromJSON(data []byte) (*WhitelistEntry, error) {
	var we WhitelistEntry
	if err := json.Unmarshal(data, &we); err != nil {
		return nil, err
	}
	return &we, nil
}

// ACLSettings represents access control settings for a server.
type ACLSettings struct {
	ServerID         string `json:"server_id,omitempty"` // empty for global
	WhitelistEnabled bool   `json:"whitelist_enabled"`
	DefaultMessage   string `json:"default_ban_message"`
	WhitelistMessage string `json:"whitelist_message"`
}

// ToJSON serializes the ACL settings to JSON.
func (as *ACLSettings) ToJSON() ([]byte, error) {
	return json.Marshal(as)
}

// ACLSettingsFromJSON deserializes ACL settings from JSON.
func ACLSettingsFromJSON(data []byte) (*ACLSettings, error) {
	var as ACLSettings
	if err := json.Unmarshal(data, &as); err != nil {
		return nil, err
	}
	return &as, nil
}

// DefaultACLSettings returns the default ACL settings.
func DefaultACLSettings() *ACLSettings {
	return &ACLSettings{
		ServerID:         "",
		WhitelistEnabled: false,
		DefaultMessage:   "You are banned from this server",
		WhitelistMessage: "You are not whitelisted on this server",
	}
}

// BlacklistEntryDTO is the data transfer object for blacklist API responses.
type BlacklistEntryDTO struct {
	ID         int64      `json:"id"`
	PlayerName string     `json:"player_name"`
	Reason     string     `json:"reason,omitempty"`
	ServerID   string     `json:"server_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	AddedBy    string     `json:"added_by,omitempty"`
}

// ToDTO converts the blacklist entry to a DTO for API responses.
func (be *BlacklistEntry) ToDTO() BlacklistEntryDTO {
	return BlacklistEntryDTO{
		ID:         be.ID,
		PlayerName: be.DisplayName,
		Reason:     be.Reason,
		ServerID:   be.ServerID,
		CreatedAt:  be.AddedAt,
		ExpiresAt:  be.ExpiresAt,
		AddedBy:    be.AddedBy,
	}
}

// WhitelistEntryDTO is the data transfer object for whitelist API responses.
type WhitelistEntryDTO struct {
	ID         int64     `json:"id"`
	PlayerName string    `json:"player_name"`
	ServerID   string    `json:"server_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	AddedBy    string    `json:"added_by,omitempty"`
}

// ToDTO converts the whitelist entry to a DTO for API responses.
func (we *WhitelistEntry) ToDTO() WhitelistEntryDTO {
	return WhitelistEntryDTO{
		ID:         we.ID,
		PlayerName: we.DisplayName,
		ServerID:   we.ServerID,
		CreatedAt:  we.AddedAt,
		AddedBy:    we.AddedBy,
	}
}

// ACLSettingsDTO is the data transfer object for ACL settings API responses.
type ACLSettingsDTO struct {
	ServerID         string `json:"server_id,omitempty"`
	WhitelistEnabled bool   `json:"whitelist_enabled"`
	DefaultMessage   string `json:"default_ban_message"`
	WhitelistMessage string `json:"whitelist_message"`
}

// ToDTO converts the ACL settings to a DTO for API responses.
func (as *ACLSettings) ToDTO() ACLSettingsDTO {
	return ACLSettingsDTO{
		ServerID:         as.ServerID,
		WhitelistEnabled: as.WhitelistEnabled,
		DefaultMessage:   as.DefaultMessage,
		WhitelistMessage: as.WhitelistMessage,
	}
}

// AddBlacklistRequest is the request body for adding a player to the blacklist.
type AddBlacklistRequest struct {
	DisplayName string     `json:"display_name"`
	PlayerName  string     `json:"player_name"`
	Reason      string     `json:"reason"`
	ServerID    string     `json:"server_id,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// GetPlayerName returns the player name from either DisplayName or PlayerName field.
func (r *AddBlacklistRequest) GetPlayerName() string {
	if r.PlayerName != "" {
		return r.PlayerName
	}
	return r.DisplayName
}

// AddWhitelistRequest is the request body for adding a player to the whitelist.
type AddWhitelistRequest struct {
	DisplayName string `json:"display_name"`
	PlayerName  string `json:"player_name"`
	ServerID    string `json:"server_id,omitempty"`
}

// GetPlayerName returns the player name from either DisplayName or PlayerName field.
func (r *AddWhitelistRequest) GetPlayerName() string {
	if r.PlayerName != "" {
		return r.PlayerName
	}
	return r.DisplayName
}

// AccessCheckResult represents the result of an access control check.
type AccessCheckResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}
