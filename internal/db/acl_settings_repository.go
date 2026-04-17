// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"fmt"
)

// ACLSettingsRepository handles ACL settings persistence operations.
type ACLSettingsRepository struct {
	db *Database
}

// NewACLSettingsRepository creates a new ACL settings repository.
func NewACLSettingsRepository(db *Database) *ACLSettingsRepository {
	return &ACLSettingsRepository{db: db}
}

// Get retrieves ACL settings for a specific server (or global if serverID is empty).
// Returns sql.ErrNoRows if no settings exist (to allow fallback to global settings).
func (r *ACLSettingsRepository) Get(serverID string) (*ACLSettings, error) {
	query := `
		SELECT server_id, blacklist_enabled, whitelist_enabled, default_ban_message, whitelist_message
		FROM acl_settings 
		WHERE server_id = ?
	`

	row := r.db.DB().QueryRow(query, serverID)

	var settings ACLSettings
	var srvID, defaultMsg, whitelistMsg sql.NullString
	var blacklistEnabled sql.NullBool
	var whitelistEnabled sql.NullBool

	err := row.Scan(&srvID, &blacklistEnabled, &whitelistEnabled, &defaultMsg, &whitelistMsg)
	if err != nil {
		if err == sql.ErrNoRows {
			// Return error to allow caller to fallback to global settings
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("failed to get ACL settings: %w", err)
	}

	if srvID.Valid {
		settings.ServerID = srvID.String
	}
	if blacklistEnabled.Valid {
		settings.BlacklistEnabled = blacklistEnabled.Bool
	} else {
		settings.BlacklistEnabled = true
	}
	if whitelistEnabled.Valid {
		settings.WhitelistEnabled = whitelistEnabled.Bool
	} else {
		// If whitelist_enabled is NULL, default to false
		settings.WhitelistEnabled = false
	}
	if defaultMsg.Valid {
		settings.DefaultMessage = defaultMsg.String
	} else {
		settings.DefaultMessage = "你已被封禁"
	}
	if whitelistMsg.Valid {
		settings.WhitelistMessage = whitelistMsg.String
	} else {
		settings.WhitelistMessage = "你不在白名单中"
	}

	return &settings, nil
}

// Update updates or inserts ACL settings for a server.
// Uses UPSERT to handle both insert and update cases.
func (r *ACLSettingsRepository) Update(settings *ACLSettings) error {
	query := `
		INSERT INTO acl_settings (server_id, blacklist_enabled, whitelist_enabled, default_ban_message, whitelist_message)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET
			blacklist_enabled = excluded.blacklist_enabled,
			whitelist_enabled = excluded.whitelist_enabled,
			default_ban_message = excluded.default_ban_message,
			whitelist_message = excluded.whitelist_message
	`

	_, err := r.db.DB().Exec(query,
		settings.ServerID,
		settings.BlacklistEnabled,
		settings.WhitelistEnabled,
		settings.DefaultMessage,
		settings.WhitelistMessage,
	)
	if err != nil {
		return fmt.Errorf("failed to update ACL settings: %w", err)
	}

	return nil
}
