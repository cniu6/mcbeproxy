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
// If no settings exist, returns default settings.
func (r *ACLSettingsRepository) Get(serverID string) (*ACLSettings, error) {
	query := `
		SELECT server_id, whitelist_enabled, default_ban_message, whitelist_message
		FROM acl_settings 
		WHERE server_id = ?
	`

	row := r.db.DB().QueryRow(query, serverID)

	var settings ACLSettings
	var srvID, defaultMsg, whitelistMsg sql.NullString
	var whitelistEnabled sql.NullBool

	err := row.Scan(&srvID, &whitelistEnabled, &defaultMsg, &whitelistMsg)
	if err != nil {
		if err == sql.ErrNoRows {
			// Return default settings if none exist
			defaults := DefaultACLSettings()
			defaults.ServerID = serverID
			return defaults, nil
		}
		return nil, fmt.Errorf("failed to get ACL settings: %w", err)
	}

	if srvID.Valid {
		settings.ServerID = srvID.String
	}
	if whitelistEnabled.Valid {
		settings.WhitelistEnabled = whitelistEnabled.Bool
	}
	if defaultMsg.Valid {
		settings.DefaultMessage = defaultMsg.String
	} else {
		settings.DefaultMessage = "You are banned from this server"
	}
	if whitelistMsg.Valid {
		settings.WhitelistMessage = whitelistMsg.String
	} else {
		settings.WhitelistMessage = "You are not whitelisted on this server"
	}

	return &settings, nil
}

// Update updates or inserts ACL settings for a server.
// Uses UPSERT to handle both insert and update cases.
func (r *ACLSettingsRepository) Update(settings *ACLSettings) error {
	query := `
		INSERT INTO acl_settings (server_id, whitelist_enabled, default_ban_message, whitelist_message)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET
			whitelist_enabled = excluded.whitelist_enabled,
			default_ban_message = excluded.default_ban_message,
			whitelist_message = excluded.whitelist_message
	`

	_, err := r.db.DB().Exec(query,
		settings.ServerID,
		settings.WhitelistEnabled,
		settings.DefaultMessage,
		settings.WhitelistMessage,
	)
	if err != nil {
		return fmt.Errorf("failed to update ACL settings: %w", err)
	}

	return nil
}
