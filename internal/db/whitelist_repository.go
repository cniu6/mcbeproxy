// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// WhitelistRepository handles whitelist persistence operations.
type WhitelistRepository struct {
	db *Database
}

// NewWhitelistRepository creates a new whitelist repository.
func NewWhitelistRepository(db *Database) *WhitelistRepository {
	return &WhitelistRepository{db: db}
}

func normalizeWhitelistDisplayName(displayName string) (string, string) {
	trimmed := strings.TrimSpace(displayName)
	return trimmed, strings.ToLower(trimmed)
}

// Create inserts a new whitelist entry into the database.
// If the entry already exists (same display_name and server_id), it will be updated.
func (r *WhitelistRepository) Create(entry *WhitelistEntry) error {
	query := `
		INSERT INTO whitelist (display_name, display_name_lower, enabled, reason, server_id, added_at, expires_at, added_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(display_name_lower, server_id) DO UPDATE SET
			enabled = excluded.enabled,
			reason = excluded.reason,
			added_at = excluded.added_at,
			expires_at = excluded.expires_at,
			added_by = excluded.added_by
	`

	serverID := normalizeACLServerID(entry.ServerID)
	entry.ServerID = serverID

	displayName, displayNameLower := normalizeWhitelistDisplayName(entry.DisplayName)
	entry.DisplayName = displayName

	if _, err := r.db.DB().Exec(query,
		displayName,
		displayNameLower,
		entry.Enabled,
		entry.Reason,
		serverID,
		entry.AddedAt,
		entry.ExpiresAt,
		entry.AddedBy,
	); err != nil {
		return fmt.Errorf("failed to create whitelist entry: %w", err)
	}

	stored, err := r.GetByName(displayName, serverID)
	if err != nil {
		return fmt.Errorf("failed to reload whitelist entry after upsert: %w", err)
	}
	*entry = *stored
	return nil
}

// GetByName retrieves a whitelist entry by display name and server ID.
// Uses case-insensitive matching on display name.
func (r *WhitelistRepository) GetByName(displayName, serverID string) (*WhitelistEntry, error) {
	query := `
		SELECT id, display_name, enabled, reason, server_id, added_at, expires_at, added_by
		FROM whitelist 
		WHERE display_name_lower = ? AND server_id = ?
	`

	_, displayNameLower := normalizeWhitelistDisplayName(displayName)
	scope := normalizeACLServerID(serverID)
	row := r.db.DB().QueryRow(query, displayNameLower, scope)
	return r.scanWhitelistEntry(row)
}

func (r *WhitelistRepository) UpdateEnabled(displayName, serverID string, enabled bool) error {
	query := `
		UPDATE whitelist
		SET enabled = ?
		WHERE display_name_lower = ? AND server_id = ?
	`

	_, displayNameLower := normalizeWhitelistDisplayName(displayName)
	scope := normalizeACLServerID(serverID)
	result, err := r.db.DB().Exec(query, enabled, displayNameLower, scope)
	if err != nil {
		return fmt.Errorf("failed to update whitelist entry enabled state: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// Delete removes a whitelist entry by display name and server ID.
func (r *WhitelistRepository) Delete(displayName, serverID string) error {
	query := `
		DELETE FROM whitelist 
		WHERE display_name_lower = ? AND server_id = ?
	`

	_, displayNameLower := normalizeWhitelistDisplayName(displayName)
	scope := normalizeACLServerID(serverID)
	result, err := r.db.DB().Exec(query, displayNameLower, scope)
	if err != nil {
		return fmt.Errorf("failed to delete whitelist entry: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// List retrieves all whitelist entries for a specific server (or global if serverID is empty).
func (r *WhitelistRepository) List(serverID string) ([]*WhitelistEntry, error) {
	query := `
		SELECT id, display_name, enabled, reason, server_id, added_at, expires_at, added_by
		FROM whitelist 
		WHERE server_id = ?
		ORDER BY added_at DESC
	`

	scope := normalizeACLServerID(serverID)
	rows, err := r.db.DB().Query(query, scope)
	if err != nil {
		return nil, fmt.Errorf("failed to list whitelist entries: %w", err)
	}
	defer rows.Close()

	return r.scanWhitelistEntries(rows)
}

// ListAll retrieves all whitelist entries from all servers.
func (r *WhitelistRepository) ListAll() ([]*WhitelistEntry, error) {
	query := `
		SELECT id, display_name, enabled, reason, server_id, added_at, expires_at, added_by
		FROM whitelist 
		ORDER BY added_at DESC
	`

	rows, err := r.db.DB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list all whitelist entries: %w", err)
	}
	defer rows.Close()

	return r.scanWhitelistEntries(rows)
}

func (r *WhitelistRepository) DeleteExpired() (int, error) {
	query := `
		DELETE FROM whitelist 
		WHERE expires_at IS NOT NULL AND expires_at < ?
	`

	result, err := r.db.DB().Exec(query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired whitelist entries: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}

	return int(affected), nil
}

// scanWhitelistEntry scans a single row into a WhitelistEntry.
func (r *WhitelistRepository) scanWhitelistEntry(row *sql.Row) (*WhitelistEntry, error) {
	var entry WhitelistEntry
	var enabled sql.NullBool
	var reason, serverID, addedBy sql.NullString
	var expiresAt sql.NullTime

	err := row.Scan(
		&entry.ID,
		&entry.DisplayName,
		&enabled,
		&reason,
		&serverID,
		&entry.AddedAt,
		&expiresAt,
		&addedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan whitelist entry: %w", err)
	}

	if enabled.Valid {
		entry.Enabled = enabled.Bool
	} else {
		entry.Enabled = true
	}
	if reason.Valid {
		entry.Reason = reason.String
	}
	if serverID.Valid {
		entry.ServerID = serverID.String
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		entry.ExpiresAt = &t
	}
	if addedBy.Valid {
		entry.AddedBy = addedBy.String
	}

	return &entry, nil
}

// scanWhitelistEntries scans multiple rows into WhitelistEntries.
func (r *WhitelistRepository) scanWhitelistEntries(rows *sql.Rows) ([]*WhitelistEntry, error) {
	var entries []*WhitelistEntry

	for rows.Next() {
		var entry WhitelistEntry
		var enabled sql.NullBool
		var reason, serverID, addedBy sql.NullString
		var expiresAt sql.NullTime

		err := rows.Scan(
			&entry.ID,
			&entry.DisplayName,
			&enabled,
			&reason,
			&serverID,
			&entry.AddedAt,
			&expiresAt,
			&addedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan whitelist entry row: %w", err)
		}

		if enabled.Valid {
			entry.Enabled = enabled.Bool
		} else {
			entry.Enabled = true
		}
		if reason.Valid {
			entry.Reason = reason.String
		}
		if serverID.Valid {
			entry.ServerID = serverID.String
		}
		if expiresAt.Valid {
			t := expiresAt.Time
			entry.ExpiresAt = &t
		}
		if addedBy.Valid {
			entry.AddedBy = addedBy.String
		}

		entries = append(entries, &entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating whitelist rows: %w", err)
	}

	return entries, nil
}
