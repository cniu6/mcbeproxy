// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// BlacklistRepository handles blacklist persistence operations.
type BlacklistRepository struct {
	db *Database
}

// NewBlacklistRepository creates a new blacklist repository.
func NewBlacklistRepository(db *Database) *BlacklistRepository {
	return &BlacklistRepository{db: db}
}

// Create inserts a new blacklist entry into the database.
// If the entry already exists (same display_name and server_id), it will be updated.
func (r *BlacklistRepository) Create(entry *BlacklistEntry) error {
	query := `
		INSERT INTO blacklist (display_name, display_name_lower, reason, server_id, added_at, expires_at, added_by)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(display_name_lower, server_id) DO UPDATE SET
			reason = excluded.reason,
			added_at = excluded.added_at,
			expires_at = excluded.expires_at,
			added_by = excluded.added_by
	`

	// Convert empty string to NULL for server_id (global blacklist)
	var serverID interface{}
	if entry.ServerID == "" {
		serverID = nil
	} else {
		serverID = entry.ServerID
	}

	result, err := r.db.DB().Exec(query,
		entry.DisplayName,
		strings.ToLower(entry.DisplayName),
		entry.Reason,
		serverID,
		entry.AddedAt,
		entry.ExpiresAt,
		entry.AddedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create blacklist entry: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	entry.ID = id

	return nil
}

// GetByName retrieves a blacklist entry by display name and server ID.
// Uses case-insensitive matching on display name.
func (r *BlacklistRepository) GetByName(displayName, serverID string) (*BlacklistEntry, error) {
	query := `
		SELECT id, display_name, reason, server_id, added_at, expires_at, added_by
		FROM blacklist 
		WHERE display_name_lower = ? AND (
			server_id = ? OR 
			(server_id IS NULL AND ? = '') OR
			(server_id = '' AND ? = '')
		)
	`

	row := r.db.DB().QueryRow(query, strings.ToLower(displayName), serverID, serverID, serverID)
	return r.scanBlacklistEntry(row)
}

// Delete removes a blacklist entry by display name and server ID.
func (r *BlacklistRepository) Delete(displayName, serverID string) error {
	query := `
		DELETE FROM blacklist 
		WHERE display_name_lower = ? AND (
			server_id = ? OR 
			(server_id IS NULL AND ? = '') OR
			(server_id = '' AND ? = '')
		)
	`

	result, err := r.db.DB().Exec(query, strings.ToLower(displayName), serverID, serverID, serverID)
	if err != nil {
		return fmt.Errorf("failed to delete blacklist entry: %w", err)
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

// List retrieves all blacklist entries for a specific server (or global if serverID is empty).
func (r *BlacklistRepository) List(serverID string) ([]*BlacklistEntry, error) {
	query := `
		SELECT id, display_name, reason, server_id, added_at, expires_at, added_by
		FROM blacklist 
		WHERE server_id = ? OR (server_id IS NULL AND ? = '') OR (server_id = '' AND ? = '')
		ORDER BY added_at DESC
	`

	rows, err := r.db.DB().Query(query, serverID, serverID, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to list blacklist entries: %w", err)
	}
	defer rows.Close()

	return r.scanBlacklistEntries(rows)
}

// ListAll retrieves all blacklist entries from all servers.
func (r *BlacklistRepository) ListAll() ([]*BlacklistEntry, error) {
	query := `
		SELECT id, display_name, reason, server_id, added_at, expires_at, added_by
		FROM blacklist 
		ORDER BY added_at DESC
	`

	rows, err := r.db.DB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list all blacklist entries: %w", err)
	}
	defer rows.Close()

	return r.scanBlacklistEntries(rows)
}

// DeleteExpired removes all expired blacklist entries and returns the count of deleted entries.
func (r *BlacklistRepository) DeleteExpired() (int, error) {
	query := `
		DELETE FROM blacklist 
		WHERE expires_at IS NOT NULL AND expires_at < ?
	`

	result, err := r.db.DB().Exec(query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired blacklist entries: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}

	return int(affected), nil
}

// scanBlacklistEntry scans a single row into a BlacklistEntry.
func (r *BlacklistRepository) scanBlacklistEntry(row *sql.Row) (*BlacklistEntry, error) {
	var entry BlacklistEntry
	var reason, serverID, addedBy sql.NullString
	var expiresAt sql.NullTime

	err := row.Scan(
		&entry.ID,
		&entry.DisplayName,
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
		return nil, fmt.Errorf("failed to scan blacklist entry: %w", err)
	}

	if reason.Valid {
		entry.Reason = reason.String
	}
	if serverID.Valid {
		entry.ServerID = serverID.String
	}
	if addedBy.Valid {
		entry.AddedBy = addedBy.String
	}
	if expiresAt.Valid {
		entry.ExpiresAt = &expiresAt.Time
	}

	return &entry, nil
}

// scanBlacklistEntries scans multiple rows into BlacklistEntries.
func (r *BlacklistRepository) scanBlacklistEntries(rows *sql.Rows) ([]*BlacklistEntry, error) {
	var entries []*BlacklistEntry

	for rows.Next() {
		var entry BlacklistEntry
		var reason, serverID, addedBy sql.NullString
		var expiresAt sql.NullTime

		err := rows.Scan(
			&entry.ID,
			&entry.DisplayName,
			&reason,
			&serverID,
			&entry.AddedAt,
			&expiresAt,
			&addedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blacklist entry row: %w", err)
		}

		if reason.Valid {
			entry.Reason = reason.String
		}
		if serverID.Valid {
			entry.ServerID = serverID.String
		}
		if addedBy.Valid {
			entry.AddedBy = addedBy.String
		}
		if expiresAt.Valid {
			entry.ExpiresAt = &expiresAt.Time
		}

		entries = append(entries, &entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating blacklist rows: %w", err)
	}

	return entries, nil
}
