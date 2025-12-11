// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"fmt"
	"strings"
)

// WhitelistRepository handles whitelist persistence operations.
type WhitelistRepository struct {
	db *Database
}

// NewWhitelistRepository creates a new whitelist repository.
func NewWhitelistRepository(db *Database) *WhitelistRepository {
	return &WhitelistRepository{db: db}
}

// Create inserts a new whitelist entry into the database.
func (r *WhitelistRepository) Create(entry *WhitelistEntry) error {
	query := `
		INSERT INTO whitelist (display_name, display_name_lower, server_id, added_at, added_by)
		VALUES (?, ?, ?, ?, ?)
	`

	result, err := r.db.DB().Exec(query,
		entry.DisplayName,
		strings.ToLower(entry.DisplayName),
		entry.ServerID,
		entry.AddedAt,
		entry.AddedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create whitelist entry: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	entry.ID = id

	return nil
}

// GetByName retrieves a whitelist entry by display name and server ID.
// Uses case-insensitive matching on display name.
func (r *WhitelistRepository) GetByName(displayName, serverID string) (*WhitelistEntry, error) {
	query := `
		SELECT id, display_name, server_id, added_at, added_by
		FROM whitelist 
		WHERE display_name_lower = ? AND (server_id = ? OR (server_id IS NULL AND ? = ''))
	`

	row := r.db.DB().QueryRow(query, strings.ToLower(displayName), serverID, serverID)
	return r.scanWhitelistEntry(row)
}

// Delete removes a whitelist entry by display name and server ID.
func (r *WhitelistRepository) Delete(displayName, serverID string) error {
	query := `
		DELETE FROM whitelist 
		WHERE display_name_lower = ? AND (server_id = ? OR (server_id IS NULL AND ? = ''))
	`

	result, err := r.db.DB().Exec(query, strings.ToLower(displayName), serverID, serverID)
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
		SELECT id, display_name, server_id, added_at, added_by
		FROM whitelist 
		WHERE server_id = ? OR (server_id IS NULL AND ? = '')
		ORDER BY added_at DESC
	`

	rows, err := r.db.DB().Query(query, serverID, serverID)
	if err != nil {
		return nil, fmt.Errorf("failed to list whitelist entries: %w", err)
	}
	defer rows.Close()

	return r.scanWhitelistEntries(rows)
}

// ListAll retrieves all whitelist entries from all servers.
func (r *WhitelistRepository) ListAll() ([]*WhitelistEntry, error) {
	query := `
		SELECT id, display_name, server_id, added_at, added_by
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

// scanWhitelistEntry scans a single row into a WhitelistEntry.
func (r *WhitelistRepository) scanWhitelistEntry(row *sql.Row) (*WhitelistEntry, error) {
	var entry WhitelistEntry
	var serverID, addedBy sql.NullString

	err := row.Scan(
		&entry.ID,
		&entry.DisplayName,
		&serverID,
		&entry.AddedAt,
		&addedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan whitelist entry: %w", err)
	}

	if serverID.Valid {
		entry.ServerID = serverID.String
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
		var serverID, addedBy sql.NullString

		err := rows.Scan(
			&entry.ID,
			&entry.DisplayName,
			&serverID,
			&entry.AddedAt,
			&addedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan whitelist entry row: %w", err)
		}

		if serverID.Valid {
			entry.ServerID = serverID.String
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
