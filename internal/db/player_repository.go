// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"fmt"
	"time"
)

// PlayerRepository handles player persistence operations.
type PlayerRepository struct {
	db *Database
}

// NewPlayerRepository creates a new player repository.
func NewPlayerRepository(db *Database) *PlayerRepository {
	return &PlayerRepository{db: db}
}

// Create inserts a new player record into the database.
func (r *PlayerRepository) Create(pr *PlayerRecord) error {
	query := `
		INSERT INTO players (display_name, uuid, xuid, first_seen, last_seen, total_bytes, total_playtime, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.DB().Exec(query,
		pr.DisplayName,
		pr.UUID,
		pr.XUID,
		pr.FirstSeen,
		pr.LastSeen,
		pr.TotalBytes,
		pr.TotalPlaytime,
		pr.Metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to create player: %w", err)
	}

	return nil
}

// GetByDisplayName retrieves a player record by display name.
func (r *PlayerRepository) GetByDisplayName(displayName string) (*PlayerRecord, error) {
	query := `
		SELECT display_name, uuid, xuid, first_seen, last_seen, total_bytes, total_playtime, metadata
		FROM players WHERE display_name = ?
	`

	row := r.db.DB().QueryRow(query, displayName)
	return r.scanPlayerRecord(row)
}

// List retrieves player records with pagination.
func (r *PlayerRepository) List(limit, offset int) ([]*PlayerRecord, error) {
	query := `
		SELECT display_name, uuid, xuid, first_seen, last_seen, total_bytes, total_playtime, metadata
		FROM players ORDER BY last_seen DESC LIMIT ? OFFSET ?
	`

	rows, err := r.db.DB().Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list players: %w", err)
	}
	defer rows.Close()

	return r.scanPlayerRecords(rows)
}

// DeleteByDisplayName deletes a player record by display name.
func (r *PlayerRepository) DeleteByDisplayName(displayName string) error {
	query := `DELETE FROM players WHERE display_name = ?`
	result, err := r.db.DB().Exec(query, displayName)
	if err != nil {
		return fmt.Errorf("failed to delete player: %w", err)
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

// UpdateStats updates a player's statistics after a session ends.
// This atomically adds bytesAdded to total_bytes and playtimeAdded to total_playtime.
func (r *PlayerRepository) UpdateStats(displayName string, bytesAdded int64, playtimeAdded time.Duration) error {
	return r.UpdateStatsWithIdentity(displayName, "", "", bytesAdded, playtimeAdded, time.Now())
}

// UpdateStatsWithIdentity updates player statistics and refreshes the latest known identity.
func (r *PlayerRepository) UpdateStatsWithIdentity(displayName, uuid, xuid string, bytesAdded int64, playtimeAdded time.Duration, lastSeen time.Time) error {
	if lastSeen.IsZero() {
		lastSeen = time.Now()
	}
	query := `
		UPDATE players 
		SET total_bytes = total_bytes + ?, 
		    total_playtime = total_playtime + ?,
		    last_seen = ?,
		    uuid = CASE WHEN ? != '' THEN ? ELSE uuid END,
		    xuid = CASE WHEN ? != '' THEN ? ELSE xuid END
		WHERE display_name = ?
	`

	playtimeSeconds := int64(playtimeAdded.Seconds())
	result, err := r.db.DB().Exec(query, bytesAdded, playtimeSeconds, lastSeen, uuid, uuid, xuid, xuid, displayName)
	if err != nil {
		return fmt.Errorf("failed to update player stats: %w", err)
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

// scanPlayerRecord scans a single row into a PlayerRecord.
func (r *PlayerRepository) scanPlayerRecord(row *sql.Row) (*PlayerRecord, error) {
	var pr PlayerRecord
	var uuid, xuid, metadata sql.NullString

	err := row.Scan(
		&pr.DisplayName,
		&uuid,
		&xuid,
		&pr.FirstSeen,
		&pr.LastSeen,
		&pr.TotalBytes,
		&pr.TotalPlaytime,
		&metadata,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan player: %w", err)
	}

	if uuid.Valid {
		pr.UUID = uuid.String
	}
	if xuid.Valid {
		pr.XUID = xuid.String
	}
	if metadata.Valid {
		pr.Metadata = metadata.String
	}

	return &pr, nil
}

// scanPlayerRecords scans multiple rows into PlayerRecords.
func (r *PlayerRepository) scanPlayerRecords(rows *sql.Rows) ([]*PlayerRecord, error) {
	var records []*PlayerRecord

	for rows.Next() {
		var pr PlayerRecord
		var uuid, xuid, metadata sql.NullString

		err := rows.Scan(
			&pr.DisplayName,
			&uuid,
			&xuid,
			&pr.FirstSeen,
			&pr.LastSeen,
			&pr.TotalBytes,
			&pr.TotalPlaytime,
			&metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan player row: %w", err)
		}

		if uuid.Valid {
			pr.UUID = uuid.String
		}
		if xuid.Valid {
			pr.XUID = xuid.String
		}
		if metadata.Valid {
			pr.Metadata = metadata.String
		}

		records = append(records, &pr)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating player rows: %w", err)
	}

	return records, nil
}
