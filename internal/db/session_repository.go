// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"mcpeserverproxy/internal/session"
)

// SessionRepository handles session persistence operations.
type SessionRepository struct {
	db         *Database
	maxRecords int
}

// NewSessionRepository creates a new session repository.
func NewSessionRepository(db *Database, maxRecords int) *SessionRepository {
	if maxRecords <= 0 {
		maxRecords = 100 // default
	}
	return &SessionRepository{
		db:         db,
		maxRecords: maxRecords,
	}
}

// Create inserts a new session record into the database.
func (r *SessionRepository) Create(sr *session.SessionRecord) error {
	query := `
		INSERT INTO sessions (id, client_addr, server_id, uuid, display_name, bytes_up, bytes_down, start_time, end_time, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var endTime interface{}
	if !sr.EndTime.IsZero() {
		endTime = sr.EndTime
	}

	_, err := r.db.DB().Exec(query,
		sr.ID,
		sr.ClientAddr,
		sr.ServerID,
		sr.UUID,
		sr.DisplayName,
		sr.BytesUp,
		sr.BytesDown,
		sr.StartTime,
		endTime,
		sr.Metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Cleanup old records if needed
	return r.Cleanup()
}

// GetByID retrieves a session record by its ID.
func (r *SessionRepository) GetByID(id string) (*session.SessionRecord, error) {
	query := `
		SELECT id, client_addr, server_id, uuid, display_name, bytes_up, bytes_down, start_time, end_time, metadata
		FROM sessions WHERE id = ?
	`

	row := r.db.DB().QueryRow(query, id)
	return r.scanSessionRecord(row)
}

// GetByPlayerUUID retrieves all session records for a player UUID.
func (r *SessionRepository) GetByPlayerUUID(uuid string) ([]*session.SessionRecord, error) {
	query := `
		SELECT id, client_addr, server_id, uuid, display_name, bytes_up, bytes_down, start_time, end_time, metadata
		FROM sessions WHERE uuid = ? ORDER BY start_time DESC
	`

	rows, err := r.db.DB().Query(query, uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions by uuid: %w", err)
	}
	defer rows.Close()

	return r.scanSessionRecords(rows)
}

// GetByPlayerName retrieves all session records for a player by display name.
func (r *SessionRepository) GetByPlayerName(displayName string) ([]*session.SessionRecord, error) {
	query := `
		SELECT id, client_addr, server_id, uuid, display_name, bytes_up, bytes_down, start_time, end_time, metadata
		FROM sessions WHERE display_name = ? ORDER BY start_time DESC
	`

	rows, err := r.db.DB().Query(query, displayName)
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions by display_name: %w", err)
	}
	defer rows.Close()

	return r.scanSessionRecords(rows)
}

// List retrieves session records with pagination.
func (r *SessionRepository) List(limit, offset int) ([]*session.SessionRecord, error) {
	query := `
		SELECT id, client_addr, server_id, uuid, display_name, bytes_up, bytes_down, start_time, end_time, metadata
		FROM sessions ORDER BY start_time DESC LIMIT ? OFFSET ?
	`

	rows, err := r.db.DB().Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer rows.Close()

	return r.scanSessionRecords(rows)
}

// Delete removes a session record by ID.
func (r *SessionRepository) Delete(id string) error {
	query := `DELETE FROM sessions WHERE id = ?`
	result, err := r.db.DB().Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
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

// Count returns the total number of session records.
func (r *SessionRepository) Count() (int, error) {
	var count int
	err := r.db.DB().QueryRow("SELECT COUNT(*) FROM sessions").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count sessions: %w", err)
	}
	return count, nil
}

// DeleteOldest deletes the oldest n session records.
func (r *SessionRepository) DeleteOldest(count int) error {
	query := `
		DELETE FROM sessions WHERE id IN (
			SELECT id FROM sessions ORDER BY start_time ASC LIMIT ?
		)
	`
	_, err := r.db.DB().Exec(query, count)
	if err != nil {
		return fmt.Errorf("failed to delete oldest sessions: %w", err)
	}
	return nil
}

// Cleanup removes records exceeding the max limit.
func (r *SessionRepository) Cleanup() error {
	count, err := r.Count()
	if err != nil {
		return err
	}

	if count > r.maxRecords {
		toDelete := count - r.maxRecords
		return r.DeleteOldest(toDelete)
	}

	return nil
}

// ClearHistory removes all session history records.
func (r *SessionRepository) ClearHistory() error {
	_, err := r.db.DB().Exec("DELETE FROM sessions")
	if err != nil {
		return fmt.Errorf("failed to clear session history: %w", err)
	}
	return nil
}

// DeleteHistory removes a specific session history record by ID.
func (r *SessionRepository) DeleteHistory(id string) error {
	return r.Delete(id)
}

// scanSessionRecord scans a single row into a SessionRecord.
func (r *SessionRepository) scanSessionRecord(row *sql.Row) (*session.SessionRecord, error) {
	var sr session.SessionRecord
	var endTime sql.NullTime
	var uuid, displayName, metadata sql.NullString

	err := row.Scan(
		&sr.ID,
		&sr.ClientAddr,
		&sr.ServerID,
		&uuid,
		&displayName,
		&sr.BytesUp,
		&sr.BytesDown,
		&sr.StartTime,
		&endTime,
		&metadata,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan session: %w", err)
	}

	if uuid.Valid {
		sr.UUID = uuid.String
	}
	if displayName.Valid {
		sr.DisplayName = displayName.String
	}
	if endTime.Valid {
		sr.EndTime = endTime.Time
	}
	if metadata.Valid {
		sr.Metadata = metadata.String
	}

	return &sr, nil
}

// scanSessionRecords scans multiple rows into SessionRecords.
func (r *SessionRepository) scanSessionRecords(rows *sql.Rows) ([]*session.SessionRecord, error) {
	var records []*session.SessionRecord

	for rows.Next() {
		var sr session.SessionRecord
		var endTime sql.NullTime
		var uuid, displayName, metadata sql.NullString

		err := rows.Scan(
			&sr.ID,
			&sr.ClientAddr,
			&sr.ServerID,
			&uuid,
			&displayName,
			&sr.BytesUp,
			&sr.BytesDown,
			&sr.StartTime,
			&endTime,
			&metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}

		if uuid.Valid {
			sr.UUID = uuid.String
		}
		if displayName.Valid {
			sr.DisplayName = displayName.String
		}
		if endTime.Valid {
			sr.EndTime = endTime.Time
		}
		if metadata.Valid {
			sr.Metadata = metadata.String
		}

		records = append(records, &sr)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating session rows: %w", err)
	}

	return records, nil
}

// SessionRecordToJSON serializes a session record to JSON string.
func SessionRecordToJSON(sr *session.SessionRecord) (string, error) {
	data, err := json.Marshal(sr)
	if err != nil {
		return "", fmt.Errorf("failed to serialize session record: %w", err)
	}
	return string(data), nil
}

// SessionRecordFromJSON deserializes a session record from JSON string.
func SessionRecordFromJSON(data string) (*session.SessionRecord, error) {
	var sr session.SessionRecord
	if err := json.Unmarshal([]byte(data), &sr); err != nil {
		return nil, fmt.Errorf("failed to deserialize session record: %w", err)
	}
	return &sr, nil
}
