// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"fmt"
	"time"
)

// APIKeyRepository handles API key persistence operations.
type APIKeyRepository struct {
	db            *Database
	maxLogRecords int
}

// NewAPIKeyRepository creates a new API key repository.
func NewAPIKeyRepository(db *Database, maxLogRecords int) *APIKeyRepository {
	if maxLogRecords <= 0 {
		maxLogRecords = 100 // default
	}
	return &APIKeyRepository{
		db:            db,
		maxLogRecords: maxLogRecords,
	}
}

// Create inserts a new API key into the database.
func (r *APIKeyRepository) Create(key *APIKey) error {
	query := `
		INSERT INTO api_keys (key, name, created_at, last_used, is_admin)
		VALUES (?, ?, ?, ?, ?)
	`

	var lastUsed interface{}
	if !key.LastUsed.IsZero() {
		lastUsed = key.LastUsed
	}

	_, err := r.db.DB().Exec(query,
		key.Key,
		key.Name,
		key.CreatedAt,
		lastUsed,
		key.IsAdmin,
	)
	if err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}

	return nil
}

// GetByKey retrieves an API key by its key value.
func (r *APIKeyRepository) GetByKey(key string) (*APIKey, error) {
	query := `
		SELECT key, name, created_at, last_used, is_admin
		FROM api_keys WHERE key = ?
	`

	row := r.db.DB().QueryRow(query, key)
	return r.scanAPIKey(row)
}

// Delete removes an API key by its key value.
func (r *APIKeyRepository) Delete(key string) error {
	query := `DELETE FROM api_keys WHERE key = ?`
	result, err := r.db.DB().Exec(query, key)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
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

// List retrieves all API keys.
func (r *APIKeyRepository) List() ([]*APIKey, error) {
	query := `
		SELECT key, name, created_at, last_used, is_admin
		FROM api_keys ORDER BY created_at DESC
	`

	rows, err := r.db.DB().Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	defer rows.Close()

	return r.scanAPIKeys(rows)
}

// LogAccess logs an API access event.
func (r *APIKeyRepository) LogAccess(key, endpoint string) error {
	// Insert access log
	query := `
		INSERT INTO api_access_log (api_key, endpoint, timestamp)
		VALUES (?, ?, ?)
	`
	_, err := r.db.DB().Exec(query, key, endpoint, time.Now())
	if err != nil {
		return fmt.Errorf("failed to log API access: %w", err)
	}

	// Update last_used on the API key
	updateQuery := `UPDATE api_keys SET last_used = ? WHERE key = ?`
	_, err = r.db.DB().Exec(updateQuery, time.Now(), key)
	if err != nil {
		return fmt.Errorf("failed to update last_used: %w", err)
	}

	// Cleanup old logs if needed
	return r.CleanupLogs()
}

// CountAccessLogs returns the total number of access log records.
func (r *APIKeyRepository) CountAccessLogs() (int, error) {
	var count int
	err := r.db.DB().QueryRow("SELECT COUNT(*) FROM api_access_log").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count access logs: %w", err)
	}
	return count, nil
}

// DeleteOldestLogs deletes the oldest n access log records.
func (r *APIKeyRepository) DeleteOldestLogs(count int) error {
	query := `
		DELETE FROM api_access_log WHERE id IN (
			SELECT id FROM api_access_log ORDER BY timestamp ASC LIMIT ?
		)
	`
	_, err := r.db.DB().Exec(query, count)
	if err != nil {
		return fmt.Errorf("failed to delete oldest access logs: %w", err)
	}
	return nil
}

// CleanupLogs removes access log records exceeding the max limit.
func (r *APIKeyRepository) CleanupLogs() error {
	count, err := r.CountAccessLogs()
	if err != nil {
		return err
	}

	if count > r.maxLogRecords {
		toDelete := count - r.maxLogRecords
		return r.DeleteOldestLogs(toDelete)
	}

	return nil
}

// scanAPIKey scans a single row into an APIKey.
func (r *APIKeyRepository) scanAPIKey(row *sql.Row) (*APIKey, error) {
	var key APIKey
	var name sql.NullString
	var lastUsed sql.NullTime

	err := row.Scan(
		&key.Key,
		&name,
		&key.CreatedAt,
		&lastUsed,
		&key.IsAdmin,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan API key: %w", err)
	}

	if name.Valid {
		key.Name = name.String
	}
	if lastUsed.Valid {
		key.LastUsed = lastUsed.Time
	}

	return &key, nil
}

// scanAPIKeys scans multiple rows into APIKeys.
func (r *APIKeyRepository) scanAPIKeys(rows *sql.Rows) ([]*APIKey, error) {
	var keys []*APIKey

	for rows.Next() {
		var key APIKey
		var name sql.NullString
		var lastUsed sql.NullTime

		err := rows.Scan(
			&key.Key,
			&name,
			&key.CreatedAt,
			&lastUsed,
			&key.IsAdmin,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan API key row: %w", err)
		}

		if name.Valid {
			key.Name = name.String
		}
		if lastUsed.Valid {
			key.LastUsed = lastUsed.Time
		}

		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating API key rows: %w", err)
	}

	return keys, nil
}

// GetAccessLogs retrieves access logs for a specific API key.
func (r *APIKeyRepository) GetAccessLogs(key string, limit int) ([]*APIAccessLog, error) {
	query := `
		SELECT id, api_key, endpoint, timestamp
		FROM api_access_log WHERE api_key = ? ORDER BY timestamp DESC LIMIT ?
	`

	rows, err := r.db.DB().Query(query, key, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get access logs: %w", err)
	}
	defer rows.Close()

	var logs []*APIAccessLog
	for rows.Next() {
		var log APIAccessLog
		err := rows.Scan(&log.ID, &log.APIKey, &log.Endpoint, &log.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to scan access log: %w", err)
		}
		logs = append(logs, &log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating access log rows: %w", err)
	}

	return logs, nil
}
