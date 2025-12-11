// Package db provides database access and persistence functionality.
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Database wraps the SQLite database connection.
type Database struct {
	db *sql.DB
}

// NewDatabase creates a new database connection.
func NewDatabase(path string) (*Database, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{db: db}, nil
}

// Initialize creates the required database schema tables.
func (d *Database) Initialize() error {
	schema := `
	-- sessions table
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		client_addr TEXT NOT NULL,
		server_id TEXT NOT NULL,
		uuid TEXT,
		display_name TEXT,
		bytes_up INTEGER DEFAULT 0,
		bytes_down INTEGER DEFAULT 0,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		metadata TEXT
	);

	-- players table (display_name is primary key since UUID can change)
	CREATE TABLE IF NOT EXISTS players (
		display_name TEXT PRIMARY KEY,
		uuid TEXT,
		xuid TEXT,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		total_bytes INTEGER DEFAULT 0,
		total_playtime INTEGER DEFAULT 0,
		metadata TEXT
	);

	-- api_keys table
	CREATE TABLE IF NOT EXISTS api_keys (
		key TEXT PRIMARY KEY,
		name TEXT,
		created_at DATETIME NOT NULL,
		last_used DATETIME,
		is_admin BOOLEAN DEFAULT FALSE
	);

	-- api_access_log table
	CREATE TABLE IF NOT EXISTS api_access_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		api_key TEXT,
		endpoint TEXT,
		timestamp DATETIME NOT NULL,
		FOREIGN KEY (api_key) REFERENCES api_keys(key)
	);

	-- Create indexes for common queries
	CREATE INDEX IF NOT EXISTS idx_sessions_uuid ON sessions(uuid);
	CREATE INDEX IF NOT EXISTS idx_sessions_server_id ON sessions(server_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
	CREATE INDEX IF NOT EXISTS idx_players_last_seen ON players(last_seen);
	CREATE INDEX IF NOT EXISTS idx_players_xuid ON players(xuid);
	CREATE INDEX IF NOT EXISTS idx_api_access_log_timestamp ON api_access_log(timestamp);

	-- blacklist table
	CREATE TABLE IF NOT EXISTS blacklist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		display_name TEXT NOT NULL,
		display_name_lower TEXT NOT NULL,
		reason TEXT,
		server_id TEXT,
		added_at DATETIME NOT NULL,
		expires_at DATETIME,
		added_by TEXT,
		UNIQUE(display_name_lower, server_id)
	);

	CREATE INDEX IF NOT EXISTS idx_blacklist_name ON blacklist(display_name_lower);
	CREATE INDEX IF NOT EXISTS idx_blacklist_server ON blacklist(server_id);

	-- whitelist table
	CREATE TABLE IF NOT EXISTS whitelist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		display_name TEXT NOT NULL,
		display_name_lower TEXT NOT NULL,
		server_id TEXT,
		added_at DATETIME NOT NULL,
		added_by TEXT,
		UNIQUE(display_name_lower, server_id)
	);

	CREATE INDEX IF NOT EXISTS idx_whitelist_name ON whitelist(display_name_lower);
	CREATE INDEX IF NOT EXISTS idx_whitelist_server ON whitelist(server_id);

	-- acl_settings table
	CREATE TABLE IF NOT EXISTS acl_settings (
		server_id TEXT PRIMARY KEY,
		whitelist_enabled BOOLEAN DEFAULT FALSE,
		default_ban_message TEXT DEFAULT 'You are banned from this server',
		whitelist_message TEXT DEFAULT 'You are not whitelisted on this server'
	);
	`

	_, err := d.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	return nil
}

// Close closes the database connection.
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// DB returns the underlying sql.DB for use by repositories.
func (d *Database) DB() *sql.DB {
	return d.db
}
