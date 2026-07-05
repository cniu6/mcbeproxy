package db

import (
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/session"
)

func newTestSessionRepository(t *testing.T) (*Database, *SessionRepository) {
	t.Helper()
	database, err := NewDatabase(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	if err := database.Initialize(); err != nil {
		database.Close()
		t.Fatalf("Initialize failed: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, NewSessionRepository(database, 100)
}

func TestSessionRepositoryPersistsXUID(t *testing.T) {
	_, repo := newTestSessionRepository(t)

	record := &session.SessionRecord{
		ID:          "session-xuid-1",
		ClientAddr:  "127.0.0.1:19132",
		ServerID:    "srv1",
		UUID:        "uuid-1",
		XUID:        "xuid-1",
		DisplayName: "PlayerOne",
		BytesUp:     123,
		BytesDown:   456,
		StartTime:   time.Now().Add(-time.Minute).Truncate(time.Second),
		EndTime:     time.Now().Truncate(time.Second),
		Status:      "disconnected",
	}
	if err := repo.Create(record); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	got, err := repo.GetByID(record.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got.XUID != record.XUID {
		t.Fatalf("XUID = %q, want %q", got.XUID, record.XUID)
	}

	listed, err := repo.List(10, 0)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(listed) != 1 || listed[0].XUID != record.XUID {
		t.Fatalf("List XUID not preserved: %+v", listed)
	}
}

func TestDatabaseInitializeMigratesSessionsXUID(t *testing.T) {
	database, repo := newTestSessionRepository(t)
	if _, err := database.DB().Exec("ALTER TABLE sessions RENAME TO sessions_new_schema"); err != nil {
		t.Fatalf("rename sessions table failed: %v", err)
	}
	if _, err := database.DB().Exec(`CREATE TABLE sessions (
		id TEXT PRIMARY KEY,
		client_addr TEXT NOT NULL,
		server_id TEXT NOT NULL,
		uuid TEXT,
		display_name TEXT,
		bytes_up INTEGER DEFAULT 0,
		bytes_down INTEGER DEFAULT 0,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		metadata TEXT,
		status TEXT DEFAULT '',
		status_reason TEXT DEFAULT ''
	)`); err != nil {
		t.Fatalf("create legacy sessions table failed: %v", err)
	}
	if _, err := database.DB().Exec("DROP TABLE sessions_new_schema"); err != nil {
		t.Fatalf("drop renamed sessions table failed: %v", err)
	}

	if err := database.Initialize(); err != nil {
		t.Fatalf("Initialize migration failed: %v", err)
	}

	record := &session.SessionRecord{
		ID:          "session-xuid-migrated",
		ClientAddr:  "127.0.0.1:19133",
		ServerID:    "srv1",
		XUID:        "xuid-migrated",
		DisplayName: "MigratedPlayer",
		StartTime:   time.Now().Add(-time.Minute),
		EndTime:     time.Now(),
	}
	if err := repo.Create(record); err != nil {
		t.Fatalf("Create after migration failed: %v", err)
	}
	got, err := repo.GetByID(record.ID)
	if err != nil {
		t.Fatalf("GetByID after migration failed: %v", err)
	}
	if got.XUID != record.XUID {
		t.Fatalf("migrated XUID = %q, want %q", got.XUID, record.XUID)
	}
}
