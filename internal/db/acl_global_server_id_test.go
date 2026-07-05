package db

import (
	"os"
	"testing"
	"time"
)

func TestGlobalBlacklistCreateUpsertsSingleRow(t *testing.T) {
	path := "test_acl_global_bl_" + t.Name() + ".db"
	defer os.Remove(path)

	database, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Initialize(); err != nil {
		t.Fatal(err)
	}

	repo := NewBlacklistRepository(database)
	now := time.Now().Truncate(time.Second)

	e1 := &BlacklistEntry{
		DisplayName: "PlayerOne",
		Reason:      "first",
		ServerID:    "",
		Enabled:     true,
		AddedAt:     now,
		AddedBy:     "admin",
	}
	if err := repo.Create(e1); err != nil {
		t.Fatal(err)
	}

	later := now.Add(time.Hour)
	e2 := &BlacklistEntry{
		DisplayName: "playerone",
		Reason:      "second",
		ServerID:    "  ",
		Enabled:     false,
		AddedAt:     later,
		AddedBy:     "mod",
	}
	if err := repo.Create(e2); err != nil {
		t.Fatal(err)
	}

	list, err := repo.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 global blacklist row, got %d", len(list))
	}
	if list[0].Reason != "second" {
		t.Fatalf("expected upserted reason %q, got %q", "second", list[0].Reason)
	}
	if list[0].ServerID != "" {
		t.Fatalf("expected empty server_id, got %q", list[0].ServerID)
	}

	var nullCount int
	if err := database.DB().QueryRow(`SELECT COUNT(*) FROM blacklist WHERE server_id IS NULL`).Scan(&nullCount); err != nil {
		t.Fatal(err)
	}
	if nullCount != 0 {
		t.Fatalf("expected no NULL server_id rows, got %d", nullCount)
	}
}

func TestMigrateACLServerIDDedupesLegacyNullGlobals(t *testing.T) {
	path := "test_acl_migrate_null_" + t.Name() + ".db"
	defer os.Remove(path)

	database, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Minimal schema without running full Initialize migrations first — insert legacy NULL rows.
	_, err = database.DB().Exec(`
		CREATE TABLE blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			display_name TEXT NOT NULL,
			display_name_lower TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			reason TEXT,
			server_id TEXT,
			added_at DATETIME NOT NULL,
			expires_at DATETIME,
			added_by TEXT,
			UNIQUE(display_name_lower, server_id)
		);
		CREATE TABLE whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			display_name TEXT NOT NULL,
			display_name_lower TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			reason TEXT,
			server_id TEXT,
			added_at DATETIME NOT NULL,
			expires_at DATETIME,
			added_by TEXT,
			UNIQUE(display_name_lower, server_id)
		);
		CREATE TABLE acl_settings (
			server_id TEXT PRIMARY KEY,
			blacklist_enabled BOOLEAN DEFAULT TRUE,
			whitelist_enabled BOOLEAN DEFAULT FALSE,
			default_ban_message TEXT DEFAULT '你已被封禁',
			whitelist_message TEXT DEFAULT '你不在白名单中'
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	for i := 0; i < 3; i++ {
		_, err = database.DB().Exec(
			`INSERT INTO blacklist (display_name, display_name_lower, enabled, reason, server_id, added_at, added_by)
			 VALUES (?, ?, 1, ?, NULL, ?, 'test')`,
			"DupPlayer", "dupplayer", "reason", now.Add(time.Duration(i)*time.Minute),
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := migrateACLServerIDScope(database.DB()); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := database.DB().QueryRow(
		`SELECT COUNT(*) FROM blacklist WHERE display_name_lower = 'dupplayer' AND server_id = ''`,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 deduped global row, got %d", count)
	}
}

func TestMigrateACLServerIDNormalizesDisplayNameWhitespace(t *testing.T) {
	path := "test_acl_migrate_trim_" + t.Name() + ".db"
	defer os.Remove(path)

	database, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	_, err = database.DB().Exec(`
		CREATE TABLE blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			display_name TEXT NOT NULL,
			display_name_lower TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			reason TEXT,
			server_id TEXT,
			added_at DATETIME NOT NULL,
			expires_at DATETIME,
			added_by TEXT,
			UNIQUE(display_name_lower, server_id)
		);
		CREATE TABLE whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			display_name TEXT NOT NULL,
			display_name_lower TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			reason TEXT,
			server_id TEXT,
			added_at DATETIME NOT NULL,
			expires_at DATETIME,
			added_by TEXT,
			UNIQUE(display_name_lower, server_id)
		);
		CREATE TABLE acl_settings (
			server_id TEXT PRIMARY KEY,
			blacklist_enabled BOOLEAN DEFAULT TRUE,
			whitelist_enabled BOOLEAN DEFAULT FALSE,
			default_ban_message TEXT DEFAULT '你已被封禁',
			whitelist_message TEXT DEFAULT '你不在白名单中'
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, err = database.DB().Exec(
		`INSERT INTO blacklist (display_name, display_name_lower, enabled, reason, server_id, added_at, added_by)
		 VALUES (?, ?, 1, 'a', '', ?, 'test'), (?, ?, 1, 'b', NULL, ?, 'test')`,
		" Player ", " player ", now,
		"player", "player", now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := migrateACLServerIDScope(database.DB()); err != nil {
		t.Fatal(err)
	}
	repo := NewBlacklistRepository(database)
	got, err := repo.GetByName("Player", "")
	if err != nil {
		t.Fatalf("GetByName after migration failed: %v", err)
	}
	if got.DisplayName != "player" && got.DisplayName != "Player" {
		t.Fatalf("display_name was not trimmed, got %q", got.DisplayName)
	}
	var rows int
	if err := database.DB().QueryRow(`SELECT COUNT(*) FROM blacklist WHERE display_name_lower = 'player' AND server_id = ''`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("expected 1 normalized row, got %d", rows)
	}
}

func TestGlobalWhitelistCreateUpsertsSingleRow(t *testing.T) {
	path := "test_acl_global_wl_" + t.Name() + ".db"
	defer os.Remove(path)

	database, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Initialize(); err != nil {
		t.Fatal(err)
	}

	repo := NewWhitelistRepository(database)
	now := time.Now().Truncate(time.Second)

	if err := repo.Create(&WhitelistEntry{
		DisplayName: "VIP",
		Reason:      "a",
		ServerID:    "",
		Enabled:     true,
		AddedAt:     now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(&WhitelistEntry{
		DisplayName: "vip",
		Reason:      "b",
		ServerID:    "",
		Enabled:     true,
		AddedAt:     now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	list, err := repo.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 global whitelist row, got %d", len(list))
	}
	if list[0].Reason != "b" {
		t.Fatalf("expected upserted reason %q, got %q", "b", list[0].Reason)
	}
}

func TestMigrateACLServerIDNullAndEmptySamePlayer(t *testing.T) {
	path := "test_acl_migrate_null_empty_" + t.Name() + ".db"
	defer os.Remove(path)

	database, err := NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	_, err = database.DB().Exec(`
		CREATE TABLE blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			display_name TEXT NOT NULL,
			display_name_lower TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			reason TEXT,
			server_id TEXT,
			added_at DATETIME NOT NULL,
			expires_at DATETIME,
			added_by TEXT,
			UNIQUE(display_name_lower, server_id)
		);
		CREATE TABLE whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			display_name TEXT NOT NULL,
			display_name_lower TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			reason TEXT,
			server_id TEXT,
			added_at DATETIME NOT NULL,
			expires_at DATETIME,
			added_by TEXT,
			UNIQUE(display_name_lower, server_id)
		);
		CREATE TABLE acl_settings (
			server_id TEXT PRIMARY KEY,
			blacklist_enabled BOOLEAN DEFAULT TRUE,
			whitelist_enabled BOOLEAN DEFAULT FALSE,
			default_ban_message TEXT DEFAULT '你已被封禁',
			whitelist_message TEXT DEFAULT '你不在白名单中'
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	_, err = database.DB().Exec(
		`INSERT INTO blacklist (display_name, display_name_lower, enabled, reason, server_id, added_at, added_by)
		 VALUES ('Same', 'same', 1, 'null-row', NULL, ?, 't')`,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.DB().Exec(
		`INSERT INTO blacklist (display_name, display_name_lower, enabled, reason, server_id, added_at, added_by)
		 VALUES ('Same', 'same', 1, 'empty-row', '', ?, 't')`,
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := migrateACLServerIDScope(database.DB()); err != nil {
		t.Fatalf("migrate failed: %v", err)
	}

	var count int
	var reason string
	if err := database.DB().QueryRow(
		`SELECT COUNT(*), MAX(reason) FROM blacklist WHERE display_name_lower = 'same' AND server_id = ''`,
	).Scan(&count, &reason); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 merged global row, got %d", count)
	}
}

func TestACLSettingsRepositoryNormalizesWhitespaceServerID(t *testing.T) {
	database := newACLTestDatabase(t)
	repo := NewACLSettingsRepository(database)

	settings := &ACLSettings{
		ServerID:         "  ",
		BlacklistEnabled: false,
		WhitelistEnabled: true,
		DefaultMessage:   "global-msg",
		WhitelistMessage: "wl-msg",
	}
	if err := repo.Update(settings); err != nil {
		t.Fatal(err)
	}
	if settings.ServerID != "" {
		t.Fatalf("Update normalized ServerID = %q, want empty", settings.ServerID)
	}

	got, err := repo.Get("")
	if err != nil {
		t.Fatal(err)
	}
	if !got.WhitelistEnabled || got.DefaultMessage != "global-msg" {
		t.Fatalf("Get global settings = %+v, want global-msg and whitelist on", got)
	}
}

func TestBlacklistCreateUpsertReloadsStableID(t *testing.T) {
	database := newACLTestDatabase(t)
	repo := NewBlacklistRepository(database)
	now := time.Now().Truncate(time.Second)

	e1 := &BlacklistEntry{
		DisplayName: "IdTest",
		Reason:      "a",
		ServerID:    "srv1",
		Enabled:     true,
		AddedAt:     now,
	}
	if err := repo.Create(e1); err != nil {
		t.Fatal(err)
	}
	id1 := e1.ID
	if id1 == 0 {
		t.Fatal("expected non-zero id after first create")
	}

	e2 := &BlacklistEntry{
		DisplayName: "idtest",
		Reason:      "b",
		ServerID:    "srv1",
		Enabled:     false,
		AddedAt:     now.Add(time.Hour),
	}
	if err := repo.Create(e2); err != nil {
		t.Fatal(err)
	}
	if e2.ID != id1 {
		t.Fatalf("upsert id = %d, want same row id %d", e2.ID, id1)
	}
	if e2.Reason != "b" {
		t.Fatalf("upsert reason = %q, want b", e2.Reason)
	}
}
