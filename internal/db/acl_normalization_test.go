package db

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newACLTestDatabase(t *testing.T) *Database {
	t.Helper()
	database, err := NewDatabase(filepath.Join(t.TempDir(), "acl.db"))
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	})
	if err := database.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	return database
}

func TestBlacklistRepositoryNormalizesDisplayNameWhitespace(t *testing.T) {
	database := newACLTestDatabase(t)
	repo := NewBlacklistRepository(database)

	entry := &BlacklistEntry{
		DisplayName: "  PlayerOne  ",
		Enabled:     true,
		Reason:      "test",
		AddedAt:     time.Now().Truncate(time.Second),
	}
	if err := repo.Create(entry); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if entry.DisplayName != "PlayerOne" {
		t.Fatalf("Create normalized entry DisplayName = %q, want PlayerOne", entry.DisplayName)
	}

	got, err := repo.GetByName(" playerone ", "")
	if err != nil {
		t.Fatalf("GetByName with trimmed lower lookup failed: %v", err)
	}
	if got.DisplayName != "PlayerOne" {
		t.Fatalf("stored DisplayName = %q, want trimmed original casing", got.DisplayName)
	}

	if err := repo.UpdateEnabled(" PLAYERONE ", "", false); err != nil {
		t.Fatalf("UpdateEnabled with spaced lookup failed: %v", err)
	}
	got, err = repo.GetByName("playerone", "")
	if err != nil {
		t.Fatalf("GetByName after update failed: %v", err)
	}
	if got.Enabled {
		t.Fatal("UpdateEnabled did not disable blacklist entry")
	}

	if err := repo.Delete(" PlayerOne ", ""); err != nil {
		t.Fatalf("Delete with spaced lookup failed: %v", err)
	}
	if _, err := repo.GetByName("playerone", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetByName after delete error = %v, want sql.ErrNoRows", err)
	}
}

func TestWhitelistRepositoryNormalizesDisplayNameWhitespace(t *testing.T) {
	database := newACLTestDatabase(t)
	repo := NewWhitelistRepository(database)

	entry := &WhitelistEntry{
		DisplayName: "  PlayerTwo  ",
		Enabled:     true,
		Reason:      "test",
		AddedAt:     time.Now().Truncate(time.Second),
	}
	if err := repo.Create(entry); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if entry.DisplayName != "PlayerTwo" {
		t.Fatalf("Create normalized entry DisplayName = %q, want PlayerTwo", entry.DisplayName)
	}

	got, err := repo.GetByName(" playertwo ", "")
	if err != nil {
		t.Fatalf("GetByName with trimmed lower lookup failed: %v", err)
	}
	if got.DisplayName != "PlayerTwo" {
		t.Fatalf("stored DisplayName = %q, want trimmed original casing", got.DisplayName)
	}

	if err := repo.UpdateEnabled(" PLAYERTWO ", "", false); err != nil {
		t.Fatalf("UpdateEnabled with spaced lookup failed: %v", err)
	}
	got, err = repo.GetByName("playertwo", "")
	if err != nil {
		t.Fatalf("GetByName after update failed: %v", err)
	}
	if got.Enabled {
		t.Fatal("UpdateEnabled did not disable whitelist entry")
	}

	if err := repo.Delete(" PlayerTwo ", ""); err != nil {
		t.Fatalf("Delete with spaced lookup failed: %v", err)
	}
	if _, err := repo.GetByName("playertwo", ""); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetByName after delete error = %v, want sql.ErrNoRows", err)
	}
}
