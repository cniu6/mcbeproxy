// Package db provides database access and persistence functionality.
package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

func TestPlayerRepositoryUpdateStatsWithIdentityUsesProvidedLastSeen(t *testing.T) {
	database, err := NewDatabase(filepath.Join(t.TempDir(), "players.db"))
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	if err := database.Initialize(); err != nil {
		database.Close()
		t.Fatalf("Initialize failed: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	repo := NewPlayerRepository(database)
	createdAt := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	if err := repo.Create(&PlayerRecord{
		DisplayName:   "SameName",
		UUID:          "old-uuid",
		XUID:          "old-xuid",
		FirstSeen:     createdAt,
		LastSeen:      createdAt,
		TotalBytes:    10,
		TotalPlaytime: 20,
	}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	lastSeen := createdAt.Add(time.Hour)
	if err := repo.UpdateStatsWithIdentity("SameName", "new-uuid", "new-xuid", 30, 40*time.Second, lastSeen); err != nil {
		t.Fatalf("UpdateStatsWithIdentity failed: %v", err)
	}

	got, err := repo.GetByDisplayName("SameName")
	if err != nil {
		t.Fatalf("GetByDisplayName failed: %v", err)
	}
	if got.UUID != "new-uuid" || got.XUID != "new-xuid" {
		t.Fatalf("identity not refreshed: uuid=%q xuid=%q", got.UUID, got.XUID)
	}
	if !got.LastSeen.Equal(lastSeen) {
		t.Fatalf("LastSeen = %v, want %v", got.LastSeen, lastSeen)
	}
	if got.TotalBytes != 40 || got.TotalPlaytime != 60 {
		t.Fatalf("stats not accumulated: bytes=%d playtime=%d", got.TotalBytes, got.TotalPlaytime)
	}
}


// **Validates: Requirements 4.4**
// *For any* player, after a session ends, the player's total_bytes SHALL increase by
// the session's (bytes_up + bytes_down), and total_playtime SHALL increase by the session duration.
func TestProperty_PlayerStatsAccumulation(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Player stats accumulate correctly after session updates", prop.ForAll(
		func(uuid string, displayName string, initialBytes int64, initialPlaytime int64,
			sessionBytesUp int64, sessionBytesDown int64, sessionDurationSec int64) bool {

			// Setup: create temp database
			dbPath := "test_player_stats_" + uuid + ".db"
			defer os.Remove(dbPath)

			db, err := NewDatabase(dbPath)
			if err != nil {
				t.Logf("Failed to create database: %v", err)
				return false
			}
			defer db.Close()

			if err := db.Initialize(); err != nil {
				t.Logf("Failed to initialize database: %v", err)
				return false
			}

			repo := NewPlayerRepository(db)

			// Create initial player
			now := time.Now()
			player := &PlayerRecord{
				UUID:          uuid,
				DisplayName:   displayName,
				FirstSeen:     now,
				LastSeen:      now,
				TotalBytes:    initialBytes,
				TotalPlaytime: initialPlaytime,
			}

			if err := repo.Create(player); err != nil {
				t.Logf("Failed to create player: %v", err)
				return false
			}

			// Simulate session end: update stats
			sessionTotalBytes := sessionBytesUp + sessionBytesDown
			sessionDuration := time.Duration(sessionDurationSec) * time.Second

			if err := repo.UpdateStats(displayName, sessionTotalBytes, sessionDuration); err != nil {
				t.Logf("Failed to update stats: %v", err)
				return false
			}

			// Verify: retrieve player and check accumulated stats
			updatedPlayer, err := repo.GetByDisplayName(displayName)
			if err != nil {
				t.Logf("Failed to get player: %v", err)
				return false
			}

			// Property: total_bytes should increase by session's (bytes_up + bytes_down)
			expectedBytes := initialBytes + sessionTotalBytes
			if updatedPlayer.TotalBytes != expectedBytes {
				t.Logf("Bytes mismatch: expected %d, got %d", expectedBytes, updatedPlayer.TotalBytes)
				return false
			}

			// Property: total_playtime should increase by session duration
			expectedPlaytime := initialPlaytime + sessionDurationSec
			if updatedPlayer.TotalPlaytime != expectedPlaytime {
				t.Logf("Playtime mismatch: expected %d, got %d", expectedPlaytime, updatedPlayer.TotalPlaytime)
				return false
			}

			return true
		},
		// Generate valid UUID (alphanumeric, non-empty, 8-36 chars)
		gen.Identifier().Map(func(s string) string {
			if len(s) > 36 {
				return s[:36]
			}
			return s
		}),
		// Generate display name (can be empty)
		gen.AlphaString().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		// Generate initial bytes (non-negative)
		gen.Int64Range(0, 1000000000),
		// Generate initial playtime (non-negative seconds)
		gen.Int64Range(0, 86400*365), // up to 1 year
		// Generate session bytes up (non-negative)
		gen.Int64Range(0, 100000000),
		// Generate session bytes down (non-negative)
		gen.Int64Range(0, 100000000),
		// Generate session duration (non-negative seconds)
		gen.Int64Range(0, 86400), // up to 1 day
	))

	properties.TestingRun(t)
}
