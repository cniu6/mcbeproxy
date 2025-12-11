// Package db provides database access and persistence functionality.
package db

import (
	"os"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// **Feature: player-access-control, Property 6: ACL Entry Round-Trip**
// **Validates: Requirements 4.4, 4.5**
// *For any* blacklist or whitelist entry, serializing to database and deserializing back
// SHALL produce an equivalent entry.
func TestProperty_ACLEntryRoundTrip_Blacklist(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Blacklist entry round-trip preserves data", prop.ForAll(
		func(displayName string, reason string, serverID string, addedBy string, hasExpiry bool, expiryOffsetHours int) bool {
			// Skip empty display names as they are invalid
			if displayName == "" {
				return true
			}

			// Setup: create temp database
			dbPath := "test_blacklist_roundtrip_" + displayName + ".db"
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

			repo := NewBlacklistRepository(db)

			// Create entry
			now := time.Now().Truncate(time.Second) // SQLite stores with second precision
			var expiresAt *time.Time
			if hasExpiry {
				expiry := now.Add(time.Duration(expiryOffsetHours) * time.Hour)
				expiresAt = &expiry
			}

			entry := &BlacklistEntry{
				DisplayName: displayName,
				Reason:      reason,
				ServerID:    serverID,
				AddedAt:     now,
				ExpiresAt:   expiresAt,
				AddedBy:     addedBy,
			}

			// Serialize (Create)
			if err := repo.Create(entry); err != nil {
				t.Logf("Failed to create blacklist entry: %v", err)
				return false
			}

			// Deserialize (GetByName)
			retrieved, err := repo.GetByName(displayName, serverID)
			if err != nil {
				t.Logf("Failed to get blacklist entry: %v", err)
				return false
			}

			// Verify round-trip preserves data
			if retrieved.DisplayName != entry.DisplayName {
				t.Logf("DisplayName mismatch: expected %q, got %q", entry.DisplayName, retrieved.DisplayName)
				return false
			}
			if retrieved.Reason != entry.Reason {
				t.Logf("Reason mismatch: expected %q, got %q", entry.Reason, retrieved.Reason)
				return false
			}
			if retrieved.ServerID != entry.ServerID {
				t.Logf("ServerID mismatch: expected %q, got %q", entry.ServerID, retrieved.ServerID)
				return false
			}
			if retrieved.AddedBy != entry.AddedBy {
				t.Logf("AddedBy mismatch: expected %q, got %q", entry.AddedBy, retrieved.AddedBy)
				return false
			}
			// Compare times with second precision
			if !retrieved.AddedAt.Truncate(time.Second).Equal(entry.AddedAt.Truncate(time.Second)) {
				t.Logf("AddedAt mismatch: expected %v, got %v", entry.AddedAt, retrieved.AddedAt)
				return false
			}
			// Compare expiry times
			if hasExpiry {
				if retrieved.ExpiresAt == nil {
					t.Logf("ExpiresAt is nil but expected %v", entry.ExpiresAt)
					return false
				}
				if !retrieved.ExpiresAt.Truncate(time.Second).Equal(entry.ExpiresAt.Truncate(time.Second)) {
					t.Logf("ExpiresAt mismatch: expected %v, got %v", entry.ExpiresAt, retrieved.ExpiresAt)
					return false
				}
			} else {
				if retrieved.ExpiresAt != nil {
					t.Logf("ExpiresAt should be nil but got %v", retrieved.ExpiresAt)
					return false
				}
			}

			return true
		},
		// Generate display name (non-empty alphanumeric)
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		// Generate reason
		gen.AlphaString().Map(func(s string) string {
			if len(s) > 200 {
				return s[:200]
			}
			return s
		}),
		// Generate server ID (can be empty for global)
		gen.OneConstOf("", "server1", "server2", "test-server"),
		// Generate added by
		gen.AlphaString().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		// Generate whether entry has expiry
		gen.Bool(),
		// Generate expiry offset in hours (1-720 hours = 1 hour to 30 days)
		gen.IntRange(1, 720),
	))

	properties.TestingRun(t)
}

// **Feature: player-access-control, Property 6: ACL Entry Round-Trip**
// **Validates: Requirements 4.4, 4.5**
// *For any* whitelist entry, serializing to database and deserializing back
// SHALL produce an equivalent entry.
func TestProperty_ACLEntryRoundTrip_Whitelist(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Whitelist entry round-trip preserves data", prop.ForAll(
		func(displayName string, serverID string, addedBy string) bool {
			// Skip empty display names as they are invalid
			if displayName == "" {
				return true
			}

			// Setup: create temp database
			dbPath := "test_whitelist_roundtrip_" + displayName + ".db"
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

			repo := NewWhitelistRepository(db)

			// Create entry
			now := time.Now().Truncate(time.Second) // SQLite stores with second precision

			entry := &WhitelistEntry{
				DisplayName: displayName,
				ServerID:    serverID,
				AddedAt:     now,
				AddedBy:     addedBy,
			}

			// Serialize (Create)
			if err := repo.Create(entry); err != nil {
				t.Logf("Failed to create whitelist entry: %v", err)
				return false
			}

			// Deserialize (GetByName)
			retrieved, err := repo.GetByName(displayName, serverID)
			if err != nil {
				t.Logf("Failed to get whitelist entry: %v", err)
				return false
			}

			// Verify round-trip preserves data
			if retrieved.DisplayName != entry.DisplayName {
				t.Logf("DisplayName mismatch: expected %q, got %q", entry.DisplayName, retrieved.DisplayName)
				return false
			}
			if retrieved.ServerID != entry.ServerID {
				t.Logf("ServerID mismatch: expected %q, got %q", entry.ServerID, retrieved.ServerID)
				return false
			}
			if retrieved.AddedBy != entry.AddedBy {
				t.Logf("AddedBy mismatch: expected %q, got %q", entry.AddedBy, retrieved.AddedBy)
				return false
			}
			// Compare times with second precision
			if !retrieved.AddedAt.Truncate(time.Second).Equal(entry.AddedAt.Truncate(time.Second)) {
				t.Logf("AddedAt mismatch: expected %v, got %v", entry.AddedAt, retrieved.AddedAt)
				return false
			}

			return true
		},
		// Generate display name (non-empty alphanumeric)
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		// Generate server ID (can be empty for global)
		gen.OneConstOf("", "server1", "server2", "test-server"),
		// Generate added by
		gen.AlphaString().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
	))

	properties.TestingRun(t)
}
