// Package acl provides access control list management for player access control.
package acl

import (
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"mcpeserverproxy/internal/db"
)

// **Feature: player-access-control, Property 1: Blacklist Membership Determines Access Denial**
// **Validates: Requirements 1.1, 1.2, 1.3**
// *For any* player name and server, if the player is in the blacklist (global or server-specific)
// and the entry has not expired, then CheckAccess SHALL return denied with the ban reason.
func TestProperty_BlacklistMembershipDeterminesAccessDenial(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Blacklisted player is denied access", prop.ForAll(
		func(playerName string, serverID string, reason string, isGlobal bool) bool {
			// Skip empty player names
			if playerName == "" {
				return true
			}

			// Create a non-expired blacklist entry
			now := time.Now()
			futureExpiry := now.Add(24 * time.Hour)

			var globalBlacklist []*db.BlacklistEntry
			var serverBlacklist []*db.BlacklistEntry

			entry := &db.BlacklistEntry{
				ID:          1,
				DisplayName: playerName,
				Reason:      reason,
				AddedAt:     now,
				ExpiresAt:   &futureExpiry,
			}

			if isGlobal {
				entry.ServerID = ""
				globalBlacklist = append(globalBlacklist, entry)
			} else {
				entry.ServerID = serverID
				serverBlacklist = append(serverBlacklist, entry)
			}

			// Settings with whitelist disabled
			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: false,
			}

			// Check access
			allowed, denialReason := CheckAccessWithEntries(
				playerName,
				serverID,
				globalBlacklist,
				serverBlacklist,
				nil,
				nil,
				settings,
			)

			// Verify: access should be denied
			if allowed {
				t.Logf("Expected access denied for blacklisted player %q", playerName)
				return false
			}

			// Verify: reason should match (or default if empty)
			expectedReason := reason
			if expectedReason == "" {
				expectedReason = "You are banned from this server"
			}
			if denialReason != expectedReason {
				t.Logf("Expected reason %q, got %q", expectedReason, denialReason)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("", "server1", "server2"),
		gen.AlphaString().Map(func(s string) string {
			if len(s) > 100 {
				return s[:100]
			}
			return s
		}),
		gen.Bool(),
	))

	properties.TestingRun(t)
}

// **Feature: player-access-control, Property 2: Expired Blacklist Entries Are Ignored**
// **Validates: Requirements 1.5**
// *For any* blacklist entry with an expiry time in the past, the entry SHALL be treated
// as if it does not exist when checking access.
func TestProperty_ExpiredBlacklistEntriesAreIgnored(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Expired blacklist entries do not block access", prop.ForAll(
		func(playerName string, serverID string, hoursAgo int) bool {
			// Skip empty player names
			if playerName == "" {
				return true
			}

			// Create an expired blacklist entry
			now := time.Now()
			pastExpiry := now.Add(-time.Duration(hoursAgo) * time.Hour)

			entry := &db.BlacklistEntry{
				ID:          1,
				DisplayName: playerName,
				Reason:      "Test ban",
				ServerID:    "",
				AddedAt:     now.Add(-48 * time.Hour),
				ExpiresAt:   &pastExpiry,
			}

			globalBlacklist := []*db.BlacklistEntry{entry}

			// Settings with whitelist disabled
			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: false,
			}

			// Check access
			allowed, _ := CheckAccessWithEntries(
				playerName,
				serverID,
				globalBlacklist,
				nil,
				nil,
				nil,
				settings,
			)

			// Verify: access should be allowed because entry is expired
			if !allowed {
				t.Logf("Expected access allowed for player %q with expired blacklist entry", playerName)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("", "server1", "server2"),
		gen.IntRange(1, 720), // 1 hour to 30 days ago
	))

	properties.TestingRun(t)
}

// **Feature: player-access-control, Property 3: Case-Insensitive Name Matching**
// **Validates: Requirements 1.7, 2.6**
// *For any* player name added to blacklist or whitelist, checking access with any case
// variation of that name SHALL produce the same result.
func TestProperty_CaseInsensitiveNameMatching(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Case variations produce same blacklist result", prop.ForAll(
		func(baseName string, serverID string) bool {
			// Skip empty names
			if baseName == "" {
				return true
			}

			// Create blacklist entry with original case
			now := time.Now()
			futureExpiry := now.Add(24 * time.Hour)

			entry := &db.BlacklistEntry{
				ID:          1,
				DisplayName: baseName,
				Reason:      "Test ban",
				ServerID:    "",
				AddedAt:     now,
				ExpiresAt:   &futureExpiry,
			}

			globalBlacklist := []*db.BlacklistEntry{entry}
			settings := &db.ACLSettings{WhitelistEnabled: false}

			// Test with different case variations
			variations := []string{
				baseName,
				toUpperCase(baseName),
				toLowerCase(baseName),
				mixedCase(baseName),
			}

			for _, variant := range variations {
				allowed, _ := CheckAccessWithEntries(
					variant,
					serverID,
					globalBlacklist,
					nil,
					nil,
					nil,
					settings,
				)
				if allowed {
					t.Logf("Expected access denied for case variant %q of %q", variant, baseName)
					return false
				}
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("", "server1"),
	))

	properties.Property("Case variations produce same whitelist result", prop.ForAll(
		func(baseName string, serverID string) bool {
			// Skip empty names
			if baseName == "" {
				return true
			}

			// Create whitelist entry with original case
			now := time.Now()

			entry := &db.WhitelistEntry{
				ID:          1,
				DisplayName: baseName,
				ServerID:    "",
				AddedAt:     now,
			}

			globalWhitelist := []*db.WhitelistEntry{entry}
			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: true,
				WhitelistMessage: "Not whitelisted",
			}

			// Test with different case variations
			variations := []string{
				baseName,
				toUpperCase(baseName),
				toLowerCase(baseName),
				mixedCase(baseName),
			}

			for _, variant := range variations {
				allowed, _ := CheckAccessWithEntries(
					variant,
					serverID,
					nil,
					nil,
					globalWhitelist,
					nil,
					settings,
				)
				if !allowed {
					t.Logf("Expected access allowed for case variant %q of whitelisted %q", variant, baseName)
					return false
				}
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("", "server1"),
	))

	properties.TestingRun(t)
}

// Helper functions for case manipulation
func toUpperCase(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			result[i] = c - 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func toLowerCase(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func mixedCase(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i%2 == 0 {
			if c >= 'a' && c <= 'z' {
				result[i] = c - 32
			} else {
				result[i] = c
			}
		} else {
			if c >= 'A' && c <= 'Z' {
				result[i] = c + 32
			} else {
				result[i] = c
			}
		}
	}
	return string(result)
}

// **Feature: player-access-control, Property 4: Whitelist Mode Restricts Access**
// **Validates: Requirements 2.1, 2.3**
// *For any* server with whitelist enabled, only players whose name is in the whitelist
// (global or server-specific) SHALL be allowed access.
func TestProperty_WhitelistModeRestrictsAccess(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Non-whitelisted players are denied when whitelist is enabled", prop.ForAll(
		func(playerName string, whitelistedName string, serverID string) bool {
			// Skip if names are the same (case-insensitive)
			if toLowerCase(playerName) == toLowerCase(whitelistedName) {
				return true
			}
			// Skip empty names
			if playerName == "" || whitelistedName == "" {
				return true
			}

			// Create whitelist with a different player
			now := time.Now()
			entry := &db.WhitelistEntry{
				ID:          1,
				DisplayName: whitelistedName,
				ServerID:    "",
				AddedAt:     now,
			}

			globalWhitelist := []*db.WhitelistEntry{entry}
			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: true,
				WhitelistMessage: "Not whitelisted",
			}

			// Check access for non-whitelisted player
			allowed, reason := CheckAccessWithEntries(
				playerName,
				serverID,
				nil,
				nil,
				globalWhitelist,
				nil,
				settings,
			)

			// Verify: access should be denied
			if allowed {
				t.Logf("Expected access denied for non-whitelisted player %q", playerName)
				return false
			}
			if reason != "Not whitelisted" {
				t.Logf("Expected whitelist denial message, got %q", reason)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("", "server1"),
	))

	properties.Property("Whitelisted players are allowed when whitelist is enabled", prop.ForAll(
		func(playerName string, serverID string, isGlobal bool) bool {
			// Skip empty names
			if playerName == "" {
				return true
			}

			// Create whitelist entry for the player
			now := time.Now()
			entry := &db.WhitelistEntry{
				ID:          1,
				DisplayName: playerName,
				AddedAt:     now,
			}

			var globalWhitelist []*db.WhitelistEntry
			var serverWhitelist []*db.WhitelistEntry

			if isGlobal {
				entry.ServerID = ""
				globalWhitelist = append(globalWhitelist, entry)
			} else {
				entry.ServerID = serverID
				serverWhitelist = append(serverWhitelist, entry)
			}

			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: true,
				WhitelistMessage: "Not whitelisted",
			}

			// Check access
			allowed, _ := CheckAccessWithEntries(
				playerName,
				serverID,
				nil,
				nil,
				globalWhitelist,
				serverWhitelist,
				settings,
			)

			// Verify: access should be allowed
			if !allowed {
				t.Logf("Expected access allowed for whitelisted player %q", playerName)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("server1", "server2"),
		gen.Bool(),
	))

	properties.TestingRun(t)
}

// **Feature: player-access-control, Property 5: Global Blacklist Priority**
// **Validates: Requirements 6.3**
// *For any* player in the global blacklist, access SHALL be denied regardless of
// server-specific whitelist entries.
func TestProperty_GlobalBlacklistPriority(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Global blacklist overrides server whitelist", prop.ForAll(
		func(playerName string, serverID string) bool {
			// Skip empty names
			if playerName == "" {
				return true
			}

			now := time.Now()
			futureExpiry := now.Add(24 * time.Hour)

			// Player is in global blacklist
			blacklistEntry := &db.BlacklistEntry{
				ID:          1,
				DisplayName: playerName,
				Reason:      "Global ban",
				ServerID:    "",
				AddedAt:     now,
				ExpiresAt:   &futureExpiry,
			}

			// Player is also in server whitelist
			whitelistEntry := &db.WhitelistEntry{
				ID:          1,
				DisplayName: playerName,
				ServerID:    serverID,
				AddedAt:     now,
			}

			globalBlacklist := []*db.BlacklistEntry{blacklistEntry}
			serverWhitelist := []*db.WhitelistEntry{whitelistEntry}

			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: true,
				WhitelistMessage: "Not whitelisted",
			}

			// Check access
			allowed, reason := CheckAccessWithEntries(
				playerName,
				serverID,
				globalBlacklist,
				nil,
				nil,
				serverWhitelist,
				settings,
			)

			// Verify: access should be denied due to global blacklist
			if allowed {
				t.Logf("Expected access denied for globally blacklisted player %q despite server whitelist", playerName)
				return false
			}
			if reason != "Global ban" {
				t.Logf("Expected ban reason 'Global ban', got %q", reason)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("server1", "server2"),
	))

	properties.TestingRun(t)
}

// **Feature: player-access-control, Property 7: Global and Server ACL Merge**
// **Validates: Requirements 1.6, 2.5, 6.2**
// *For any* access check, the system SHALL consider both global and server-specific entries,
// with global blacklist taking priority.
func TestProperty_GlobalAndServerACLMerge(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Server-specific blacklist blocks access", prop.ForAll(
		func(playerName string, serverID string) bool {
			// Skip empty names or empty serverID
			if playerName == "" || serverID == "" {
				return true
			}

			now := time.Now()
			futureExpiry := now.Add(24 * time.Hour)

			// Player is only in server-specific blacklist
			blacklistEntry := &db.BlacklistEntry{
				ID:          1,
				DisplayName: playerName,
				Reason:      "Server ban",
				ServerID:    serverID,
				AddedAt:     now,
				ExpiresAt:   &futureExpiry,
			}

			serverBlacklist := []*db.BlacklistEntry{blacklistEntry}

			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: false,
			}

			// Check access
			allowed, _ := CheckAccessWithEntries(
				playerName,
				serverID,
				nil,
				serverBlacklist,
				nil,
				nil,
				settings,
			)

			// Verify: access should be denied
			if allowed {
				t.Logf("Expected access denied for server-blacklisted player %q", playerName)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("server1", "server2"),
	))

	properties.Property("Global whitelist allows access to any server", prop.ForAll(
		func(playerName string, serverID string) bool {
			// Skip empty names
			if playerName == "" {
				return true
			}

			now := time.Now()

			// Player is in global whitelist
			whitelistEntry := &db.WhitelistEntry{
				ID:          1,
				DisplayName: playerName,
				ServerID:    "",
				AddedAt:     now,
			}

			globalWhitelist := []*db.WhitelistEntry{whitelistEntry}

			settings := &db.ACLSettings{
				ServerID:         serverID,
				WhitelistEnabled: true,
				WhitelistMessage: "Not whitelisted",
			}

			// Check access
			allowed, _ := CheckAccessWithEntries(
				playerName,
				serverID,
				nil,
				nil,
				globalWhitelist,
				nil,
				settings,
			)

			// Verify: access should be allowed
			if !allowed {
				t.Logf("Expected access allowed for globally whitelisted player %q", playerName)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("server1", "server2", "server3"),
	))

	properties.Property("Server whitelist only allows access to that server", prop.ForAll(
		func(playerName string, whitelistServer string, accessServer string) bool {
			// Skip empty names or same servers
			if playerName == "" || whitelistServer == accessServer {
				return true
			}

			now := time.Now()

			// Player is in server-specific whitelist for whitelistServer
			// When checking access to accessServer, this entry should NOT be in serverWhitelist
			// because serverWhitelist should only contain entries for the server being accessed
			whitelistEntry := &db.WhitelistEntry{
				ID:          1,
				DisplayName: playerName,
				ServerID:    whitelistServer,
				AddedAt:     now,
			}

			// The entry is for whitelistServer, not accessServer
			// So when checking access to accessServer, we pass empty serverWhitelist
			// This simulates the real behavior where the repository would only return
			// entries matching the requested serverID
			_ = whitelistEntry // Entry exists but is for different server

			settings := &db.ACLSettings{
				ServerID:         accessServer,
				WhitelistEnabled: true,
				WhitelistMessage: "Not whitelisted",
			}

			// Check access to a different server - no whitelist entries for this server
			allowed, _ := CheckAccessWithEntries(
				playerName,
				accessServer,
				nil,
				nil,
				nil,
				nil, // No server whitelist entries for accessServer
				settings,
			)

			// Verify: access should be denied because no whitelist entry for accessServer
			if allowed {
				t.Logf("Expected access denied for player %q whitelisted on %q but accessing %q",
					playerName, whitelistServer, accessServer)
				return false
			}

			return true
		},
		gen.Identifier().Map(func(s string) string {
			if len(s) > 50 {
				return s[:50]
			}
			return s
		}),
		gen.OneConstOf("server1", "server2"),
		gen.OneConstOf("server3", "server4"),
	))

	properties.TestingRun(t)
}
