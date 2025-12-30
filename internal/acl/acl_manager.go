// Package acl provides access control list management for player access control.
package acl

import (
	"database/sql"
	"strings"
	"sync"
	"time"

	"mcpeserverproxy/internal/db"
)

// ACLManager manages access control lists for blacklist and whitelist functionality.
// It provides thread-safe access to ACL operations.
type ACLManager struct {
	blacklistRepo *db.BlacklistRepository
	whitelistRepo *db.WhitelistRepository
	settingsRepo  *db.ACLSettingsRepository
	mu            sync.RWMutex
}

// NewACLManager creates a new ACL manager with the given database.
func NewACLManager(database *db.Database) *ACLManager {
	return &ACLManager{
		blacklistRepo: db.NewBlacklistRepository(database),
		whitelistRepo: db.NewWhitelistRepository(database),
		settingsRepo:  db.NewACLSettingsRepository(database),
	}
}

// IsBlacklisted checks if a player is blacklisted for a specific server.
// It checks both global blacklist (serverID="") and server-specific blacklist.
// Returns true and the blacklist entry if the player is blacklisted and the entry has not expired.
func (m *ACLManager) IsBlacklisted(playerName, serverID string) (bool, *db.BlacklistEntry) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check global blacklist first
	entry, err := m.blacklistRepo.GetByName(playerName, "")
	if err == nil && entry != nil && !entry.IsExpired() {
		return true, entry
	}

	// Check server-specific blacklist if serverID is provided
	if serverID != "" {
		entry, err = m.blacklistRepo.GetByName(playerName, serverID)
		if err == nil && entry != nil && !entry.IsExpired() {
			return true, entry
		}
	}

	return false, nil
}

// IsWhitelisted checks if a player is whitelisted for a specific server.
// It checks both global whitelist (serverID="") and server-specific whitelist.
func (m *ACLManager) IsWhitelisted(playerName, serverID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check global whitelist first
	entry, err := m.whitelistRepo.GetByName(playerName, "")
	if err == nil && entry != nil {
		return true
	}

	// Check server-specific whitelist if serverID is provided
	if serverID != "" {
		entry, err = m.whitelistRepo.GetByName(playerName, serverID)
		if err == nil && entry != nil {
			return true
		}
	}

	return false
}

// CheckAccess checks if a player is allowed to access a specific server.
// It implements the access control priority logic:
// 1. Check global blacklist - if found and not expired: DENY
// 2. Check server-specific blacklist - if found and not expired: DENY
// 3. Get ACL settings - if whitelist not enabled: ALLOW
// 4. Check global whitelist - if found: ALLOW
// 5. Check server-specific whitelist - if found: ALLOW
// 6. DENY with whitelist message
//
// This method implements fail-open behavior: if database errors occur,
// access is allowed (Requirement 5.4).
func (m *ACLManager) CheckAccess(playerName, serverID string) (allowed bool, reason string) {
	allowed, reason, _ = m.CheckAccessWithError(playerName, serverID)
	return allowed, reason
}

// CheckAccessWithError checks if a player is allowed to access a specific server.
// It returns any database errors encountered for logging purposes.
// This method implements fail-open behavior: if database errors occur,
// access is allowed and the error is returned for logging (Requirement 5.4).
func (m *ACLManager) CheckAccessWithError(playerName, serverID string) (allowed bool, reason string, dbErr error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error

	// Step 1: Check global blacklist
	entry, err := m.blacklistRepo.GetByName(playerName, "")
	if err != nil && err != ErrNotFound {
		lastErr = err
	}
	if err == nil && entry != nil {
		if !entry.IsExpired() {
			reason := entry.Reason
			if reason == "" {
				settings, _ := m.settingsRepo.Get("")
				if settings != nil {
					reason = settings.DefaultMessage
				} else {
					reason = "You are banned from this server"
				}
			}
			return false, reason, nil
		}
	}

	// Step 2: Check server-specific blacklist
	if serverID != "" {
		entry, err = m.blacklistRepo.GetByName(playerName, serverID)
		if err != nil && err != ErrNotFound {
			lastErr = err
		}
		if err == nil && entry != nil {
			if !entry.IsExpired() {
				reason := entry.Reason
				if reason == "" {
					settings, _ := m.settingsRepo.Get(serverID)
					if settings != nil {
						reason = settings.DefaultMessage
					} else {
						reason = "You are banned from this server"
					}
				}
				return false, reason, nil
			}
		}
	}

	// Step 3: Get ACL settings for server
	settings, err := m.settingsRepo.Get(serverID)
	if err != nil && err != ErrNotFound {
		lastErr = err
	}
	if err != nil || settings == nil {
		settings = db.DefaultACLSettings()
	}

	// If whitelist is not enabled, allow access
	if !settings.WhitelistEnabled {
		return true, "", lastErr
	}

	// Step 4: Check global whitelist
	whitelistEntry, err := m.whitelistRepo.GetByName(playerName, "")
	if err != nil && err != ErrNotFound {
		lastErr = err
	}
	if err == nil && whitelistEntry != nil {
		return true, "", nil
	}

	// Step 5: Check server-specific whitelist
	if serverID != "" {
		whitelistEntry, err = m.whitelistRepo.GetByName(playerName, serverID)
		if err != nil && err != ErrNotFound {
			lastErr = err
		}
		if err == nil && whitelistEntry != nil {
			return true, "", nil
		}
	}

	// Step 6: Deny with whitelist message
	return false, settings.WhitelistMessage, lastErr
}

// GetSettings retrieves ACL settings for a specific server.
func (m *ACLManager) GetSettings(serverID string) (*db.ACLSettings, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settingsRepo.Get(serverID)
}

// UpdateSettings updates ACL settings for a server.
func (m *ACLManager) UpdateSettings(settings *db.ACLSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settingsRepo.Update(settings)
}

// AddToBlacklist adds a player to the blacklist.
func (m *ACLManager) AddToBlacklist(entry *db.BlacklistEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Normalize the display name for case-insensitive storage
	entry.DisplayName = strings.TrimSpace(entry.DisplayName)
	if entry.AddedAt.IsZero() {
		entry.AddedAt = time.Now()
	}

	return m.blacklistRepo.Create(entry)
}

// RemoveFromBlacklist removes a player from the blacklist.
func (m *ACLManager) RemoveFromBlacklist(displayName, serverID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blacklistRepo.Delete(displayName, serverID)
}

// GetBlacklist retrieves all blacklist entries for a specific server.
func (m *ACLManager) GetBlacklist(serverID string) ([]*db.BlacklistEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blacklistRepo.List(serverID)
}

// GetAllBlacklist retrieves all blacklist entries from all servers.
func (m *ACLManager) GetAllBlacklist() ([]*db.BlacklistEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blacklistRepo.ListAll()
}

// AddToWhitelist adds a player to the whitelist.
func (m *ACLManager) AddToWhitelist(entry *db.WhitelistEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Normalize the display name for case-insensitive storage
	entry.DisplayName = strings.TrimSpace(entry.DisplayName)
	if entry.AddedAt.IsZero() {
		entry.AddedAt = time.Now()
	}

	return m.whitelistRepo.Create(entry)
}

// RemoveFromWhitelist removes a player from the whitelist.
func (m *ACLManager) RemoveFromWhitelist(displayName, serverID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.whitelistRepo.Delete(displayName, serverID)
}

// GetWhitelist retrieves all whitelist entries for a specific server.
func (m *ACLManager) GetWhitelist(serverID string) ([]*db.WhitelistEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.whitelistRepo.List(serverID)
}

// GetAllWhitelist retrieves all whitelist entries from all servers.
func (m *ACLManager) GetAllWhitelist() ([]*db.WhitelistEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.whitelistRepo.ListAll()
}

// DeleteExpiredBlacklistEntries removes all expired blacklist entries.
func (m *ACLManager) DeleteExpiredBlacklistEntries() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blacklistRepo.DeleteExpired()
}

// IsBlacklistedByEntry checks if a player name matches a blacklist entry (case-insensitive).
func IsBlacklistedByEntry(playerName string, entry *db.BlacklistEntry) bool {
	if entry == nil {
		return false
	}
	if entry.IsExpired() {
		return false
	}
	return strings.EqualFold(playerName, entry.DisplayName)
}

// IsWhitelistedByEntry checks if a player name matches a whitelist entry (case-insensitive).
func IsWhitelistedByEntry(playerName string, entry *db.WhitelistEntry) bool {
	if entry == nil {
		return false
	}
	return strings.EqualFold(playerName, entry.DisplayName)
}

// CheckAccessWithEntries checks access using provided entries (for testing purposes).
// This is a pure function that doesn't require database access.
func CheckAccessWithEntries(
	playerName string,
	serverID string,
	globalBlacklist []*db.BlacklistEntry,
	serverBlacklist []*db.BlacklistEntry,
	globalWhitelist []*db.WhitelistEntry,
	serverWhitelist []*db.WhitelistEntry,
	settings *db.ACLSettings,
) (allowed bool, reason string) {
	// Step 1: Check global blacklist
	for _, entry := range globalBlacklist {
		if IsBlacklistedByEntry(playerName, entry) {
			reason := entry.Reason
			if reason == "" {
				reason = "You are banned from this server"
			}
			return false, reason
		}
	}

	// Step 2: Check server-specific blacklist
	for _, entry := range serverBlacklist {
		if IsBlacklistedByEntry(playerName, entry) {
			reason := entry.Reason
			if reason == "" {
				reason = "You are banned from this server"
			}
			return false, reason
		}
	}

	// Step 3: Check if whitelist is enabled
	if settings == nil || !settings.WhitelistEnabled {
		return true, ""
	}

	// Step 4: Check global whitelist
	for _, entry := range globalWhitelist {
		if IsWhitelistedByEntry(playerName, entry) {
			return true, ""
		}
	}

	// Step 5: Check server-specific whitelist
	for _, entry := range serverWhitelist {
		if IsWhitelistedByEntry(playerName, entry) {
			return true, ""
		}
	}

	// Step 6: Deny with whitelist message
	whitelistMsg := settings.WhitelistMessage
	if whitelistMsg == "" {
		whitelistMsg = "You are not whitelisted on this server"
	}
	return false, whitelistMsg
}

// FindBlacklistEntry finds a blacklist entry for a player name (case-insensitive).
func FindBlacklistEntry(playerName string, entries []*db.BlacklistEntry) *db.BlacklistEntry {
	for _, entry := range entries {
		if strings.EqualFold(playerName, entry.DisplayName) && !entry.IsExpired() {
			return entry
		}
	}
	return nil
}

// FindWhitelistEntry finds a whitelist entry for a player name (case-insensitive).
func FindWhitelistEntry(playerName string, entries []*db.WhitelistEntry) *db.WhitelistEntry {
	for _, entry := range entries {
		if strings.EqualFold(playerName, entry.DisplayName) {
			return entry
		}
	}
	return nil
}

// Ensure ACLManager implements the interface at compile time
var _ ACLManagerInterface = (*ACLManager)(nil)

// ACLManagerInterface defines the interface for ACL management.
type ACLManagerInterface interface {
	CheckAccess(playerName, serverID string) (allowed bool, reason string)
	CheckAccessWithError(playerName, serverID string) (allowed bool, reason string, dbErr error)
	IsBlacklisted(playerName, serverID string) (bool, *db.BlacklistEntry)
	IsWhitelisted(playerName, serverID string) bool
	GetSettings(serverID string) (*db.ACLSettings, error)
	UpdateSettings(settings *db.ACLSettings) error
	AddToBlacklist(entry *db.BlacklistEntry) error
	RemoveFromBlacklist(displayName, serverID string) error
	GetBlacklist(serverID string) ([]*db.BlacklistEntry, error)
	GetAllBlacklist() ([]*db.BlacklistEntry, error)
	AddToWhitelist(entry *db.WhitelistEntry) error
	RemoveFromWhitelist(displayName, serverID string) error
	GetWhitelist(serverID string) ([]*db.WhitelistEntry, error)
	GetAllWhitelist() ([]*db.WhitelistEntry, error)
}

// Ensure sql.ErrNoRows is available for error checking
var ErrNotFound = sql.ErrNoRows
