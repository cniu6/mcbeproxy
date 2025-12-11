// Package auth provides Xbox Live authentication functionality for the proxy.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CachedToken represents the serialized token data for persistence.
type CachedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserHash     string    `json:"user_hash"`
}

// TokenCache handles token persistence to and from a file.
type TokenCache struct {
	path string
}

// NewTokenCache creates a new TokenCache with the specified file path.
func NewTokenCache(path string) *TokenCache {
	return &TokenCache{
		path: path,
	}
}

// Save persists the token to the cache file as JSON.
// Returns an error if serialization or file writing fails.
func (c *TokenCache) Save(token *CachedToken) error {
	if token == nil {
		return fmt.Errorf("cannot save nil token")
	}

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	// Write with restricted permissions (owner read/write only)
	if err := os.WriteFile(c.path, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// Load retrieves the token from the cache file.
// Returns an error if the file doesn't exist, can't be read, or contains invalid JSON.
func (c *TokenCache) Load() (*CachedToken, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("token file not found: %w", err)
		}
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token CachedToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token file: %w", err)
	}

	return &token, nil
}

// Clear removes the token cache file.
// Returns nil if the file doesn't exist (idempotent operation).
func (c *TokenCache) Clear() error {
	err := os.Remove(c.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove token file: %w", err)
	}
	return nil
}

// GetPath returns the path to the token cache file.
func (c *TokenCache) GetPath() string {
	return c.path
}

// ExpirationBuffer is the time before actual expiration when a token is considered expired.
// This provides a safety margin to ensure tokens are refreshed before they actually expire.
const ExpirationBuffer = 5 * time.Minute

// IsValid checks if the token is still valid (not expired).
// A token is considered invalid if it expires within the next 5 minutes (ExpirationBuffer).
func (t *CachedToken) IsValid() bool {
	if t == nil {
		return false
	}
	// Token is valid if ExpiresAt is after (now + buffer)
	return time.Now().Add(ExpirationBuffer).Before(t.ExpiresAt)
}
