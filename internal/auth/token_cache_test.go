package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// **Feature: xbox-live-auth-proxy, Property 1: Token Cache Round-Trip**
// **Validates: Requirements 4.1, 4.4**
//
// *For any* valid CachedToken object, serializing to JSON and deserializing back
// SHALL produce an equivalent CachedToken object with identical field values.
func TestProperty1_TokenCacheRoundTrip(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generator for non-empty strings (tokens should not be empty)
	nonEmptyString := gen.AnyString().SuchThat(func(s string) bool {
		return len(s) > 0
	})

	// Generator for time values (within reasonable range)
	timeGen := gen.Int64Range(0, 2000000000).Map(func(ts int64) time.Time {
		return time.Unix(ts, 0).UTC()
	})

	// Property: Save then Load produces equivalent token
	properties.Property("save then load produces equivalent token", prop.ForAll(
		func(accessToken, refreshToken, userHash string, expiresAt time.Time) bool {
			// Create a unique file path for this test iteration
			tokenPath := filepath.Join(tempDir, "test_token.json")
			cache := NewTokenCache(tokenPath)

			// Create original token
			original := &CachedToken{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ExpiresAt:    expiresAt,
				UserHash:     userHash,
			}

			// Save the token
			if err := cache.Save(original); err != nil {
				t.Logf("Save failed: %v", err)
				return false
			}

			// Load the token back
			loaded, err := cache.Load()
			if err != nil {
				t.Logf("Load failed: %v", err)
				return false
			}

			// Verify all fields match
			if loaded.AccessToken != original.AccessToken {
				t.Logf("AccessToken mismatch: got %q, want %q", loaded.AccessToken, original.AccessToken)
				return false
			}
			if loaded.RefreshToken != original.RefreshToken {
				t.Logf("RefreshToken mismatch: got %q, want %q", loaded.RefreshToken, original.RefreshToken)
				return false
			}
			if loaded.UserHash != original.UserHash {
				t.Logf("UserHash mismatch: got %q, want %q", loaded.UserHash, original.UserHash)
				return false
			}
			// Compare times with second precision (JSON doesn't preserve nanoseconds)
			if !loaded.ExpiresAt.Equal(original.ExpiresAt) {
				t.Logf("ExpiresAt mismatch: got %v, want %v", loaded.ExpiresAt, original.ExpiresAt)
				return false
			}

			// Clean up for next iteration
			cache.Clear()

			return true
		},
		nonEmptyString, // accessToken
		nonEmptyString, // refreshToken
		nonEmptyString, // userHash
		timeGen,        // expiresAt
	))

	properties.TestingRun(t)
}

// TestTokenCache_Clear tests the Clear method
func TestTokenCache_Clear(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tokenPath := filepath.Join(tempDir, "test_token.json")
	cache := NewTokenCache(tokenPath)

	// Save a token first
	token := &CachedToken{
		AccessToken:  "test_access",
		RefreshToken: "test_refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		UserHash:     "test_hash",
	}
	if err := cache.Save(token); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		t.Fatal("Token file should exist after save")
	}

	// Clear the cache
	if err := cache.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Verify file is removed
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("Token file should not exist after clear")
	}

	// Clear again should not error (idempotent)
	if err := cache.Clear(); err != nil {
		t.Fatalf("Second clear should not error: %v", err)
	}
}

// TestTokenCache_LoadNonExistent tests loading from a non-existent file
func TestTokenCache_LoadNonExistent(t *testing.T) {
	cache := NewTokenCache("/nonexistent/path/token.json")

	_, err := cache.Load()
	if err == nil {
		t.Fatal("Load should fail for non-existent file")
	}
}

// TestTokenCache_SaveNilToken tests saving a nil token
func TestTokenCache_SaveNilToken(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "token_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tokenPath := filepath.Join(tempDir, "test_token.json")
	cache := NewTokenCache(tokenPath)

	err = cache.Save(nil)
	if err == nil {
		t.Fatal("Save should fail for nil token")
	}
}

// TestTokenCache_GetPath tests the GetPath method
func TestTokenCache_GetPath(t *testing.T) {
	expectedPath := "/some/path/token.json"
	cache := NewTokenCache(expectedPath)

	if cache.GetPath() != expectedPath {
		t.Errorf("GetPath() = %q, want %q", cache.GetPath(), expectedPath)
	}
}

// **Feature: xbox-live-auth-proxy, Property 2: Token Expiration Detection**
// **Validates: Requirements 4.5**
//
// *For any* CachedToken with ExpiresAt in the past, the Token Manager SHALL detect
// it as expired and return false for IsValid().
func TestProperty2_TokenExpirationDetection(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	properties := gopter.NewProperties(parameters)

	// Generator for non-empty strings
	nonEmptyString := gen.AnyString().SuchThat(func(s string) bool {
		return len(s) > 0
	})

	// Property: Tokens with ExpiresAt in the past are detected as expired
	properties.Property("expired tokens are detected as invalid", prop.ForAll(
		func(accessToken, refreshToken, userHash string, secondsInPast int64) bool {
			// Create a token that expired some time in the past
			expiresAt := time.Now().Add(-time.Duration(secondsInPast) * time.Second)

			token := &CachedToken{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ExpiresAt:    expiresAt,
				UserHash:     userHash,
			}

			// Token should be invalid (expired)
			return !token.IsValid()
		},
		nonEmptyString,              // accessToken
		nonEmptyString,              // refreshToken
		nonEmptyString,              // userHash
		gen.Int64Range(1, 86400*30), // secondsInPast (1 second to 30 days in the past)
	))

	// Property: Tokens expiring within the buffer period are detected as invalid
	properties.Property("tokens expiring within buffer are invalid", prop.ForAll(
		func(accessToken, refreshToken, userHash string, secondsUntilExpiry int64) bool {
			// Create a token that expires within the 5-minute buffer
			expiresAt := time.Now().Add(time.Duration(secondsUntilExpiry) * time.Second)

			token := &CachedToken{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ExpiresAt:    expiresAt,
				UserHash:     userHash,
			}

			// Token should be invalid (within buffer period)
			return !token.IsValid()
		},
		nonEmptyString,            // accessToken
		nonEmptyString,            // refreshToken
		nonEmptyString,            // userHash
		gen.Int64Range(0, 5*60-1), // secondsUntilExpiry (0 to just under 5 minutes)
	))

	// Property: Tokens expiring after the buffer period are valid
	properties.Property("tokens expiring after buffer are valid", prop.ForAll(
		func(accessToken, refreshToken, userHash string, secondsAfterBuffer int64) bool {
			// Create a token that expires well after the 5-minute buffer
			// Add buffer (5 min) + additional time
			expiresAt := time.Now().Add(ExpirationBuffer + time.Duration(secondsAfterBuffer)*time.Second + time.Second)

			token := &CachedToken{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				ExpiresAt:    expiresAt,
				UserHash:     userHash,
			}

			// Token should be valid
			return token.IsValid()
		},
		nonEmptyString,               // accessToken
		nonEmptyString,               // refreshToken
		nonEmptyString,               // userHash
		gen.Int64Range(1, 86400*365), // secondsAfterBuffer (1 second to 1 year after buffer)
	))

	properties.TestingRun(t)
}

// TestCachedToken_IsValid_NilToken tests that nil tokens are invalid
func TestCachedToken_IsValid_NilToken(t *testing.T) {
	var token *CachedToken = nil
	if token.IsValid() {
		t.Error("nil token should be invalid")
	}
}
