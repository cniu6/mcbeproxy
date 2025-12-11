// Package auth provides Xbox Live authentication functionality for the proxy.
package auth

import (
	"context"
	"fmt"
	"sync"

	"mcpeserverproxy/internal/logger"

	"github.com/sandertv/gophertunnel/minecraft/auth"
	"golang.org/x/oauth2"
)

// XboxAuthManager handles Xbox Live authentication using device auth flow.
// It manages token acquisition, caching, and provides a TokenSource for use
// with gophertunnel's minecraft.Dialer.
type XboxAuthManager struct {
	tokenPath   string             // Path to token cache file
	tokenSource oauth2.TokenSource // OAuth2 token source for authentication
	tokenCache  *TokenCache        // Token cache for persistence
	mu          sync.RWMutex       // Protects tokenSource
}

// NewXboxAuthManager creates a new auth manager with the specified token cache path.
// The tokenPath specifies where authentication tokens will be persisted.
func NewXboxAuthManager(tokenPath string) *XboxAuthManager {
	return &XboxAuthManager{
		tokenPath:  tokenPath,
		tokenCache: NewTokenCache(tokenPath),
	}
}

// GetTokenSource returns the OAuth2 token source for use with gophertunnel.
// Returns nil if not authenticated. The returned TokenSource can be used
// with minecraft.Dialer to connect to servers requiring Xbox Live authentication.
func (m *XboxAuthManager) GetTokenSource() oauth2.TokenSource {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokenSource
}

// IsAuthenticated returns whether valid tokens are available.
// Returns true if the manager has a valid token source that can be used
// for authentication.
func (m *XboxAuthManager) IsAuthenticated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tokenSource != nil
}

// setTokenSource sets the token source (thread-safe).
func (m *XboxAuthManager) setTokenSource(ts oauth2.TokenSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenSource = ts
}

// Authenticate initiates the authentication process.
// It first checks for cached tokens and uses them if valid.
// If no valid cached tokens exist, it initiates the device auth flow.
// Returns an error if authentication fails.
func (m *XboxAuthManager) Authenticate(ctx context.Context) error {
	// First, try to load cached tokens
	if err := m.loadCachedTokens(ctx); err == nil {
		// Requirement 6.2: Log success when using cached tokens
		logger.Info("Xbox Live authentication successful")
		logger.Info("Xbox Live authentication: using cached tokens")
		return nil // Successfully loaded cached tokens
	}

	// No valid cached tokens, initiate device auth flow
	logger.Info("Xbox Live authentication: initiating device auth flow")
	return m.initiateDeviceAuth(ctx)
}

// ReauthenticateOnFailure handles token refresh failure by clearing cache and re-authenticating.
// This implements Requirement 1.7: IF refresh token is invalid THEN initiate new device authentication flow.
// Requirements: 3.5, 6.4
func (m *XboxAuthManager) ReauthenticateOnFailure(ctx context.Context) error {
	// Requirement 6.4: Log warning when token refresh fails
	logger.Warn("Token refresh failed, clearing cache and initiating re-authentication")

	// Clear the invalid token source
	m.mu.Lock()
	m.tokenSource = nil
	m.mu.Unlock()

	// Clear the cached tokens
	if err := m.tokenCache.Clear(); err != nil {
		logger.Warn("Failed to clear token cache: %v", err)
	}

	// Initiate new device authentication
	return m.initiateDeviceAuth(ctx)
}

// ValidateAndRefreshToken checks if the current token is valid and refreshes if needed.
// Returns an error if the token cannot be refreshed.
// Requirements: 1.6, 3.5, 6.4
func (m *XboxAuthManager) ValidateAndRefreshToken(ctx context.Context) error {
	m.mu.RLock()
	ts := m.tokenSource
	m.mu.RUnlock()

	if ts == nil {
		return fmt.Errorf("no token source available")
	}

	// Try to get a token - this will trigger refresh if needed
	_, err := ts.Token()
	if err != nil {
		// Token refresh failed - need to re-authenticate
		// Requirement 6.4: Log warning when token refresh fails
		logger.Warn("Token validation/refresh failed: %v", err)
		return err
	}

	return nil
}

// loadCachedTokens attempts to load and validate cached tokens.
// Returns nil if valid tokens were loaded, error otherwise.
// Requirements: 1.4, 1.5, 1.6, 6.4
func (m *XboxAuthManager) loadCachedTokens(ctx context.Context) error {
	cachedToken, err := m.tokenCache.Load()
	if err != nil {
		logger.Debug("Failed to load cached tokens: %v", err)
		return fmt.Errorf("failed to load cached tokens: %w", err)
	}

	// Check if the cached token has a refresh token (required for refresh)
	if cachedToken.RefreshToken == "" {
		logger.Debug("Cached token has no refresh token")
		return fmt.Errorf("cached token has no refresh token")
	}

	// Create a token source from the cached token using gophertunnel's auth package.
	// We use RefreshTokenSource which will automatically refresh the token when needed.
	token := &oauth2.Token{
		AccessToken:  cachedToken.AccessToken,
		RefreshToken: cachedToken.RefreshToken,
		Expiry:       cachedToken.ExpiresAt,
	}

	// Create a refreshable token source that will auto-refresh when token expires
	// gophertunnel's RefreshTokenSource handles automatic token refresh
	tokenSource := auth.RefreshTokenSource(token)

	// Verify the token source works by getting a token
	// This will trigger a refresh if the token is expired
	refreshedToken, err := tokenSource.Token()
	if err != nil {
		// Token refresh failed - clear cache and return error
		// This will trigger new device auth (Requirement 1.7)
		// Requirement 6.4: Log warning when token refresh fails
		logger.Warn("Token refresh failed: %v", err)
		logger.Warn("Clearing token cache and initiating re-authentication")
		m.tokenCache.Clear()
		return fmt.Errorf("token refresh failed: %w", err)
	}

	// Update cache with refreshed token if it changed
	if refreshedToken.AccessToken != cachedToken.AccessToken {
		logger.Debug("Token was refreshed, updating cache")
		if err := m.saveTokenToCache(refreshedToken); err != nil {
			logger.Warn("Failed to update token cache: %v", err)
		}
	}

	m.setTokenSource(tokenSource)
	return nil
}

// initiateDeviceAuth starts the device authorization flow using gophertunnel's auth package.
// It displays the verification URL and user code for the administrator to complete authentication.
// Requirements: 1.1, 1.2, 1.3, 6.1, 6.2, 6.3
func (m *XboxAuthManager) initiateDeviceAuth(ctx context.Context) error {
	// Requirement 6.1: Output verification URL and user code prominently
	logger.Info("=================================================")
	logger.Info("Xbox Live Device Authentication Required")
	logger.Info("-------------------------------------------------")
	logger.Info("Please visit: https://www.microsoft.com/link")
	logger.Info("The user code will be displayed by the authentication library")
	logger.Info("-------------------------------------------------")

	// Use gophertunnel's RequestLiveTokenWriter to get the token with device auth flow.
	// This will print the verification URL and user code to stdout.
	token, err := auth.RequestLiveToken()
	if err != nil {
		// Requirement 6.3: Log specific error with context when authentication fails
		logger.Error("Xbox Live authentication failed: %v", err)
		logger.Error("Please check your network connection and try again")
		return fmt.Errorf("device authentication failed: %w", err)
	}

	// Requirement 6.2: Log success message
	logger.Info("-------------------------------------------------")
	logger.Info("Xbox Live authentication successful")
	logger.Info("=================================================")

	// Create a refreshable token source
	tokenSource := auth.RefreshTokenSource(token)
	m.setTokenSource(tokenSource)

	// Save the token to cache for future use
	if err := m.saveTokenToCache(token); err != nil {
		logger.Warn("Failed to cache authentication token: %v", err)
		// Don't return error - authentication succeeded, caching is optional
	}

	return nil
}

// saveTokenToCache persists the OAuth2 token to the cache file.
func (m *XboxAuthManager) saveTokenToCache(token *oauth2.Token) error {
	cachedToken := &CachedToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
		UserHash:     "", // UserHash is not available from oauth2.Token
	}

	return m.tokenCache.Save(cachedToken)
}

// Logout clears cached tokens and resets the authentication state.
func (m *XboxAuthManager) Logout() error {
	m.mu.Lock()
	m.tokenSource = nil
	m.mu.Unlock()

	return m.tokenCache.Clear()
}

// GetTokenPath returns the path to the token cache file.
func (m *XboxAuthManager) GetTokenPath() string {
	return m.tokenPath
}
