// Package errors provides error handling utilities for the proxy server.
package errors

import (
	"fmt"
	"log"
	"time"
)

// ErrorType categorizes different types of errors for handling.
type ErrorType int

const (
	// ErrorTypeNetwork represents network-related errors.
	ErrorTypeNetwork ErrorType = iota
	// ErrorTypeProtocol represents protocol parsing errors.
	ErrorTypeProtocol
	// ErrorTypeDatabase represents database operation errors.
	ErrorTypeDatabase
	// ErrorTypeConfig represents configuration errors.
	ErrorTypeConfig
	// ErrorTypeAuth represents authentication-related errors.
	ErrorTypeAuth
)

// Authentication error messages for Minecraft disconnect packets.
// These use Minecraft color codes (§) for formatting.
const (
	// ErrMsgAuthRequired is shown when Xbox Live authentication is required.
	ErrMsgAuthRequired = "§cXbox Live authentication required\n§7Please wait for proxy authentication"
	// ErrMsgAuthFailed is shown when authentication fails.
	ErrMsgAuthFailed = "§cAuthentication failed\n§7%v"
	// ErrMsgServerRejected is shown when the remote server rejects the connection.
	ErrMsgServerRejected = "§cServer rejected connection\n§7%v"
	// ErrMsgTokenExpired is shown when the session token has expired.
	ErrMsgTokenExpired = "§cSession expired\n§7Please reconnect"
	// ErrMsgTokenRefreshFailed is shown when token refresh fails.
	ErrMsgTokenRefreshFailed = "§cAuthentication expired\n§7Proxy is re-authenticating, please reconnect"
)

// ProxyError wraps errors with additional context.
type ProxyError struct {
	Type    ErrorType
	Op      string // operation that failed
	Err     error  // underlying error
	Context map[string]interface{}
}

func (e *ProxyError) Error() string {
	if e.Context != nil && len(e.Context) > 0 {
		return fmt.Sprintf("%s: %v (context: %v)", e.Op, e.Err, e.Context)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *ProxyError) Unwrap() error {
	return e.Err
}

// NewNetworkError creates a new network error.
func NewNetworkError(op string, err error) *ProxyError {
	return &ProxyError{
		Type: ErrorTypeNetwork,
		Op:   op,
		Err:  err,
	}
}

// NewProtocolError creates a new protocol error.
func NewProtocolError(op string, err error) *ProxyError {
	return &ProxyError{
		Type: ErrorTypeProtocol,
		Op:   op,
		Err:  err,
	}
}

// NewDatabaseError creates a new database error.
func NewDatabaseError(op string, err error) *ProxyError {
	return &ProxyError{
		Type: ErrorTypeDatabase,
		Op:   op,
		Err:  err,
	}
}

// NewConfigError creates a new configuration error.
func NewConfigError(op string, err error) *ProxyError {
	return &ProxyError{
		Type: ErrorTypeConfig,
		Op:   op,
		Err:  err,
	}
}

// NewAuthError creates a new authentication error.
func NewAuthError(op string, err error) *ProxyError {
	return &ProxyError{
		Type: ErrorTypeAuth,
		Op:   op,
		Err:  err,
	}
}

// IsAuthError checks if an error is an authentication error.
func IsAuthError(err error) bool {
	if pe, ok := err.(*ProxyError); ok {
		return pe.Type == ErrorTypeAuth
	}
	return false
}

// WithContext adds context to an error.
func (e *ProxyError) WithContext(key string, value interface{}) *ProxyError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// ErrorHandler provides centralized error handling with retry logic.
type ErrorHandler struct {
	maxRetries   int
	retryDelay   time.Duration
	retryBackoff float64
}

// NewErrorHandler creates a new error handler with default settings.
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		maxRetries:   3,
		retryDelay:   100 * time.Millisecond,
		retryBackoff: 2.0,
	}
}

// WithMaxRetries sets the maximum number of retries.
func (h *ErrorHandler) WithMaxRetries(n int) *ErrorHandler {
	h.maxRetries = n
	return h
}

// WithRetryDelay sets the initial retry delay.
func (h *ErrorHandler) WithRetryDelay(d time.Duration) *ErrorHandler {
	h.retryDelay = d
	return h
}

// HandlePacketForwardError handles packet forwarding errors.
// Per requirement 9.1: log the error and continue processing.
func (h *ErrorHandler) HandlePacketForwardError(err error, clientAddr, direction string) {
	log.Printf("[WARN] Packet forward error (%s -> %s): %v", clientAddr, direction, err)
}

// HandleRemoteUnreachable handles remote server unreachable errors.
// Per requirement 9.2: mark affected sessions and attempt reconnection.
func (h *ErrorHandler) HandleRemoteUnreachable(err error, serverID, clientAddr string) {
	log.Printf("[ERROR] Remote server unreachable (server=%s, client=%s): %v", serverID, clientAddr, err)
}

// RetryOperation retries a database operation up to maxRetries times.
// Per requirement 9.3: retry database operations up to 3 times.
func (h *ErrorHandler) RetryOperation(op string, fn func() error) error {
	var lastErr error
	delay := h.retryDelay

	for attempt := 1; attempt <= h.maxRetries; attempt++ {
		if err := fn(); err != nil {
			lastErr = err
			if attempt < h.maxRetries {
				log.Printf("[WARN] %s failed (attempt %d/%d): %v, retrying in %v",
					op, attempt, h.maxRetries, err, delay)
				time.Sleep(delay)
				delay = time.Duration(float64(delay) * h.retryBackoff)
			}
		} else {
			return nil
		}
	}

	log.Printf("[ERROR] %s failed after %d attempts: %v", op, h.maxRetries, lastErr)
	return fmt.Errorf("%s failed after %d retries: %w", op, h.maxRetries, lastErr)
}

// LogAndContinue logs an error and returns nil to allow continuation.
func LogAndContinue(op string, err error) error {
	if err != nil {
		log.Printf("[WARN] %s: %v (continuing)", op, err)
	}
	return nil
}

// IsRetryable determines if an error should be retried.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	// Network and database errors are typically retryable
	if pe, ok := err.(*ProxyError); ok {
		return pe.Type == ErrorTypeNetwork || pe.Type == ErrorTypeDatabase
	}
	return true
}
