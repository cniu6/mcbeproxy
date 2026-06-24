package errors

import (
	"errors"
	"testing"
	"time"
)

func TestRetryOperationSucceedsOnFirstAttempt(t *testing.T) {
	h := NewErrorHandler()
	calls := 0
	err := h.RetryOperation("test-op", func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRetryOperationRetriesAndSucceeds(t *testing.T) {
	h := NewErrorHandler().WithRetryDelay(1 * time.Millisecond)
	calls := 0
	err := h.RetryOperation("test-op", func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetryOperationFailsAfterMaxRetries(t *testing.T) {
	h := NewErrorHandler().WithRetryDelay(1 * time.Millisecond)
	calls := 0
	err := h.RetryOperation("test-op", func() error {
		calls++
		return errors.New("permanent")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls != h.maxRetries {
		t.Fatalf("expected %d calls, got %d", h.maxRetries, calls)
	}
}

func TestLogAndContinueReturnsNil(t *testing.T) {
	err := LogAndContinue("test-op", errors.New("some error"))
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestLogAndContinueWithNilError(t *testing.T) {
	err := LogAndContinue("test-op", nil)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestHandlePacketForwardErrorDoesNotPanic(t *testing.T) {
	h := NewErrorHandler()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	h.HandlePacketForwardError(errors.New("test"), "client", "remote")
}

func TestHandleRemoteUnreachableDoesNotPanic(t *testing.T) {
	h := NewErrorHandler()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	h.HandleRemoteUnreachable(errors.New("test"), "server-1", "client-1")
}

func TestIsRetryable(t *testing.T) {
	if IsRetryable(nil) {
		t.Fatal("nil error should not be retryable")
	}
	if !IsRetryable(errors.New("network")) {
		t.Fatal("generic error should be retryable")
	}
	networkErr := &ProxyError{Type: ErrorTypeNetwork}
	if !IsRetryable(networkErr) {
		t.Fatal("network error should be retryable")
	}
}

func TestWithRetryDelay(t *testing.T) {
	h := NewErrorHandler().WithRetryDelay(50 * time.Millisecond)
	if h.retryDelay != 50*time.Millisecond {
		t.Fatalf("expected 50ms, got %v", h.retryDelay)
	}
}

func TestWithMaxRetries(t *testing.T) {
	h := NewErrorHandler().WithMaxRetries(5)
	if h.maxRetries != 5 {
		t.Fatalf("expected 5, got %d", h.maxRetries)
	}
}
