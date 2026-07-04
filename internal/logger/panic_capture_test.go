package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCapturePanic_NoPanic(t *testing.T) {
	// Should be a no-op when no panic occurs
	CapturePanic("test-no-panic")
}

func TestCapturePanic_WithPanic(t *testing.T) {
	// Configure a temp log dir
	tmpDir := t.TempDir()
	origConfig := defaultLogger.getConfig()
	defer func() {
		defaultLogger.mu.Lock()
		defaultLogger.config = origConfig
		defaultLogger.mu.Unlock()
	}()

	defaultLogger.mu.Lock()
	defaultLogger.config = &LogConfig{
		LogDir:           tmpDir,
		RetentionDays:    7,
		MaxSizeMB:        100,
		EnableFileLog:    true,
		EnableConsoleLog: false,
	}
	defaultLogger.mu.Unlock()

	func() {
		defer CapturePanic("test-context")
		panic("test panic value")
	}()

	// Give file writes a moment to flush
	time.Sleep(50 * time.Millisecond)

	// Find the panic file
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read log dir: %v", err)
	}

	var panicFile string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "panic_") && strings.HasSuffix(e.Name(), ".txt") {
			panicFile = filepath.Join(tmpDir, e.Name())
			break
		}
	}
	if panicFile == "" {
		t.Fatal("expected a panic_*.txt file in log dir, found none")
	}

	content, err := os.ReadFile(panicFile)
	if err != nil {
		t.Fatalf("failed to read panic file: %v", err)
	}

	s := string(content)
	if !strings.Contains(s, "test panic value") {
		t.Errorf("panic file does not contain panic value: %s", s)
	}
	if !strings.Contains(s, "test-context") {
		t.Errorf("panic file does not contain context: %s", s)
	}
	if !strings.Contains(s, "Goroutine Stack Dump") {
		t.Errorf("panic file does not contain stack dump: %s", s)
	}
}

func TestSafeGo_WithPanic(t *testing.T) {
	tmpDir := t.TempDir()
	origConfig := defaultLogger.getConfig()
	defer func() {
		defaultLogger.mu.Lock()
		defaultLogger.config = origConfig
		defaultLogger.mu.Unlock()
	}()

	defaultLogger.mu.Lock()
	defaultLogger.config = &LogConfig{
		LogDir:           tmpDir,
		RetentionDays:    7,
		MaxSizeMB:        100,
		EnableFileLog:    true,
		EnableConsoleLog: false,
	}
	defaultLogger.mu.Unlock()

	done := make(chan struct{})
	SafeGo("safe-go-test", func() {
		panic("safe-go panic")
	})

	// Wait for goroutine to finish (it should not crash the process)
	time.Sleep(100 * time.Millisecond)

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("failed to read log dir: %v", err)
	}

	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "panic_") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a panic file from SafeGo, found none")
	}

	close(done)
}
