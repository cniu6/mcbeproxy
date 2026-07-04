package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func configureTestLoggerDir(t *testing.T, dir string) func() {
	t.Helper()
	origConfig := defaultLogger.getConfig()
	defaultLogger.mu.Lock()
	defaultLogger.config = &LogConfig{
		LogDir:           dir,
		RetentionDays:    7,
		MaxSizeMB:        100,
		EnableFileLog:    true,
		EnableConsoleLog: false,
	}
	defaultLogger.mu.Unlock()
	return func() {
		defaultLogger.mu.Lock()
		defaultLogger.config = origConfig
		defaultLogger.mu.Unlock()
	}
}

func TestCapturePanic_NoPanic(t *testing.T) {
	CapturePanic("test-no-panic")
}

func TestCapturePanic_WithPanic(t *testing.T) {
	tmpDir := t.TempDir()
	restore := configureTestLoggerDir(t, tmpDir)
	defer restore()

	func() {
		defer CapturePanic("test-context")
		panic("test panic value")
	}()

	time.Sleep(50 * time.Millisecond)

	content := readFirstCrashFile(t, tmpDir)
	if !strings.Contains(content, "test panic value") {
		t.Fatalf("crash report missing panic value: %s", content)
	}
	if !strings.Contains(content, "test-context") {
		t.Fatalf("crash report missing context: %s", content)
	}
	if !strings.Contains(content, "recovered_panic") {
		t.Fatalf("crash report missing kind: %s", content)
	}
	if !strings.Contains(content, "Reason:") {
		t.Fatalf("crash report missing reason: %s", content)
	}
}

func TestCapturePanicExit_ReasonWritten(t *testing.T) {
	tmpDir := t.TempDir()
	restore := configureTestLoggerDir(t, tmpDir)
	defer restore()

	handleRecoveredPanic("exit-context", "exit panic", true)
	time.Sleep(50 * time.Millisecond)

	content := readFirstCrashFile(t, tmpDir)
	if !strings.Contains(content, "exit panic") {
		t.Fatalf("expected exit panic in report, got: %s", content)
	}
	if !strings.Contains(content, "ExitAfterReport: true") {
		t.Fatalf("expected exit flag in report, got: %s", content)
	}
}

func TestSafeGo_WithPanic(t *testing.T) {
	tmpDir := t.TempDir()
	restore := configureTestLoggerDir(t, tmpDir)
	defer restore()

	SafeGo("safe-go-test", func() {
		panic("safe-go panic")
	})

	time.Sleep(100 * time.Millisecond)
	content := readFirstCrashFile(t, tmpDir)
	if !strings.Contains(content, "safe-go panic") {
		t.Fatalf("expected safe-go panic in report, got: %s", content)
	}
}

func TestReportAPIPanic(t *testing.T) {
	tmpDir := t.TempDir()
	restore := configureTestLoggerDir(t, tmpDir)
	defer restore()

	ReportAPIPanic("GET /api/test", "boom")
	time.Sleep(50 * time.Millisecond)

	content := readFirstCrashFile(t, tmpDir)
	if !strings.Contains(content, "api_panic") {
		t.Fatalf("expected api_panic kind, got: %s", content)
	}
	if !strings.Contains(content, "boom") {
		t.Fatalf("expected panic detail, got: %s", content)
	}
}

func readFirstCrashFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".txt") && (strings.HasPrefix(name, "recovered_panic_") || strings.HasPrefix(name, "api_panic_") || name == "crash_latest.txt") {
			content, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read crash file: %v", err)
			}
			return string(content)
		}
	}
	t.Fatalf("no crash report file found in %s", dir)
	return ""
}
