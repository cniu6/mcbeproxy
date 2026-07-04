package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// CapturePanic recovers from a panic, logs it with a full goroutine stack dump,
// and writes a standalone panic log file for post-mortem analysis.
// It should be called as `defer logger.CapturePanic("context")` in any goroutine
// or function where panics should not crash the process.
//
// If no panic occurred, this is a no-op.
func CapturePanic(context string) {
	r := recover()
	if r == nil {
		return
	}

	// Grab full goroutine dump (all goroutines, not just this one)
	stackBuf := make([]byte, 1024*1024) // 1MB
	n := runtime.Stack(stackBuf, true)
	stack := string(stackBuf[:n])

	msg := fmt.Sprintf("PANIC recovered in %s: %v\n%s", context, r, stack)
	Error("%s", msg)

	// Write standalone panic log file for easy retrieval
	writePanicFile(context, r, stack)
}

// writePanicFile writes a panic report to a dated file in the log directory.
// The file is named panic_YYYY-MM-DD_HHMMSS.txt so multiple panics don't overwrite.
func writePanicFile(context string, r any, stack string) {
	logDir := ""
	if cfg := defaultLogger.getConfig(); cfg != nil && cfg.LogDir != "" {
		logDir = cfg.LogDir
	}

	fileName := fmt.Sprintf("panic_%s.txt", time.Now().Format("2006-01-02_150405"))
	path := filepath.Join(logDir, fileName)

	content := fmt.Sprintf(
		"Time: %s\nVersion: %s (build %s, commit %s)\nContext: %s\nPanic: %v\n\n=== Goroutine Stack Dump ===\n%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		Version, BuildTime, GitCommit,
		context, r, stack,
	)

	// If logDir is empty or write fails, still try cwd as fallback
	if err := os.WriteFile(path, []byte(content), 0644); err != nil && logDir != "" {
		// Fallback: write to current directory
		fallback := fileName
		_ = os.WriteFile(fallback, []byte(content), 0644)
	}
}

// SafeGo launches a goroutine with automatic panic capture and logging.
// Usage: logger.SafeGo("forwardResponses", func() { ... })
// Any panic in the goroutine will be recovered, logged, and written to a panic file.
func SafeGo(context string, fn func()) {
	go func() {
		defer CapturePanic(context)
		fn()
	}()
}

// (getConfig is a small helper to safely read the logger config under lock.)
func (l *Logger) getConfig() *LogConfig {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config
}
