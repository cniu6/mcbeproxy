package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// CrashKind classifies how/why the process crashed or recovered.
type CrashKind string

const (
	CrashKindRecoveredPanic CrashKind = "recovered_panic"
	CrashKindFatalRuntime   CrashKind = "fatal_runtime"
	CrashKindSignal         CrashKind = "signal"
	CrashKindAPIPanic       CrashKind = "api_panic"
)

var (
	crashHandlerOnce             sync.Once
	crashOutputFile              *os.File
	crashReportFileOutputEnabled atomic.Bool
)

func SetCrashReportFileOutput(enabled bool) {
	crashReportFileOutputEnabled.Store(enabled)
}

func CrashReportFileOutputEnabled() bool {
	return crashReportFileOutputEnabled.Load()
}

// InstallCrashHandlers registers process-level crash capture:
//   - runtime/debug.SetCrashOutput for unhandled panics and fatal runtime errors
//
// logDir is the directory for crash_latest.log; defaults to "logs" when empty.
// Safe to call multiple times; only the first call takes effect.
// Must NOT be called while Logger.Configure holds l.mu.
func InstallCrashHandlers(logDir string) {
	crashHandlerOnce.Do(func() {
		installCrashOutputFile(logDir)
	})
}

func installCrashOutputFile(logDir string) {
	if logDir == "" {
		logDir = "logs"
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		Warn("Failed to create crash log directory %s: %v", logDir, err)
		return
	}

	crashPath := filepath.Join(logDir, "crash_latest.log")
	f, err := os.OpenFile(crashPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		Warn("Failed to open crash output file %s: %v", crashPath, err)
		return
	}

	if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
		Warn("Failed to install runtime crash output: %v", err)
		_ = f.Close()
		return
	}

	crashOutputFile = f
	Info("Crash output capture enabled: %s", crashPath)
}

// CapturePanic recovers a panic in a worker goroutine, logs the reason,
// optionally writes debug-only crash files, and keeps the process running.
func CapturePanic(context string) {
	if r := recover(); r != nil {
		handleRecoveredPanic(context, r, false)
	}
}

// CapturePanicExit recovers a panic in main or another critical goroutine,
// logs the reason, optionally writes debug-only crash files, then exits with code 1.
func CapturePanicExit(context string) {
	if r := recover(); r != nil {
		handleRecoveredPanic(context, r, true)
		os.Exit(1)
	}
}

func handleRecoveredPanic(context string, r any, exitAfter bool) {
	stack := ""
	if CrashReportFileOutputEnabled() {
		stack = captureAllGoroutineStacks()
	}
	caller := callerDescription(2)
	reason := fmt.Sprintf("panic in %s (%s): %v", context, caller, r)
	reportCrash(CrashKindRecoveredPanic, context, reason, r, stack, exitAfter)
}

// ReportAPIPanic logs an HTTP handler panic with request context.
func ReportAPIPanic(context string, err any) {
	stack := ""
	if CrashReportFileOutputEnabled() {
		stack = string(debug.Stack())
	}
	reason := fmt.Sprintf("HTTP handler panic in %s: %v", context, err)
	reportCrash(CrashKindAPIPanic, context, reason, err, stack, false)
}

// SafeGo launches fn in a goroutine with automatic panic capture.
func SafeGo(context string, fn func()) {
	go func() {
		defer CapturePanic(context)
		fn()
	}()
}

// SafeGoWithWaitGroup is like SafeGo but participates in a WaitGroup.
func SafeGoWithWaitGroup(context string, wg *sync.WaitGroup, fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer CapturePanic(context)
		fn()
	}()
}

func reportCrash(kind CrashKind, context, reason string, detail any, stack string, exitAfter bool) {
	msg := fmt.Sprintf("[%s] %s", kind, reason)
	Error("%s", msg)

	if CrashReportFileOutputEnabled() {
		content := formatCrashReport(kind, context, reason, detail, stack, exitAfter)
		writeCrashReportFiles(kind, content)
	}

	// Best-effort flush so crash info survives abrupt termination.
	defaultLogger.mu.Lock()
	if defaultLogger.fileOutput != nil {
		_ = defaultLogger.fileOutput.Sync()
	}
	defaultLogger.mu.Unlock()
}

func formatCrashReport(kind CrashKind, context, reason string, detail any, stack string, exitAfter bool) string {
	return fmt.Sprintf(
		"Time: %s\nVersion: %s (build %s, commit %s)\nKind: %s\nContext: %s\nReason: %s\nDetail: %v\nExitAfterReport: %t\n\n=== Stack Dump ===\n%s\n",
		time.Now().Format("2006-01-02 15:04:05.000"),
		Version, BuildTime, GitCommit,
		kind, context, reason, detail, exitAfter, stack,
	)
}

func writeCrashReportFiles(kind CrashKind, content string) {
	if !CrashReportFileOutputEnabled() {
		return
	}
	logDir := resolveLogDir()
	stamp := time.Now().Format("2006-01-02_150405")
	prefix := string(kind)
	if prefix == "" {
		prefix = "crash"
	}

	candidates := []string{
		filepath.Join(logDir, fmt.Sprintf("%s_%s.txt", prefix, stamp)),
		filepath.Join(logDir, "crash_latest.txt"),
	}

	written := false
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err == nil {
			written = true
		}
	}
	if !written {
		Error("Failed to write crash report files for kind=%s", kind)
	}
}

func captureAllGoroutineStacks() string {
	stackBuf := make([]byte, 2*1024*1024)
	n := runtime.Stack(stackBuf, true)
	return string(stackBuf[:n])
}

func callerDescription(skip int) string {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "unknown"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}
	return fmt.Sprintf("%s (%s:%d)", fn.Name(), filepath.Base(file), line)
}

func resolveLogDir() string {
	if cfg := defaultLogger.getConfig(); cfg != nil && cfg.LogDir != "" {
		return cfg.LogDir
	}
	return "logs"
}

// getConfig safely reads the logger config under lock.
func (l *Logger) getConfig() *LogConfig {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config
}
