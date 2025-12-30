// Package logger provides structured logging functionality for the proxy server.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Version information - should be set at build time.
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

// Level represents the logging level.
type Level int

const (
	// LevelDebug is for debug messages.
	LevelDebug Level = iota
	// LevelInfo is for informational messages.
	LevelInfo
	// LevelWarn is for warning messages.
	LevelWarn
	// LevelError is for error messages.
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// LogConfig holds configuration for file logging.
type LogConfig struct {
	LogDir           string // Directory for log files
	RetentionDays    int    // Days to keep log files
	MaxSizeMB        int    // Max size per log file in MB
	EnableFileLog    bool   // Whether to enable file logging
	EnableConsoleLog bool   // Whether to enable console logging
}

// DefaultLogConfig returns default logging configuration.
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		LogDir:           "logs",
		RetentionDays:    7,
		MaxSizeMB:        100,
		EnableFileLog:    true,
		EnableConsoleLog: true,
	}
}

// Logger provides structured logging with levels and file output.
type Logger struct {
	mu            sync.Mutex
	level         atomic.Int32
	consoleOutput io.Writer
	fileOutput    *os.File
	config        *LogConfig
	currentDate   string
	prefix        string
}

// defaultLogger is the package-level logger instance.
var defaultLogger = NewLogger(os.Stdout, LevelInfo, "")

func IsLevelEnabled(level Level) bool {
	return level >= Level(defaultLogger.level.Load())
}

// NewLogger creates a new logger instance.
func NewLogger(output io.Writer, level Level, prefix string) *Logger {
	l := &Logger{
		consoleOutput: output,
		prefix:        prefix,
		config:        DefaultLogConfig(),
	}
	l.level.Store(int32(level))
	return l
}

// SetLevel sets the logging level.
func (l *Logger) SetLevel(level Level) {
	l.level.Store(int32(level))
}

// SetOutput sets the console output writer.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consoleOutput = w
}

// Configure sets up file logging with the given configuration.
func (l *Logger) Configure(config *LogConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.config = config

	if config.EnableFileLog && config.LogDir != "" {
		// Create log directory if it doesn't exist
		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		// Open or create today's log file
		if err := l.rotateLogFile(); err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}

		// Clean up old log files
		l.cleanupOldLogs()
	}

	return nil
}

// rotateLogFile opens a new log file for the current date.
func (l *Logger) rotateLogFile() error {
	today := time.Now().Format("2006-01-02")

	// Close existing file if date changed
	if l.fileOutput != nil && l.currentDate != today {
		l.fileOutput.Close()
		l.fileOutput = nil
	}

	if l.fileOutput == nil {
		logPath := filepath.Join(l.config.LogDir, fmt.Sprintf("proxy_%s.log", today))
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		l.fileOutput = file
		l.currentDate = today
	}

	return nil
}

// checkAndRotateBySize checks if current log file exceeds max size and rotates if needed.
func (l *Logger) checkAndRotateBySize() {
	if l.fileOutput == nil || l.config.MaxSizeMB <= 0 {
		return
	}

	info, err := l.fileOutput.Stat()
	if err != nil {
		return
	}

	maxBytes := int64(l.config.MaxSizeMB) * 1024 * 1024
	if info.Size() >= maxBytes {
		// Close current file
		l.fileOutput.Close()

		// Rename with timestamp
		oldPath := filepath.Join(l.config.LogDir, fmt.Sprintf("proxy_%s.log", l.currentDate))
		newPath := filepath.Join(l.config.LogDir, fmt.Sprintf("proxy_%s_%s.log", l.currentDate, time.Now().Format("150405")))
		os.Rename(oldPath, newPath)

		// Open new file
		l.fileOutput = nil
		l.rotateLogFile()
	}
}

// cleanupOldLogs removes log files older than retention period.
func (l *Logger) cleanupOldLogs() {
	if l.config.RetentionDays <= 0 {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -l.config.RetentionDays)

	files, err := os.ReadDir(l.config.LogDir)
	if err != nil {
		return
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), "proxy_") || !strings.HasSuffix(file.Name(), ".log") {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(l.config.LogDir, file.Name()))
		}
	}
}

// log writes a log message at the specified level.
func (l *Logger) log(level Level, format string, args ...any) {
	if level < Level(l.level.Load()) {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if level < Level(l.level.Load()) {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	prefix := l.prefix
	if prefix != "" {
		prefix = "[" + prefix + "] "
	}

	msg := fmt.Sprintf(format, args...)
	logLine := fmt.Sprintf("%s [%s] %s%s\n", timestamp, level.String(), prefix, msg)

	// Write to console
	if l.config.EnableConsoleLog && l.consoleOutput != nil {
		fmt.Fprint(l.consoleOutput, logLine)
	}

	// Write to file
	if l.config.EnableFileLog && l.fileOutput != nil {
		// Check for date rotation
		today := time.Now().Format("2006-01-02")
		if l.currentDate != today {
			l.rotateLogFile()
		}

		// Check for size rotation
		l.checkAndRotateBySize()

		if l.fileOutput != nil {
			l.fileOutput.WriteString(logLine)
		}
	}
}

// Debug logs a debug message.
func (l *Logger) Debug(format string, args ...any) {
	l.log(LevelDebug, format, args...)
}

// Info logs an informational message.
func (l *Logger) Info(format string, args ...any) {
	l.log(LevelInfo, format, args...)
}

// Warn logs a warning message.
func (l *Logger) Warn(format string, args ...any) {
	l.log(LevelWarn, format, args...)
}

// Error logs an error message.
func (l *Logger) Error(format string, args ...any) {
	l.log(LevelError, format, args...)
}

// Close closes the log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fileOutput != nil {
		l.fileOutput.Close()
		l.fileOutput = nil
	}
}

// Package-level functions using the default logger.

// SetDefaultLevel sets the default logger's level.
func SetDefaultLevel(level Level) {
	defaultLogger.SetLevel(level)
}

// SetDefaultOutput sets the default logger's output.
func SetDefaultOutput(w io.Writer) {
	defaultLogger.SetOutput(w)
}

// Configure configures the default logger with file logging.
func Configure(config *LogConfig) error {
	return defaultLogger.Configure(config)
}

// Close closes the default logger.
func Close() {
	defaultLogger.Close()
}

// Debug logs a debug message using the default logger.
func Debug(format string, args ...any) {
	defaultLogger.Debug(format, args...)
}

// Info logs an informational message using the default logger.
func Info(format string, args ...any) {
	defaultLogger.Info(format, args...)
}

// Warn logs a warning message using the default logger.
func Warn(format string, args ...any) {
	defaultLogger.Warn(format, args...)
}

// Error logs an error message using the default logger.
func Error(format string, args ...any) {
	defaultLogger.Error(format, args...)
}

// GetLogFiles returns a list of log files sorted by date (newest first).
func GetLogFiles(logDir string) ([]LogFileInfo, error) {
	files, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}

	var logFiles []LogFileInfo
	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), "proxy_") || !strings.HasSuffix(file.Name(), ".log") {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		logFiles = append(logFiles, LogFileInfo{
			Name:    file.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	// Sort by modification time, newest first
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].ModTime.After(logFiles[j].ModTime)
	})

	return logFiles, nil
}

// LogFileInfo contains information about a log file.
type LogFileInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// LogStartup outputs startup information including version and configuration summary.
func LogStartup(config *StartupConfig) {
	Info("=================================================")
	Info("mcpeserverproxy starting")
	Info("Version: %s", Version)
	Info("Build Time: %s", BuildTime)
	Info("Git Commit: %s", GitCommit)
	Info("-------------------------------------------------")
	if config != nil {
		Info("Configuration Summary:")
		Info("  API Port: %d", config.APIPort)
		Info("  Database: %s", config.DatabasePath)
		Info("  Server Count: %d", config.ServerCount)
		Info("  Max Session Records: %d", config.MaxSessionRecords)
		Info("  Max Access Log Records: %d", config.MaxAccessLogRecords)
		Info("  Log Directory: %s", config.LogDir)
		Info("  Log Retention: %d days", config.LogRetentionDays)
	}
	Info("=================================================")
}

// StartupConfig holds configuration information for startup logging.
type StartupConfig struct {
	APIPort             int
	DatabasePath        string
	ServerCount         int
	MaxSessionRecords   int
	MaxAccessLogRecords int
	LogDir              string
	LogRetentionDays    int
}

// LogPlayerConnect logs a player connection event.
func LogPlayerConnect(playerName, playerUUID, playerXUID, clientAddr string) {
	Info("Player connected: name=%s, uuid=%s, xuid=%s, client=%s",
		playerName, playerUUID, playerXUID, clientAddr)
}

// LogPlayerDisconnect logs a player disconnection event.
func LogPlayerDisconnect(playerUUID, displayName, serverName, clientAddr string, duration time.Duration, bytesUp, bytesDown int64) {
	Info("Player disconnected: uuid=%s, name=%s, server=%s, addr=%s, duration=%v, up=%d, down=%d",
		playerUUID, displayName, serverName, clientAddr, duration, bytesUp, bytesDown)
}

// LogSessionCreated logs when a new session is created.
func LogSessionCreated(clientAddr, serverID string) {
	Info("Session created: client=%s, server=%s", clientAddr, serverID)
}

// LogSessionEnded logs when a session ends.
func LogSessionEnded(clientAddr, serverID string, duration time.Duration) {
	Info("Session ended: client=%s, server=%s, duration=%v", clientAddr, serverID, duration)
}

// LogServerStarted logs when a server listener starts.
func LogServerStarted(serverID, listenAddr string) {
	Info("Server started: id=%s, listen=%s", serverID, listenAddr)
}

// LogServerStopped logs when a server listener stops.
func LogServerStopped(serverID string) {
	Info("Server stopped: id=%s", serverID)
}

// LogConfigReloaded logs when configuration is reloaded.
func LogConfigReloaded(serverCount int) {
	Info("Configuration reloaded: %d servers configured", serverCount)
}

// LogDNSResolved logs DNS resolution results.
func LogDNSResolved(hostname, ip string) {
	Debug("DNS resolved: %s -> %s", hostname, ip)
}

// LogPacketForwardError logs packet forwarding errors.
func LogPacketForwardError(direction, clientAddr string, err error) {
	Warn("Packet forward error: direction=%s, client=%s, error=%v", direction, clientAddr, err)
}

// LogRemoteUnreachable logs when a remote server is unreachable.
func LogRemoteUnreachable(serverID, target string, err error) {
	Error("Remote server unreachable: server=%s, target=%s, error=%v", serverID, target, err)
}

// LogDatabaseError logs database operation errors.
func LogDatabaseError(operation string, err error) {
	Error("Database error: op=%s, error=%v", operation, err)
}

// LogDatabaseRetry logs database retry attempts.
func LogDatabaseRetry(operation string, attempt, maxAttempts int, err error) {
	Warn("Database retry: op=%s, attempt=%d/%d, error=%v", operation, attempt, maxAttempts, err)
}

// LogAccessDenied logs when a player's access is denied by ACL.
func LogAccessDenied(playerName, serverID, clientAddr, reason string) {
	Info("Access denied: player=%s, server=%s, client=%s, reason=%s",
		playerName, serverID, clientAddr, reason)
}

// LogACLCheckError logs when ACL check fails due to database error.
func LogACLCheckError(playerName, serverID string, err any) {
	Warn("ACL check error, allowing connection: player=%s, server=%s, error=%v",
		playerName, serverID, err)
}

// LogAuthVerify logs external auth verification results.
func LogAuthVerify(playerName, xuid, serverID string, allowed bool, reason string) {
	if allowed {
		Info("Auth verify passed: player=%s, xuid=%s, server=%s", playerName, xuid, serverID)
	} else {
		Info("Auth verify denied: player=%s, xuid=%s, server=%s, reason=%s", playerName, xuid, serverID, reason)
	}
}

// Init initializes the logger with standard log package integration.
func Init() {
	// Set standard log package to use our format
	log.SetFlags(0)
	log.SetOutput(&logWriter{})
}

// logWriter adapts standard log output to our logger.
type logWriter struct{}

func (w *logWriter) Write(p []byte) (n int, err error) {
	// Remove trailing newline if present
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	Info("%s", msg)
	return len(p), nil
}
