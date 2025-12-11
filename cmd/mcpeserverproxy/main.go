// Package main provides the entry point for the mcpeserverproxy application.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/api"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/proxy"
)

var (
	configPath     = flag.String("config", "config.json", "Path to global configuration file")
	serverListPath = flag.String("servers", "server_list.json", "Path to server list configuration file")
	showVersion    = flag.Bool("version", false, "Show version information")
	debugMode      = flag.Bool("debug", false, "Enable debug logging")
)

func main() {
	flag.Parse()

	// Initialize logger
	logger.Init()

	// Enable debug mode if flag is set
	if *debugMode {
		logger.SetDefaultLevel(logger.LevelDebug)
	}

	// Show version and exit if requested
	if *showVersion {
		fmt.Printf("mcpeserverproxy %s\n", logger.Version)
		fmt.Printf("Build Time: %s\n", logger.BuildTime)
		fmt.Printf("Git Commit: %s\n", logger.GitCommit)
		os.Exit(0)
	}

	// Load global configuration
	globalConfig, err := config.LoadGlobalConfig(*configPath)
	if err != nil {
		logger.Error("Failed to load global config: %v", err)
		os.Exit(1)
	}

	// Validate global configuration
	if err := globalConfig.Validate(); err != nil {
		logger.Error("Invalid global config: %v", err)
		os.Exit(1)
	}

	// Enable debug mode from config if not already set by flag
	if globalConfig.DebugMode && !*debugMode {
		logger.SetDefaultLevel(logger.LevelDebug)
	}

	// Configure file logging
	logConfig := &logger.LogConfig{
		LogDir:           globalConfig.LogDir,
		RetentionDays:    globalConfig.LogRetentionDays,
		MaxSizeMB:        globalConfig.LogMaxSizeMB,
		EnableFileLog:    globalConfig.LogDir != "",
		EnableConsoleLog: true,
	}
	if err := logger.Configure(logConfig); err != nil {
		logger.Error("Failed to configure file logging: %v", err)
		// Continue without file logging
	}

	// Create config manager and load server configurations
	configMgr, err := config.NewConfigManager(*serverListPath)
	if err != nil {
		logger.Error("Failed to create config manager: %v", err)
		os.Exit(1)
	}

	if err := configMgr.Load(); err != nil {
		logger.Error("Failed to load server configurations: %v", err)
		os.Exit(1)
	}

	// Initialize database
	database, err := db.NewDatabase(globalConfig.DatabasePath)
	if err != nil {
		logger.Error("Failed to open database: %v", err)
		os.Exit(1)
	}
	defer database.Close()

	if err := database.Initialize(); err != nil {
		logger.Error("Failed to initialize database schema: %v", err)
		os.Exit(1)
	}

	// Log startup information (requirement 9.4)
	logger.LogStartup(&logger.StartupConfig{
		APIPort:             globalConfig.APIPort,
		DatabasePath:        globalConfig.DatabasePath,
		ServerCount:         configMgr.ServerCount(),
		MaxSessionRecords:   globalConfig.MaxSessionRecords,
		MaxAccessLogRecords: globalConfig.MaxAccessLogRecords,
		LogDir:              globalConfig.LogDir,
		LogRetentionDays:    globalConfig.LogRetentionDays,
	})

	// Create proxy server
	proxyServer, err := proxy.NewProxyServer(globalConfig, configMgr, database)
	if err != nil {
		logger.Error("Failed to create proxy server: %v", err)
		os.Exit(1)
	}

	// Create system monitor
	mon := monitor.NewMonitor()

	// Create API key repository
	apiKeyRepo := db.NewAPIKeyRepository(database, globalConfig.MaxAccessLogRecords)

	// Create ACL manager for access control
	aclManager := acl.NewACLManager(database)

	// Inject ACL manager into proxy server for access control (Requirement 4.1, 5.1)
	proxyServer.SetACLManager(aclManager)

	// Create API server
	apiServer := api.NewAPIServer(
		globalConfig,
		configMgr,
		proxyServer.GetSessionManager(),
		database,
		apiKeyRepo,
		proxyServer.GetPlayerRepository(),
		proxyServer.GetSessionRepository(),
		mon,
		proxyServer,
		aclManager,
	)

	// Start proxy server
	if err := proxyServer.Start(); err != nil {
		logger.Error("Failed to start proxy server: %v", err)
		os.Exit(1)
	}

	// Start API server in a goroutine
	apiAddr := fmt.Sprintf(":%d", globalConfig.APIPort)
	go func() {
		logger.Info("Starting API server on %s", apiAddr)
		if err := apiServer.Start(apiAddr); err != nil {
			logger.Error("API server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	logger.Info("Shutdown signal received, stopping services...")

	// Stop API server
	if err := apiServer.Stop(); err != nil {
		logger.Error("Error stopping API server: %v", err)
	}

	// Stop proxy server
	if err := proxyServer.Stop(); err != nil {
		logger.Error("Error stopping proxy server: %v", err)
	}

	// Close logger
	logger.Close()

	logger.Info("Shutdown complete")
}
