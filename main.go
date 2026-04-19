package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/api"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/db"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/monitor"
	"mcpeserverproxy/internal/proxy"
	"mcpeserverproxy/internal/subscription"
)

var (
	configPath     = flag.String("config", "config.json", "Path to global configuration file")
	serverListPath = flag.String("servers", "server_list.json", "Path to server list configuration file")
	showVersion    = flag.Bool("version", false, "Show version information")
	debugMode      = flag.Bool("debug", false, "Enable debug logging")
)

func main() {
	flag.Parse()

	logger.Init()

	if *debugMode {
		logger.SetDefaultLevel(logger.LevelDebug)
	}

	if *showVersion {
		fmt.Printf("mcpeserverproxy %s\n", logger.Version)
		fmt.Printf("Build Time: %s\n", logger.BuildTime)
		fmt.Printf("Git Commit: %s\n", logger.GitCommit)
		os.Exit(0)
	}

	ensureJSONFile(*serverListPath, []byte("[]"), "server list config")
	ensureJSONFile("proxy_outbounds.json", []byte("[]"), "proxy outbounds config")
	ensureJSONFile("proxy_subscriptions.json", []byte("[]"), "proxy subscriptions config")
	ensureJSONFile("proxy_ports.json", []byte("[]"), "proxy ports config")
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		defaultCfg := config.DefaultGlobalConfig()
		if err := defaultCfg.Save(*configPath); err != nil {
			logger.Warn("Failed to initialize global config file %s: %v", *configPath, err)
		} else {
			logger.Info("Initialized global config file: %s", *configPath)
		}
	}

	globalConfig, err := config.LoadGlobalConfig(*configPath)
	if err != nil {
		logger.Error("Failed to load global config: %v", err)
		os.Exit(1)
	}

	if err := globalConfig.Validate(); err != nil {
		logger.Error("Invalid global config: %v", err)
		os.Exit(1)
	}

	if globalConfig.DebugMode && !*debugMode {
		logger.SetDefaultLevel(logger.LevelDebug)
	}

	logConfig := &logger.LogConfig{
		LogDir:           globalConfig.LogDir,
		RetentionDays:    globalConfig.LogRetentionDays,
		MaxSizeMB:        globalConfig.LogMaxSizeMB,
		EnableFileLog:    globalConfig.LogDir != "",
		EnableConsoleLog: true,
	}
	if err := logger.Configure(logConfig); err != nil {
		logger.Error("Failed to configure file logging: %v", err)
	}

	configMgr, err := config.NewConfigManager(*serverListPath)
	if err != nil {
		logger.Error("Failed to create config manager: %v", err)
		os.Exit(1)
	}

	if err := configMgr.Load(); err != nil {
		logger.Error("Failed to load server configurations: %v", err)
		os.Exit(1)
	}

	proxySubscriptionMgr := config.NewProxySubscriptionConfigManager("proxy_subscriptions.json")
	if err := proxySubscriptionMgr.Load(); err != nil {
		logger.Error("Failed to load proxy subscriptions: %v", err)
		os.Exit(1)
	}

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

	logger.LogStartup(&logger.StartupConfig{
		APIPort:             globalConfig.APIPort,
		DatabasePath:        globalConfig.DatabasePath,
		ServerCount:         configMgr.ServerCount(),
		MaxSessionRecords:   globalConfig.MaxSessionRecords,
		MaxAccessLogRecords: globalConfig.MaxAccessLogRecords,
		LogDir:              globalConfig.LogDir,
		LogRetentionDays:    globalConfig.LogRetentionDays,
	})

	proxyServer, err := proxy.NewProxyServer(globalConfig, configMgr, database)
	if err != nil {
		logger.Error("Failed to create proxy server: %v", err)
		os.Exit(1)
	}

	mon := monitor.NewMonitor()
	apiKeyRepo := db.NewAPIKeyRepository(database, globalConfig.MaxAccessLogRecords)
	aclManager := acl.NewACLManager(database)
	proxyServer.SetACLManager(aclManager)

	proxyOutboundHandler := api.NewProxyOutboundHandler(
		proxyServer.GetProxyOutboundConfigManager(),
		proxySubscriptionMgr,
		configMgr,
		proxyServer.GetOutboundManager(),
	)
	proxyOutboundHandler.SetUsageContext(proxyServer.GetProxyPortConfigManager(), proxyServer)
	proxyOutboundHandler.SetSubscriptionUpdateHook(proxyServer.TriggerAutoLatencyRefresh)
	subscriptionScheduler := subscription.NewScheduler(
		proxySubscriptionMgr,
		subscription.NewService(proxyServer.GetProxyOutboundConfigManager(), proxyServer.GetOutboundManager()),
		func() int {
			return proxyServer.GetActiveSessionCount() + proxyServer.GetActiveProxyPortConnectionCount()
		},
	)
	subscriptionScheduler.SetAfterUpdateHook(func(sub *config.ProxySubscription, result *subscription.UpdateResult) {
		reason := "subscription auto update"
		if sub != nil && sub.Name != "" {
			reason = "subscription auto update: " + sub.Name
		}
		proxyServer.TriggerAutoLatencyRefresh(reason)
	})

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
		proxyOutboundHandler,
		proxyServer.GetProxyPortConfigManager(),
	)

	if err := proxyServer.Start(); err != nil {
		logger.Error("Failed to start proxy server: %v", err)
		os.Exit(1)
	}

	apiAddr := fmt.Sprintf(":%d", globalConfig.APIPort)
	go func() {
		logger.Info("Starting API server on %s", apiAddr)
		if err := apiServer.Start(apiAddr); err != nil {
			logger.Error("API server error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	subscriptionScheduler.Start(ctx)

	<-ctx.Done()
	logger.Info("Shutdown signal received, stopping services...")

	if err := apiServer.Stop(); err != nil {
		logger.Error("Error stopping API server: %v", err)
	}

	if err := proxyServer.Stop(); err != nil {
		logger.Error("Error stopping proxy server: %v", err)
	}

	logger.Close()
	logger.Info("Shutdown complete")
}

func ensureJSONFile(path string, defaultContent []byte, desc string) {
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err == nil {
		return
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Warn("Failed to create directory for %s (%s): %v", desc, path, err)
			return
		}
	}

	if err := os.WriteFile(path, defaultContent, 0644); err != nil {
		logger.Warn("Failed to initialize %s (%s): %v", desc, path, err)
		return
	}
	logger.Info("Initialized %s: %s", desc, path)
}
