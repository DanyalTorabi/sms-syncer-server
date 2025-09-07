package main

import (
	"flag"
	"fmt"
	"os"
	"sms-sync-server/internal/config"
	"sms-sync-server/pkg/logger"

	"go.uber.org/zap"
)

// Version information set at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Handle version flag
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.Parse()

	if showVersion {
		fmt.Printf("SMS Sync Server\n")
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Commit: %s\n", commit)
		fmt.Printf("Built: %s\n", date)
		os.Exit(0)
	}

	// Load configuration
	cfg := config.DefaultConfig()

	// Initialize logger
	if err := logger.Init(cfg.Logging.Path); err != nil {
		panic(err)
	}
	defer logger.Info("Server shutting down")

	logger.Info("Starting SMS Sync Server",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("build_date", date),
	)

	// Setup and start server
	srv, err := SetupServer(cfg)
	if err != nil {
		logger.Fatal("Failed to setup server", zap.Error(err))
	}

	if err := StartServer(srv); err != nil {
		logger.Fatal("Server error", zap.Error(err))
	}
}
