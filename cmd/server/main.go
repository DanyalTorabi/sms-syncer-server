package main

import (
	"sms-sync-server/internal/config"
	"sms-sync-server/pkg/logger"

	"go.uber.org/zap"
)

func main() {
	// Load configuration
	cfg := config.DefaultConfig()

	// Initialize logger
	if err := logger.Init(cfg.Logging.Path); err != nil {
		panic(err)
	}
	defer logger.Info("Server shutting down")

	// Setup and start server
	srv, err := SetupServer(cfg)
	if err != nil {
		logger.Fatal("Failed to setup server", zap.Error(err))
	}

	if err := StartServer(srv); err != nil {
		logger.Fatal("Server error", zap.Error(err))
	}
}
