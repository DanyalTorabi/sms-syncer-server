package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sms-sync-server/pkg/logger"

	"go.uber.org/zap"
)

// Config holds all configuration settings
type Config struct {
	Server struct {
		Port int    `json:"port"`
		Host string `json:"host"`
	} `json:"server"`
	Database struct {
		DSN string `json:"dsn"`
	} `json:"database"`
	JWT struct {
		Secret      string        `json:"secret"`
		TokenExpiry time.Duration `json:"token_expiry"`
	} `json:"jwt"`
	Logging struct {
		Level string `json:"level"`
		Path  string `json:"path"`
	} `json:"logging"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(path string) (*Config, error) {
	// Validate path to prevent directory traversal
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("config path must be absolute")
	}

	// Check if file exists and is a regular file
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("config file error: %w", err)
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("config path is not a regular file")
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Warn("Failed to close config file", zap.Error(closeErr))
		}
	}()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	config := &Config{}
	config.Server.Port = 8080
	config.Server.Host = "localhost"
	config.Database.DSN = "file:sms.db?cache=shared&mode=rwc"
	config.JWT.Secret = "your-secret-key" // This should be changed in production
	config.JWT.TokenExpiry = 24 * time.Hour
	config.Logging.Level = "info"
	config.Logging.Path = "server.log"
	return config
}
