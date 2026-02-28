package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sms-sync-server/pkg/logger"

	"go.uber.org/zap"
)

// Config holds all configuration settings
type Config struct {
	Server struct {
		Port int    `json:"port"`
		Host string `json:"host"`
		TLS  struct {
			Enabled  bool   `json:"enabled"`
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`
		} `json:"tls"`
	} `json:"server"`
	Database struct {
		DSN string `json:"dsn"`
	} `json:"database"`
	JWT struct {
		// #nosec G117 - Config loading only, never marshaled in responses
		Secret      string        `json:"secret"`
		TokenExpiry time.Duration `json:"token_expiry"`
	} `json:"jwt"`
	Security struct {
		// TOTPEncryptionKey is a 32-byte key for AES-256-GCM encryption of TOTP secrets
		// #nosec G117 - Config loading only, never marshaled in responses
		TOTPEncryptionKey string `json:"totp_encryption_key"`
	} `json:"security"`
	Logging struct {
		Level string `json:"level"`
		Path  string `json:"path"`
	} `json:"logging"`
	Seed struct {
		Enable        bool   `json:"enable"`
		AdminUsername string `json:"admin_username"`
		AdminPassword string `json:"admin_password"`
	} `json:"seed"`
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
	config.Server.TLS.Enabled = false
	config.Server.TLS.CertFile = ""
	config.Server.TLS.KeyFile = ""
	config.Database.DSN = "file:sms.db?cache=shared&mode=rwc"
	config.JWT.Secret = "your-secret-key"                                  // This should be changed in production
	config.JWT.TokenExpiry = 1 * time.Hour                                 // 1-hour expiry as per ticket #69
	config.Security.TOTPEncryptionKey = "12345678901234567890123456789012" // 32-byte key, change in production
	config.Logging.Level = "info"
	config.Logging.Path = "server.log"
	config.Seed.Enable = true
	config.Seed.AdminUsername = "admin"    // Default admin username
	config.Seed.AdminPassword = "admin123" // Should be changed in production
	return config
}

// LoadFromEnv loads configuration from environment variables.
// Required variables: JWT_SECRET, TOTP_ENCRYPTION_KEY
// Optional variables with defaults: SERVER_PORT, LOG_LEVEL, DATABASE_DSN, JWT_TOKEN_EXPIRY, ADMIN_USERNAME, ADMIN_PASSWORD
func LoadFromEnv() (*Config, error) {
	config := DefaultConfig()

	// SERVER_PORT (optional, default: 8080)
	if portStr := os.Getenv("SERVER_PORT"); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SERVER_PORT: %w", err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("SERVER_PORT must be between 1 and 65535, got %d", port)
		}
		config.Server.Port = port
	}

	// SERVER_HOST (optional, default: localhost)
	if host := os.Getenv("SERVER_HOST"); host != "" {
		config.Server.Host = host
	}

	// TLS_ENABLED (optional, default: false)
	if tlsEnabled := os.Getenv("TLS_ENABLED"); tlsEnabled != "" {
		enabled, err := strconv.ParseBool(tlsEnabled)
		if err != nil {
			return nil, fmt.Errorf("invalid TLS_ENABLED: %w", err)
		}
		config.Server.TLS.Enabled = enabled
	}

	// TLS_CERT_FILE (required when TLS_ENABLED=true)
	if certFile := os.Getenv("TLS_CERT_FILE"); certFile != "" {
		config.Server.TLS.CertFile = certFile
	}

	// TLS_KEY_FILE (required when TLS_ENABLED=true)
	if keyFile := os.Getenv("TLS_KEY_FILE"); keyFile != "" {
		config.Server.TLS.KeyFile = keyFile
	}

	// DATABASE_DSN (optional, default: file:sms.db?cache=shared&mode=rwc)
	if dsn := os.Getenv("DATABASE_DSN"); dsn != "" {
		config.Database.DSN = dsn
	}

	// JWT_SECRET (REQUIRED)
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		config.JWT.Secret = secret
	} else if config.JWT.Secret == "your-secret-key" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is required")
	}

	// JWT_TOKEN_EXPIRY (optional, default: 1h)
	if expiry := os.Getenv("JWT_TOKEN_EXPIRY"); expiry != "" {
		duration, err := time.ParseDuration(expiry)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_TOKEN_EXPIRY format (use Go duration format like 1h, 30m): %w", err)
		}
		config.JWT.TokenExpiry = duration
	}

	// TOTP_ENCRYPTION_KEY (REQUIRED, must be 32 bytes hex)
	if key := os.Getenv("TOTP_ENCRYPTION_KEY"); key != "" {
		if err := validateTOTPKey(key); err != nil {
			return nil, fmt.Errorf("invalid TOTP_ENCRYPTION_KEY: %w", err)
		}
		config.Security.TOTPEncryptionKey = key
	} else if config.Security.TOTPEncryptionKey == "12345678901234567890123456789012" {
		return nil, fmt.Errorf("TOTP_ENCRYPTION_KEY environment variable is required")
	}

	// LOG_LEVEL (optional, default: info)
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
		if !validLevels[strings.ToLower(level)] {
			return nil, fmt.Errorf("invalid LOG_LEVEL: must be one of debug, info, warn, error")
		}
		config.Logging.Level = strings.ToLower(level)
	}

	// ADMIN_USERNAME (optional, default: admin)
	if username := os.Getenv("ADMIN_USERNAME"); username != "" {
		if strings.TrimSpace(username) == "" {
			return nil, fmt.Errorf("ADMIN_USERNAME cannot be empty or whitespace")
		}
		config.Seed.AdminUsername = username
	}

	// ADMIN_PASSWORD (optional on initial load, but required for seeding)
	if password := os.Getenv("ADMIN_PASSWORD"); password != "" {
		config.Seed.AdminPassword = password
	}

	return config, nil
}

// validateTOTPKey validates that the TOTP encryption key is 32 bytes (64 hex characters).
func validateTOTPKey(key string) error {
	// Key should be 32 bytes in hex format (64 hex characters)
	if len(key) != 64 {
		return fmt.Errorf("TOTP key must be 64 hex characters (32 bytes), got %d characters", len(key))
	}

	// Verify all characters are valid hex
	for _, ch := range key {
		if !isHexChar(ch) {
			return fmt.Errorf("TOTP key contains invalid hex character: %c", ch)
		}
	}

	return nil
}

// isHexChar checks if a character is a valid hexadecimal digit.
func isHexChar(ch rune) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// Validate performs validation on the configuration.
func (c *Config) Validate() error {
	if c.JWT.Secret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if c.Security.TOTPEncryptionKey == "" {
		return fmt.Errorf("TOTP encryption key is required")
	}

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Database.DSN == "" {
		return fmt.Errorf("database DSN is required")
	}

	if c.Server.TLS.Enabled {
		if strings.TrimSpace(c.Server.TLS.CertFile) == "" {
			return fmt.Errorf("TLS cert file is required when TLS is enabled")
		}

		if strings.TrimSpace(c.Server.TLS.KeyFile) == "" {
			return fmt.Errorf("TLS key file is required when TLS is enabled")
		}

		certInfo, err := os.Stat(c.Server.TLS.CertFile)
		if err != nil {
			return fmt.Errorf("invalid TLS cert file: %w", err)
		}
		if !certInfo.Mode().IsRegular() {
			return fmt.Errorf("TLS cert file must be a regular file")
		}

		keyInfo, err := os.Stat(c.Server.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("invalid TLS key file: %w", err)
		}
		if !keyInfo.Mode().IsRegular() {
			return fmt.Errorf("TLS key file must be a regular file")
		}
	}

	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLogLevels[strings.ToLower(c.Logging.Level)] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}
