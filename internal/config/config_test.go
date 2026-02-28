package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "localhost", cfg.Server.Host)
	assert.Equal(t, "development", cfg.Server.Environment)
	assert.False(t, cfg.Server.AllowInsecureHTTP)
	assert.False(t, cfg.Server.TLS.Enabled)
	assert.Equal(t, "", cfg.Server.TLS.CertFile)
	assert.Equal(t, "", cfg.Server.TLS.KeyFile)
	assert.False(t, cfg.Server.TLS.RedirectHTTP)
	assert.Equal(t, "file:sms.db?cache=shared&mode=rwc", cfg.Database.DSN)
	assert.Equal(t, "your-secret-key", cfg.JWT.Secret)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "server.log", cfg.Logging.Path)
	assert.Equal(t, "admin", cfg.Seed.AdminUsername)
	assert.Equal(t, "admin123", cfg.Seed.AdminPassword)
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	configData := `{
		"server": {
			"port": 9090,
			"host": "127.0.0.1"
		},
		"database": {
			"dsn": "file:test.db?cache=shared&mode=rwc"
		},
		"jwt": {
			"secret": "test-secret-key"
		},
		"logging": {
			"level": "debug",
			"path": "test.log"
		}
	}`

	err := os.WriteFile(configPath, []byte(configData), 0644)
	assert.NoError(t, err)

	// Test loading valid config
	cfg, err := LoadConfig(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, "file:test.db?cache=shared&mode=rwc", cfg.Database.DSN)
	assert.Equal(t, "test-secret-key", cfg.JWT.Secret)
	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, "test.log", cfg.Logging.Path)

	// Test loading non-existent file
	cfg, err = LoadConfig("non-existent.json")
	assert.Error(t, err)
	assert.Nil(t, cfg)

	// Test loading invalid JSON
	invalidConfigPath := filepath.Join(tmpDir, "invalid.json")
	err = os.WriteFile(invalidConfigPath, []byte("invalid json"), 0644)
	assert.NoError(t, err)

	cfg, err = LoadConfig(invalidConfigPath)
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoadConfigPartial(t *testing.T) {
	// Create a temporary config file with partial configuration
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "partial.json")

	configData := `{
		"server": {
			"port": 9090
		},
		"jwt": {
			"secret": "test-secret-key"
		}
	}`

	err := os.WriteFile(configPath, []byte(configData), 0644)
	assert.NoError(t, err)

	// Test loading partial config
	cfg, err := LoadConfig(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "", cfg.Server.Host)
	assert.Equal(t, "", cfg.Database.DSN)
	assert.Equal(t, "test-secret-key", cfg.JWT.Secret)
	assert.Equal(t, "", cfg.Logging.Level)
	assert.Equal(t, "", cfg.Logging.Path)
}

func TestLoadFromEnv(t *testing.T) {
	// Save original env vars
	originalJWT := os.Getenv("JWT_SECRET")
	originalTOTP := os.Getenv("TOTP_ENCRYPTION_KEY")
	originalPort := os.Getenv("SERVER_PORT")
	originalLogLevel := os.Getenv("LOG_LEVEL")
	originalDSN := os.Getenv("DATABASE_DSN")
	originalAdminUser := os.Getenv("ADMIN_USERNAME")
	originalAdminPass := os.Getenv("ADMIN_PASSWORD")
	originalTLSEnabled := os.Getenv("TLS_ENABLED")
	originalTLSCertFile := os.Getenv("TLS_CERT_FILE")
	originalTLSKeyFile := os.Getenv("TLS_KEY_FILE")
	originalAPPEnv := os.Getenv("APP_ENV")
	originalAllowInsecureHTTP := os.Getenv("ALLOW_INSECURE_HTTP")
	originalTLSRedirectHTTP := os.Getenv("TLS_REDIRECT_HTTP")

	defer func() {
		// Restore original env vars
		_ = os.Setenv("JWT_SECRET", originalJWT)
		_ = os.Setenv("TOTP_ENCRYPTION_KEY", originalTOTP)
		_ = os.Setenv("SERVER_PORT", originalPort)
		_ = os.Setenv("LOG_LEVEL", originalLogLevel)
		_ = os.Setenv("DATABASE_DSN", originalDSN)
		_ = os.Setenv("ADMIN_USERNAME", originalAdminUser)
		_ = os.Setenv("ADMIN_PASSWORD", originalAdminPass)
		_ = os.Setenv("TLS_ENABLED", originalTLSEnabled)
		_ = os.Setenv("TLS_CERT_FILE", originalTLSCertFile)
		_ = os.Setenv("TLS_KEY_FILE", originalTLSKeyFile)
		_ = os.Setenv("APP_ENV", originalAPPEnv)
		_ = os.Setenv("ALLOW_INSECURE_HTTP", originalAllowInsecureHTTP)
		_ = os.Setenv("TLS_REDIRECT_HTTP", originalTLSRedirectHTTP)
	}()

	tests := []struct {
		name        string
		setupEnv    func()
		expectError bool
		validateCfg func(*testing.T, *Config)
	}{
		{
			name: "valid configuration from env",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("SERVER_PORT", "9090")
				_ = os.Setenv("LOG_LEVEL", "debug")
				_ = os.Setenv("DATABASE_DSN", "file:test.db")
				_ = os.Setenv("ADMIN_USERNAME", "testadmin")
			},
			expectError: false,
			validateCfg: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "test-jwt-secret", cfg.JWT.Secret)
				assert.Equal(t, 9090, cfg.Server.Port)
				assert.Equal(t, "debug", cfg.Logging.Level)
				assert.Equal(t, "file:test.db", cfg.Database.DSN)
				assert.Equal(t, "testadmin", cfg.Seed.AdminUsername)
			},
		},
		{
			name: "valid TLS env values",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("TLS_ENABLED", "true")
				_ = os.Setenv("TLS_CERT_FILE", "/tmp/server.crt")
				_ = os.Setenv("TLS_KEY_FILE", "/tmp/server.key")
			},
			expectError: false,
			validateCfg: func(t *testing.T, cfg *Config) {
				assert.True(t, cfg.Server.TLS.Enabled)
				assert.Equal(t, "/tmp/server.crt", cfg.Server.TLS.CertFile)
				assert.Equal(t, "/tmp/server.key", cfg.Server.TLS.KeyFile)
			},
		},
		{
			name: "invalid TLS_ENABLED value",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("TLS_ENABLED", "not-a-bool")
			},
			expectError: true,
		},
		{
			name: "valid environment policy env values",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("APP_ENV", "staging")
				_ = os.Setenv("ALLOW_INSECURE_HTTP", "true")
				_ = os.Setenv("TLS_REDIRECT_HTTP", "true")
			},
			expectError: false,
			validateCfg: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "staging", cfg.Server.Environment)
				assert.True(t, cfg.Server.AllowInsecureHTTP)
				assert.True(t, cfg.Server.TLS.RedirectHTTP)
			},
		},
		{
			name: "invalid APP_ENV value",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("APP_ENV", "invalid-env")
			},
			expectError: false,
			validateCfg: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "invalid-env", cfg.Server.Environment)
			},
		},
		{
			name: "missing JWT_SECRET",
			setupEnv: func() {
				_ = os.Unsetenv("JWT_SECRET")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
			},
			expectError: true,
		},
		{
			name: "missing TOTP_ENCRYPTION_KEY",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Unsetenv("TOTP_ENCRYPTION_KEY")
			},
			expectError: true,
		},
		{
			name: "invalid SERVER_PORT",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("SERVER_PORT", "invalid")
			},
			expectError: true,
		},
		{
			name: "SERVER_PORT out of range",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("SERVER_PORT", "99999")
			},
			expectError: true,
		},
		{
			name: "invalid LOG_LEVEL",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Setenv("LOG_LEVEL", "invalid")
			},
			expectError: true,
		},
		{
			name: "invalid TOTP_ENCRYPTION_KEY length",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "tooshort")
			},
			expectError: true,
		},
		{
			name: "invalid TOTP_ENCRYPTION_KEY non-hex",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
			},
			expectError: true,
		},
		{
			name: "default values used when env vars not set",
			setupEnv: func() {
				_ = os.Setenv("JWT_SECRET", "test-jwt-secret")
				_ = os.Setenv("TOTP_ENCRYPTION_KEY", "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab")
				_ = os.Unsetenv("SERVER_PORT")
				_ = os.Unsetenv("LOG_LEVEL")
				_ = os.Unsetenv("DATABASE_DSN")
			},
			expectError: false,
			validateCfg: func(t *testing.T, cfg *Config) {
				assert.Equal(t, 8080, cfg.Server.Port)
				assert.Equal(t, "info", cfg.Logging.Level)
				assert.Equal(t, "file:sms.db?cache=shared&mode=rwc", cfg.Database.DSN)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.Unsetenv("TLS_ENABLED")
			_ = os.Unsetenv("TLS_CERT_FILE")
			_ = os.Unsetenv("TLS_KEY_FILE")
			_ = os.Unsetenv("APP_ENV")
			_ = os.Unsetenv("ALLOW_INSECURE_HTTP")
			_ = os.Unsetenv("TLS_REDIRECT_HTTP")
			tt.setupEnv()
			cfg, err := LoadFromEnv()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
				if tt.validateCfg != nil {
					tt.validateCfg(t, cfg)
				}
			}
		})
	}
}

func TestValidateTOTPKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid hex key",
			key:     "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefab",
			wantErr: false,
		},
		{
			name:    "valid hex key uppercase",
			key:     "12345678901234567890123456789012ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
			wantErr: false,
		},
		{
			name:    "key too short",
			key:     "12345678901234567890123456789012abcdefabcdef",
			wantErr: true,
		},
		{
			name:    "key too long",
			key:     "12345678901234567890123456789012abcdefabcdefabcdefabcdefabcdefabXX",
			wantErr: true,
		},
		{
			name:    "invalid hex character",
			key:     "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
			wantErr: true,
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTOTPKey(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name       string
		setupCfg   func() *Config
		wantErr    bool
		errMessage string
	}{
		{
			name: "valid config",
			setupCfg: func() *Config {
				cfg := &Config{}
				cfg.JWT.Secret = "test-secret"
				cfg.JWT.TokenExpiry = 1 * time.Hour
				cfg.Security.TOTPEncryptionKey = "12345678901234567890123456789012"
				cfg.Server.Port = 8080
				cfg.Database.DSN = "file:test.db"
				cfg.Logging.Level = "info"
				return cfg
			},
			wantErr: false,
		},
		{
			name: "staging requires TLS when insecure mode not allowed",
			setupCfg: func() *Config {
				cfg := &Config{}
				cfg.JWT.Secret = "test-secret"
				cfg.JWT.TokenExpiry = 1 * time.Hour
				cfg.Security.TOTPEncryptionKey = "12345678901234567890123456789012"
				cfg.Server.Port = 8080
				cfg.Server.Environment = "staging"
				cfg.Server.TLS.Enabled = false
				cfg.Server.AllowInsecureHTTP = false
				cfg.Database.DSN = "file:test.db"
				cfg.Logging.Level = "info"
				return cfg
			},
			wantErr:    true,
			errMessage: "TLS is required for APP_ENV=staging",
		},
		{
			name: "invalid APP_ENV is rejected",
			setupCfg: func() *Config {
				cfg := &Config{}
				cfg.JWT.Secret = "test-secret"
				cfg.JWT.TokenExpiry = 1 * time.Hour
				cfg.Security.TOTPEncryptionKey = "12345678901234567890123456789012"
				cfg.Server.Port = 8080
				cfg.Server.Environment = "unknown-env"
				cfg.Database.DSN = "file:test.db"
				cfg.Logging.Level = "info"
				return cfg
			},
			wantErr:    true,
			errMessage: "invalid APP_ENV",
		},
		{
			name: "TLS enabled without cert file",
			setupCfg: func() *Config {
				cfg := &Config{}
				cfg.JWT.Secret = "test-secret"
				cfg.JWT.TokenExpiry = 1 * time.Hour
				cfg.Security.TOTPEncryptionKey = "12345678901234567890123456789012"
				cfg.Server.Port = 8080
				cfg.Server.TLS.Enabled = true
				cfg.Server.TLS.KeyFile = "/tmp/server.key"
				cfg.Database.DSN = "file:test.db"
				cfg.Logging.Level = "info"
				return cfg
			},
			wantErr:    true,
			errMessage: "TLS cert file is required",
		},
		{
			name: "TLS enabled without key file",
			setupCfg: func() *Config {
				cfg := &Config{}
				cfg.JWT.Secret = "test-secret"
				cfg.JWT.TokenExpiry = 1 * time.Hour
				cfg.Security.TOTPEncryptionKey = "12345678901234567890123456789012"
				cfg.Server.Port = 8080
				cfg.Server.TLS.Enabled = true
				cfg.Server.TLS.CertFile = "/tmp/server.crt"
				cfg.Database.DSN = "file:test.db"
				cfg.Logging.Level = "info"
				return cfg
			},
			wantErr:    true,
			errMessage: "TLS key file is required",
		},
		{
			name: "missing JWT secret",
			setupCfg: func() *Config {
				cfg := &Config{}
				cfg.Security.TOTPEncryptionKey = "12345678901234567890123456789012"
				cfg.Server.Port = 8080
				cfg.Database.DSN = "file:test.db"
				cfg.Logging.Level = "info"
				return cfg
			},
			wantErr:    true,
			errMessage: "JWT secret is required",
		},
		{
			name: "invalid server port",
			setupCfg: func() *Config {
				cfg := &Config{}
				cfg.JWT.Secret = "test-secret"
				cfg.Security.TOTPEncryptionKey = "12345678901234567890123456789012"
				cfg.Server.Port = 99999
				cfg.Database.DSN = "file:test.db"
				cfg.Logging.Level = "info"
				return cfg
			},
			wantErr:    true,
			errMessage: "invalid server port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setupCfg()
			err := cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMessage != "" {
					assert.Contains(t, err.Error(), tt.errMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
