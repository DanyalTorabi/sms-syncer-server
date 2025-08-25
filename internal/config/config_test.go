package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "localhost", cfg.Server.Host)
	assert.Equal(t, "file:sms.db?cache=shared&mode=rwc", cfg.Database.DSN)
	assert.Equal(t, "your-secret-key", cfg.JWT.Secret)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "server.log", cfg.Logging.Path)
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
