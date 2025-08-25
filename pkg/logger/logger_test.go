package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Config represents the logger configuration
type Config struct {
	Level string
	Path  string
}

func TestLogger(t *testing.T) {
	// Create a temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "logger_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "test.log")

	t.Run("Initialize logger with valid path", func(t *testing.T) {
		err := Init(logPath)
		assert.NoError(t, err)
		defer os.Remove(logPath)

		// Test all log levels
		Info("info message")
		Debug("debug message")
		Warn("warn message")
		Error("error message")

		// Read the log file
		content, err := os.ReadFile(logPath)
		require.NoError(t, err)

		// Split the content into lines and parse each line
		lines := splitLines(string(content))
		require.Len(t, lines, 4)

		// Verify each log entry
		logLevels := []string{"info", "debug", "warn", "error"}
		messages := []string{"info message", "debug message", "warn message", "error message"}

		for i, line := range lines {
			var entry map[string]interface{}
			err := json.Unmarshal([]byte(line), &entry)
			require.NoError(t, err)

			assert.Equal(t, logLevels[i], entry["level"])
			assert.Equal(t, messages[i], entry["msg"])
			assert.Contains(t, entry, "timestamp")
		}
	})

	t.Run("Initialize logger with invalid path", func(t *testing.T) {
		invalidPath := filepath.Join("/nonexistent", "dir", "test.log")
		err := Init(invalidPath)
		assert.Error(t, err)
	})

	t.Run("Log without initialization", func(t *testing.T) {
		// Reset the logger
		log = nil

		// These should not panic
		Info("test message")
		Debug("test message")
		Warn("test message")
		Error("test message")
	})
}

func TestLoggerWithoutInit(t *testing.T) {
	// Reset the logger
	log = nil

	// These should not panic
	Info("test info")
	Error("test error")
	Debug("test debug")
	Warn("test warn")
	Fatal("test fatal") // Note: Fatal would normally exit, but we're testing with nil logger
	err := Sync()
	assert.NoError(t, err)
}

func TestLoggerInitWithInvalidPath(t *testing.T) {
	// Try to initialize logger with an invalid path
	err := Init("/invalid/path/that/does/not/exist/test.log")
	assert.Error(t, err)
}

func TestLoggerFatal(t *testing.T) {
	// Enable test mode to prevent os.Exit
	SetTestMode(true)
	defer SetTestMode(false)

	// Initialize logger
	err := Init("test-fatal.log")
	require.NoError(t, err)
	defer os.Remove("test-fatal.log")

	// Log a fatal message
	Fatal("This is a fatal message")

	// Read the log file
	content, err := os.ReadFile("test-fatal.log")
	require.NoError(t, err)

	// Verify the log entry
	require.Contains(t, string(content), "This is a fatal message")
	require.Contains(t, string(content), "level\":\"error\"")
}

func TestLoggerSync(t *testing.T) {
	// Create a temporary directory for test logs
	tmpDir, err := os.MkdirTemp("", "logger_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "test.log")

	// Initialize logger
	err = Init(logPath)
	require.NoError(t, err)
	defer os.Remove(logPath)

	// Log some messages
	Info("info message")
	Error("error message")

	// Sync the logger
	err = Sync()
	assert.NoError(t, err)

	// Verify the messages were written
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.NotEmpty(t, content)

	// Test Sync with uninitialized logger
	log = nil
	err = Sync()
	assert.NoError(t, err)
}

// Helper function to split log content into lines
func splitLines(content string) []string {
	var lines []string
	var line []byte

	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			if len(line) > 0 {
				lines = append(lines, string(line))
				line = nil
			}
		} else {
			line = append(line, content[i])
		}
	}
	if len(line) > 0 {
		lines = append(lines, string(line))
	}
	return lines
}
