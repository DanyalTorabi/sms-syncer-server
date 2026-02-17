package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	// Enable foreign key constraints
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatalf("failed to enable foreign keys: %v", err)
	}

	// Create all tables
	schema := `
		CREATE TABLE IF NOT EXISTS sms_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sms_id INTEGER,
			user_id TEXT NOT NULL,
			sms_timestamp INTEGER NOT NULL,
			event_timestamp INTEGER NOT NULL,
			phone_number TEXT NOT NULL,
			body TEXT,
			event_type TEXT,
			thread_id INTEGER,
			date_sent INTEGER,
			person TEXT
		);

		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			totp_enabled BOOLEAN DEFAULT 0,
			failed_login_attempts INTEGER DEFAULT 0,
			locked_until INTEGER,
			last_login INTEGER,
			active BOOLEAN DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			active BOOLEAN DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS permissions (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			resource TEXT NOT NULL,
			action TEXT NOT NULL,
			description TEXT,
			active BOOLEAN DEFAULT 1,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS user_groups (
			user_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			assigned_at INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS group_permissions (
			group_id TEXT NOT NULL,
			permission_id TEXT NOT NULL,
			assigned_at INTEGER NOT NULL,
			PRIMARY KEY (group_id, permission_id),
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
		);

		CREATE INDEX IF NOT EXISTS idx_sms_user_id ON sms_messages(user_id);
		CREATE INDEX IF NOT EXISTS idx_sms_timestamp ON sms_messages(sms_timestamp);
		CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
		CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
		CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
		CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups(group_id);
		CREATE INDEX IF NOT EXISTS idx_group_permissions_group_id ON group_permissions(group_id);
		CREATE INDEX IF NOT EXISTS idx_group_permissions_permission_id ON group_permissions(permission_id);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	// Cleanup on test completion
	t.Cleanup(func() {
		db.Close()
	})

	return db
}
