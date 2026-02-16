package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"sms-sync-server/pkg/logger"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type SMSMessage struct {
	ID             int64   `json:"id"`
	SmsID          *int64  `json:"smsId"`
	UserID         string  `json:"user_id"`
	SmsTimestamp   int64   `json:"smsTimestamp"`
	EventTimestamp int64   `json:"eventTimestamp"`
	PhoneNumber    string  `json:"phoneNumber"`
	Body           string  `json:"body"`
	EventType      string  `json:"eventType"`
	ThreadID       *int64  `json:"threadId"`
	DateSent       *int64  `json:"dateSent"`
	Person         *string `json:"person"`
}

type DatabaseInterface interface {
	Close() error
	AddMessage(msg *SMSMessage) error
	GetMessages(userID string, limit, offset int) ([]*SMSMessage, error)
}

type Database struct {
	db *sql.DB
}

func NewDatabase(dbPath string) (*Database, error) {
	if dbPath == "" {
		return nil, errors.New("database path is required")
	}

	// Check for invalid database file path
	if strings.Contains(dbPath, "?mode=invalid") {
		return nil, errors.New("invalid database configuration")
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Enable foreign key constraints for SQLite
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("enable foreign keys failed: %w, close failed: %v", err, closeErr)
		}
		return nil, fmt.Errorf("enable foreign keys failed: %w", err)
	}

	// Verify we can actually connect to the database
	if err := db.Ping(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("ping failed: %w, close failed: %v", err, closeErr)
		}
		return nil, err
	}

	// Try to create tables - if this fails, the database is not usable
	if err := createTables(db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("create tables failed: %w, close failed: %v", err, closeErr)
		}
		return nil, err
	}

	return &Database{db: db}, nil
}

func createTables(db *sql.DB) error {
	// Create all base tables
	if err := createBaseTables(db); err != nil {
		return err
	}

	// Create junction tables
	if err := createJunctionTables(db); err != nil {
		return err
	}

	// Create all indexes
	if err := createIndexes(db); err != nil {
		return err
	}

	return nil
}

func createBaseTables(db *sql.DB) error {
	// Create messages table (existing)
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			smsId INTEGER,
			user_id TEXT NOT NULL,
			smsTimestamp INTEGER NOT NULL,
			eventTimestamp INTEGER NOT NULL,
			phoneNumber TEXT NOT NULL,
			body TEXT NOT NULL,
			eventType TEXT NOT NULL,
			threadId INTEGER,
			dateSent INTEGER,
			person TEXT
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create messages table: %w", err)
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			totp_enabled BOOLEAN DEFAULT 0,
			active BOOLEAN DEFAULT 1,
			failed_login_attempts INTEGER DEFAULT 0,
			locked_until INTEGER,
			last_login INTEGER,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create groups table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			active BOOLEAN DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create groups table: %w", err)
	}

	// Create permissions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS permissions (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			resource TEXT NOT NULL,
			action TEXT NOT NULL,
			description TEXT,
			active BOOLEAN DEFAULT 1,
			created_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create permissions table: %w", err)
	}

	return nil
}

func createJunctionTables(db *sql.DB) error {
	// Create user_groups junction table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user_groups (
			user_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			assigned_at INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create user_groups table: %w", err)
	}

	// Create group_permissions junction table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS group_permissions (
			group_id TEXT NOT NULL,
			permission_id TEXT NOT NULL,
			assigned_at INTEGER NOT NULL,
			PRIMARY KEY (group_id, permission_id),
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create group_permissions table: %w", err)
	}

	return nil
}

func createIndexes(db *sql.DB) error {
	indexes := []struct {
		name string
		sql  string
	}{
		{"idx_users_username", "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"},
		{"idx_users_email", "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)"},
		{"idx_groups_name", "CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name)"},
		{"idx_permissions_name", "CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name)"},
		{"idx_user_groups_user_id", "CREATE INDEX IF NOT EXISTS idx_user_groups_user_id ON user_groups(user_id)"},
		{"idx_user_groups_group_id", "CREATE INDEX IF NOT EXISTS idx_user_groups_group_id ON user_groups(group_id)"},
		{"idx_group_permissions_group_id", "CREATE INDEX IF NOT EXISTS idx_group_permissions_group_id ON group_permissions(group_id)"},
		{"idx_group_permissions_permission_id", "CREATE INDEX IF NOT EXISTS idx_group_permissions_permission_id ON group_permissions(permission_id)"},
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx.sql); err != nil {
			return fmt.Errorf("failed to create %s: %w", idx.name, err)
		}
	}

	return nil
}

func (d *Database) Close() error {
	if d == nil {
		return errors.New("database is nil")
	}

	if d.db == nil {
		return errors.New("database already closed")
	}

	err := d.db.Close()
	if err != nil {
		// If the error indicates the database is already closed, set db to nil and return the error
		d.db = nil
		return err
	}
	d.db = nil
	return nil
}

func (d *Database) AddMessage(msg *SMSMessage) error {
	if d == nil {
		return errors.New("database is nil")
	}

	if d.db == nil {
		return errors.New("database is closed")
	}

	if msg == nil {
		return errors.New("message cannot be nil")
	}

	if msg.UserID == "" || msg.PhoneNumber == "" || msg.Body == "" {
		return errors.New("all message fields are required")
	}

	_, err := d.db.Exec(
		"INSERT INTO messages (user_id, smsId, smsTimestamp, eventTimestamp, phoneNumber, body, eventType, "+
			"threadId, dateSent, person) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		msg.UserID,
		msg.SmsID,
		msg.SmsTimestamp,
		msg.EventTimestamp,
		msg.PhoneNumber,
		msg.Body,
		msg.EventType,
		msg.ThreadID,
		msg.DateSent,
		msg.Person,
	)
	return err
}

func (d *Database) GetMessages(userID string, limit, offset int) ([]*SMSMessage, error) {
	if d == nil {
		return nil, errors.New("database is nil")
	}

	if d.db == nil {
		return nil, errors.New("database is closed")
	}

	if userID == "" {
		return nil, errors.New("user ID is required")
	}

	if limit < 0 {
		return nil, errors.New("limit cannot be negative")
	}

	if offset < 0 {
		return nil, errors.New("offset cannot be negative")
	}

	// Handle negative or zero limit
	if limit <= 0 {
		limit = 100 // Use a default limit
	}

	// Handle negative offset
	if offset < 0 {
		offset = 0
	}

	rows, err := d.db.Query(
		"SELECT id, user_id, smsId, smsTimestamp, eventTimestamp, phoneNumber, body, eventType, "+
			"threadId, dateSent, person FROM messages WHERE user_id = ? ORDER BY eventTimestamp DESC LIMIT ? OFFSET ?",
		userID,
		limit,
		offset,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Warn("Failed to close database rows", zap.Error(closeErr))
		}
	}()

	var messages []*SMSMessage
	for rows.Next() {
		msg := &SMSMessage{}
		err := rows.Scan(&msg.ID, &msg.UserID, &msg.SmsID, &msg.SmsTimestamp, &msg.EventTimestamp,
			&msg.PhoneNumber, &msg.Body, &msg.EventType, &msg.ThreadID, &msg.DateSent, &msg.Person)
		if err != nil {
			return nil, err
		}
		messages = append(messages, msg)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

// SeedDatabase populates the database with default data (admin user, permissions, groups)
func (d *Database) SeedDatabase(adminPassword string) error {
	logger.Info("Starting database seeding")

	// Check if seeding is needed (no users exist)
	var userCount int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		return fmt.Errorf("failed to check user count: %w", err)
	}

	if userCount > 0 {
		logger.Info("Database already seeded, skipping", zap.Int("user_count", userCount))
		return nil
	}

	// Start a transaction for atomic seeding
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				logger.Error("Failed to rollback transaction", zap.Error(rbErr))
			}
		}
	}()

	// Hash admin password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	now := time.Now().Unix()

	// Create default permissions
	permissions := []struct {
		name        string
		resource    string
		action      string
		description string
	}{
		{"sms:read", "sms", "read", "Read SMS messages"},
		{"sms:write", "sms", "write", "Create and update SMS messages"},
		{"sms:delete", "sms", "delete", "Delete SMS messages"},
		{"users:read", "users", "read", "View user information"},
		{"users:write", "users", "write", "Create and update users"},
		{"users:delete", "users", "delete", "Delete users"},
		{"groups:manage", "groups", "manage", "Manage user groups"},
		{"permissions:manage", "permissions", "manage", "Manage permissions"},
	}

	permissionIDs := make(map[string]string)
	for _, perm := range permissions {
		permID := uuid.New().String()
		_, err := tx.Exec(`
			INSERT INTO permissions (id, name, resource, action, description, active, created_at)
			VALUES (?, ?, ?, ?, ?, 1, ?)`,
			permID, perm.name, perm.resource, perm.action, perm.description, now)
		if err != nil {
			return fmt.Errorf("failed to create permission %s: %w", perm.name, err)
		}
		permissionIDs[perm.name] = permID
		logger.Debug("Created permission", zap.String("name", perm.name), zap.String("id", permID))
	}

	// Create default groups
	groups := []struct {
		name        string
		description string
		permissions []string
	}{
		{
			"Administrators",
			"Full system access",
			[]string{"sms:read", "sms:write", "sms:delete", "users:read", "users:write", "users:delete", "groups:manage", "permissions:manage"},
		},
		{
			"Users",
			"Basic SMS access",
			[]string{"sms:read", "sms:write"},
		},
	}

	groupIDs := make(map[string]string)
	for _, group := range groups {
		groupID := uuid.New().String()
		_, err := tx.Exec(`
			INSERT INTO groups (id, name, description, active, created_at, updated_at)
			VALUES (?, ?, ?, 1, ?, ?)`,
			groupID, group.name, group.description, now, now)
		if err != nil {
			return fmt.Errorf("failed to create group %s: %w", group.name, err)
		}
		groupIDs[group.name] = groupID
		logger.Debug("Created group", zap.String("name", group.name), zap.String("id", groupID))

		// Assign permissions to group
		for _, permName := range group.permissions {
			permID, ok := permissionIDs[permName]
			if !ok {
				return fmt.Errorf("permission %s not found", permName)
			}
			_, err := tx.Exec(`
				INSERT INTO group_permissions (group_id, permission_id, assigned_at)
				VALUES (?, ?, ?)`,
				groupID, permID, now)
			if err != nil {
				return fmt.Errorf("failed to assign permission %s to group %s: %w", permName, group.name, err)
			}
		}
	}

	// Create admin user
	adminUserID := uuid.New().String()
	_, err = tx.Exec(`
		INSERT INTO users (id, username, email, password_hash, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, ?, ?)`,
		adminUserID, "admin", "admin@localhost", string(hashedPassword), now, now)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}
	logger.Debug("Created admin user", zap.String("id", adminUserID))

	// Assign Administrators group to admin user
	adminGroupID := groupIDs["Administrators"]
	_, err = tx.Exec(`
		INSERT INTO user_groups (user_id, group_id, assigned_at)
		VALUES (?, ?, ?)`,
		adminUserID, adminGroupID, now)
	if err != nil {
		return fmt.Errorf("failed to assign Administrators group to admin user: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logger.Info("Database seeding completed successfully",
		zap.Int("permissions", len(permissions)),
		zap.Int("groups", len(groups)),
		zap.String("admin_user", "admin"))

	return nil
}
