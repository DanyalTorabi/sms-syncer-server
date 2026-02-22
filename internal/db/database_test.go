package db

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestNewDatabase(t *testing.T) {
	// Test with empty path
	db, err := NewDatabase("")
	if err == nil {
		t.Error("Expected error for empty database path, got nil")
	}
	if db != nil {
		t.Error("Expected nil database for empty path, got non-nil")
	}

	// Test with invalid configuration
	db, err = NewDatabase("test.db?mode=invalid")
	if err == nil {
		t.Error("Expected error for invalid configuration, got nil")
	}
	if db != nil {
		t.Error("Expected nil database for invalid configuration, got non-nil")
	}

	// Test with valid path
	db, err = NewDatabase(":memory:")
	if err != nil {
		t.Errorf("Expected no error for valid path, got: %v", err)
	}
	if db == nil {
		t.Error("Expected non-nil database for valid path, got nil")
	}
	if db != nil {
		db.Close()
	}
}

func TestNewDatabase_CreateTableError(t *testing.T) {
	// Create a temporary file for the database
	tmpFile, err := os.CreateTemp("", "testdb-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Make the file read-only to cause a create table error
	err = os.Chmod(tmpFile.Name(), 0444)
	if err != nil {
		t.Fatalf("Failed to set file permissions: %v", err)
	}

	db, err := NewDatabase(tmpFile.Name())
	if err == nil {
		t.Error("Expected error from NewDatabase when createTables fails")
	}
	if db != nil {
		t.Error("Expected nil database when createTables fails")
	}
}

type mockDriver struct {
	shouldFail bool
}

func (d *mockDriver) Open(dsn string) (driver.Conn, error) {
	return &mockConn{shouldFail: d.shouldFail}, nil
}

type mockConn struct {
	shouldFail bool
}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{shouldFail: c.shouldFail}, nil
}

func (c *mockConn) Close() error {
	return nil
}

func (c *mockConn) Begin() (driver.Tx, error) {
	return nil, nil
}

type mockStmt struct {
	shouldFail bool
}

func (s *mockStmt) Close() error {
	return nil
}

func (s *mockStmt) NumInput() int {
	return 0
}

func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	if s.shouldFail {
		return nil, fmt.Errorf("mock exec error")
	}
	return nil, nil
}

func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, nil
}

func TestAddMessage(t *testing.T) {
	// Test normal add message
	db, err := NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	msg := &SMSMessage{
		UserID:         "test-user",
		PhoneNumber:    "sender",
		Body:           "test message",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	err = db.AddMessage(msg)
	if err != nil {
		t.Errorf("AddMessage() error = %v, want nil", err)
	}

	// Test with nil database
	var nilDB *Database
	err = nilDB.AddMessage(msg)
	if err == nil {
		t.Error("AddMessage() with nil database should return an error")
	}

	// Test with nil message
	err = db.AddMessage(nil)
	if err == nil {
		t.Error("AddMessage() with nil message should return an error")
	}

	// Test with invalid message
	invalidMsg := &SMSMessage{
		UserID:      "", // Empty user ID
		PhoneNumber: "sender",
		Body:        "test message",
		EventType:   "RECEIVED",
	}
	err = db.AddMessage(invalidMsg)
	if err == nil {
		t.Error("AddMessage() with invalid message should return an error")
	}
}

func TestGetMessages(t *testing.T) {
	// Test normal get messages
	db, err := NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Add some test messages
	messages := []*SMSMessage{
		{
			UserID:         "test-user",
			PhoneNumber:    "sender1",
			Body:           "message 1",
			EventType:      "RECEIVED",
			SmsTimestamp:   time.Now().Unix(),
			EventTimestamp: time.Now().Unix(),
		},
		{
			UserID:         "test-user",
			PhoneNumber:    "sender2",
			Body:           "message 2",
			EventType:      "RECEIVED",
			SmsTimestamp:   time.Now().Unix(),
			EventTimestamp: time.Now().Unix(),
		},
	}

	for _, msg := range messages {
		err = db.AddMessage(msg)
		if err != nil {
			t.Fatalf("Failed to add message: %v", err)
		}
	}

	// Test normal query
	msgs, err := db.GetMessages("test-user", 10, 0)
	if err != nil {
		t.Errorf("GetMessages() error = %v, want nil", err)
	}
	if len(msgs) != 2 {
		t.Errorf("GetMessages() returned %d messages, want 2", len(msgs))
	}

	// Test with nil database
	var nilDB *Database
	msgs, err = nilDB.GetMessages("test-user", 10, 0)
	if err == nil {
		t.Error("GetMessages() with nil database should return an error")
	}
	if msgs != nil {
		t.Error("GetMessages() with nil database should return nil messages")
	}

	// Test with invalid user ID
	msgs, err = db.GetMessages("", 10, 0)
	if err == nil {
		t.Error("GetMessages() with empty user ID should return an error")
	}
	if msgs != nil {
		t.Error("GetMessages() with empty user ID should return nil messages")
	}

	// Test with negative limit
	msgs, err = db.GetMessages("test-user", -1, 0)
	if err == nil {
		t.Error("GetMessages() with negative limit should return an error")
	}
	if msgs != nil {
		t.Error("GetMessages() with negative limit should return nil messages")
	}

	// Test with negative offset
	msgs, err = db.GetMessages("test-user", 10, -1)
	if err == nil {
		t.Error("GetMessages() with negative offset should return an error")
	}
	if msgs != nil {
		t.Error("GetMessages() with negative offset should return nil messages")
	}

	// Test with query error
	// Create a mock database that will fail on Query
	mockDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer mockDB.Close()

	// Close the mock database to make it return an error on subsequent operations
	mockDB.Close()

	db = &Database{db: mockDB}
	msgs, err = db.GetMessages("test-user", 10, 0)
	if err == nil {
		t.Error("GetMessages() with query error should return an error")
	}
	if msgs != nil {
		t.Error("GetMessages() with query error should return nil messages")
	}
}

func TestClose(t *testing.T) {
	// Test closing a valid database
	db, err := NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Test closing an already closed database
	if err := db.Close(); err == nil {
		t.Error("Expected error when closing already closed database")
	}

	// Test closing a nil database
	var nilDB *Database
	if err := nilDB.Close(); err == nil {
		t.Error("Expected error when closing nil database")
	}
}

type mockDatabase struct {
	shouldFail bool
}

func (m *mockDatabase) Close() error {
	if m.shouldFail {
		return fmt.Errorf("mock close error")
	}
	return nil
}

func (m *mockDatabase) Exec(query string, args ...interface{}) (sql.Result, error) {
	return nil, nil
}

func (m *mockDatabase) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return nil, nil
}

func TestDatabaseOperations(t *testing.T) {
	// Create a temporary directory for test database
	tmpDir, err := os.MkdirTemp("", "db_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := NewDatabase(dbPath)
	require.NoError(t, err)
	defer db.Close()

	// Test AddMessage
	msg := &SMSMessage{
		UserID:         "test-user",
		PhoneNumber:    "1234567890",
		Body:           "Test message",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	err = db.AddMessage(msg)
	assert.NoError(t, err)

	// Test GetMessages
	messages, err := db.GetMessages("test-user", 10, 0)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, msg.UserID, messages[0].UserID)
	assert.Equal(t, msg.PhoneNumber, messages[0].PhoneNumber)
	assert.Equal(t, msg.Body, messages[0].Body)

	// Test pagination
	messages, err = db.GetMessages("test-user", 1, 1)
	assert.NoError(t, err)
	assert.Len(t, messages, 0)

	// Test with non-existent user
	messages, err = db.GetMessages("non-existent", 10, 0)
	assert.NoError(t, err)
	assert.Len(t, messages, 0)

	// Test invalid message
	err = db.AddMessage(nil)
	assert.Error(t, err)

	// Test with empty fields
	emptyMsg := &SMSMessage{
		UserID:      "",
		PhoneNumber: "",
		Body:        "",
		EventType:   "",
	}
	err = db.AddMessage(emptyMsg)
	assert.Error(t, err)
}

func TestDatabaseConcurrency(t *testing.T) {
	// Create a temporary directory for test database
	tmpDir, err := os.MkdirTemp("", "db_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := NewDatabase(dbPath)
	require.NoError(t, err)
	defer db.Close()

	// Test concurrent writes
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := &SMSMessage{
				UserID:         fmt.Sprintf("user-%d", i),
				PhoneNumber:    fmt.Sprintf("sender-%d", i),
				Body:           fmt.Sprintf("message-%d", i),
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			}
			assert.NoError(t, db.AddMessage(msg))
		}(i)
	}
	wg.Wait()

	// Verify all messages were written
	for i := 0; i < 10; i++ {
		messages, err := db.GetMessages(fmt.Sprintf("user-%d", i), 10, 0)
		assert.NoError(t, err)
		assert.Len(t, messages, 1)
	}
}

func TestDatabase(t *testing.T) {
	// Create a temporary database
	db, err := NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Test adding a message
	msg := &SMSMessage{
		UserID:         "test-user",
		PhoneNumber:    "1234567890",
		Body:           "Test message",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	if err := db.AddMessage(msg); err != nil {
		t.Errorf("Failed to add message: %v", err)
	}

	// Test retrieving messages
	messages, err := db.GetMessages("test-user", 10, 0)
	if err != nil {
		t.Errorf("Failed to get messages: %v", err)
	}

	if len(messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(messages))
	}

	if messages[0].Body != "Test message" {
		t.Errorf("Expected message body 'Test message', got '%s'", messages[0].Body)
	}

	// Test pagination
	msg2 := &SMSMessage{
		UserID:         "test-user",
		PhoneNumber:    "1234567890",
		Body:           "Test message 2",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	if err := db.AddMessage(msg2); err != nil {
		t.Errorf("Failed to add second message: %v", err)
	}

	// Test limit
	messages, err = db.GetMessages("test-user", 1, 0)
	if err != nil {
		t.Errorf("Failed to get messages with limit: %v", err)
	}

	if len(messages) != 1 {
		t.Errorf("Expected 1 message with limit=1, got %d", len(messages))
	}

	// Test offset
	messages, err = db.GetMessages("test-user", 10, 1)
	if err != nil {
		t.Errorf("Failed to get messages with offset: %v", err)
	}

	if len(messages) != 1 {
		t.Errorf("Expected 1 message with offset=1, got %d", len(messages))
	}

	// Test non-existent user
	messages, err = db.GetMessages("non-existent-user", 10, 0)
	if err != nil {
		t.Errorf("Failed to get messages for non-existent user: %v", err)
	}

	if len(messages) != 0 {
		t.Errorf("Expected 0 messages for non-existent user, got %d", len(messages))
	}
}

// TestUserManagementTables verifies that all user management tables are created successfully
func TestUserManagementTables(t *testing.T) {
	tests := []struct {
		name      string
		tableName string
	}{
		{"users table exists", "users"},
		{"groups table exists", "groups"},
		{"permissions table exists", "permissions"},
		{"user_groups junction table exists", "user_groups"},
		{"group_permissions junction table exists", "group_permissions"},
	}

	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	defer db.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tableName string
			query := `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
			err := db.db.QueryRow(query, tt.tableName).Scan(&tableName)
			assert.NoError(t, err, "Table %s should exist", tt.tableName)
			assert.Equal(t, tt.tableName, tableName)
		})
	}
}

// TestUserManagementIndexes verifies that all required indexes are created
func TestUserManagementIndexes(t *testing.T) {
	tests := []struct {
		name      string
		indexName string
	}{
		{"idx_users_username exists", "idx_users_username"},
		{"idx_users_email exists", "idx_users_email"},
		{"idx_groups_name exists", "idx_groups_name"},
		{"idx_permissions_name exists", "idx_permissions_name"},
		{"idx_user_groups_user_id exists", "idx_user_groups_user_id"},
		{"idx_user_groups_group_id exists", "idx_user_groups_group_id"},
		{"idx_group_permissions_group_id exists", "idx_group_permissions_group_id"},
		{"idx_group_permissions_permission_id exists", "idx_group_permissions_permission_id"},
		{"idx_messages_user_id exists", "idx_messages_user_id"},
		{"idx_messages_sms_timestamp exists", "idx_messages_sms_timestamp"},
		{"idx_messages_user_timestamp exists", "idx_messages_user_timestamp"},
	}

	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	defer db.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var indexName string
			query := `SELECT name FROM sqlite_master WHERE type='index' AND name=?`
			err := db.db.QueryRow(query, tt.indexName).Scan(&indexName)
			assert.NoError(t, err, "Index %s should exist", tt.indexName)
			assert.Equal(t, tt.indexName, indexName)
		})
	}
}

// TestForeignKeyConstraints verifies that foreign key constraints work correctly
func TestForeignKeyConstraints(t *testing.T) {
	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	defer db.Close()

	// Verify foreign keys are enabled
	var fkEnabled int
	err = db.db.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled)
	require.NoError(t, err)
	assert.Equal(t, 1, fkEnabled, "Foreign keys should be enabled")

	// Test CASCADE delete for user_groups
	t.Run("user_groups CASCADE on user delete", func(t *testing.T) {
		userID := "test-user-fk-1"
		groupID := "test-group-fk-1"
		now := time.Now().Unix()

		// Insert user
		_, err := db.db.Exec(`INSERT INTO users (id, username, email, password_hash, created_at, updated_at) 
			VALUES (?, ?, ?, ?, ?, ?)`, userID, "testuser", "test@example.com", "hash", now, now)
		require.NoError(t, err)

		// Insert group
		_, err = db.db.Exec(`INSERT INTO groups (id, name, created_at, updated_at) 
			VALUES (?, ?, ?, ?)`, groupID, "testgroup", now, now)
		require.NoError(t, err)

		// Insert user_group relationship
		_, err = db.db.Exec(`INSERT INTO user_groups (user_id, group_id, assigned_at) 
			VALUES (?, ?, ?)`, userID, groupID, now)
		require.NoError(t, err)

		// Verify relationship exists
		var count int
		err = db.db.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE user_id = ?`, userID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Delete user - should cascade delete user_groups entry
		_, err = db.db.Exec(`DELETE FROM users WHERE id = ?`, userID)
		require.NoError(t, err)

		// Verify relationship was deleted
		err = db.db.QueryRow(`SELECT COUNT(*) FROM user_groups WHERE user_id = ?`, userID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "user_groups entry should be cascade deleted")
	})

	// Test CASCADE delete for group_permissions
	t.Run("group_permissions CASCADE on group delete", func(t *testing.T) {
		groupID := "test-group-fk-2"
		permissionID := "test-permission-fk-1"
		now := time.Now().Unix()

		// Insert group
		_, err := db.db.Exec(`INSERT INTO groups (id, name, created_at, updated_at) 
			VALUES (?, ?, ?, ?)`, groupID, "testgroup2", now, now)
		require.NoError(t, err)

		// Insert permission
		_, err = db.db.Exec(`INSERT INTO permissions (id, name, resource, action, created_at) 
			VALUES (?, ?, ?, ?, ?)`, permissionID, "testperm", "sms", "read", now)
		require.NoError(t, err)

		// Insert group_permission relationship
		_, err = db.db.Exec(`INSERT INTO group_permissions (group_id, permission_id, assigned_at) 
			VALUES (?, ?, ?)`, groupID, permissionID, now)
		require.NoError(t, err)

		// Verify relationship exists
		var count int
		err = db.db.QueryRow(`SELECT COUNT(*) FROM group_permissions WHERE group_id = ?`, groupID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Delete group - should cascade delete group_permissions entry
		_, err = db.db.Exec(`DELETE FROM groups WHERE id = ?`, groupID)
		require.NoError(t, err)

		// Verify relationship was deleted
		err = db.db.QueryRow(`SELECT COUNT(*) FROM group_permissions WHERE group_id = ?`, groupID).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "group_permissions entry should be cascade deleted")
	})

	// Test foreign key constraint prevents invalid references
	t.Run("foreign key constraint prevents invalid user_id", func(t *testing.T) {
		now := time.Now().Unix()
		// Try to insert user_groups with non-existent user_id
		_, err := db.db.Exec(`INSERT INTO user_groups (user_id, group_id, assigned_at) 
			VALUES (?, ?, ?)`, "non-existent-user", "non-existent-group", now)
		assert.Error(t, err, "Should fail with foreign key constraint violation")
	})
}

// TestIdempotentMigration verifies that running migrations multiple times doesn't cause errors
func TestIdempotentMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_idempotent.db")

	// First migration
	db1, err := NewDatabase(dbPath)
	require.NoError(t, err, "First migration should succeed")
	require.NotNil(t, db1)
	db1.Close()

	// Second migration on same database
	db2, err := NewDatabase(dbPath)
	require.NoError(t, err, "Second migration should succeed (idempotent)")
	require.NotNil(t, db2)
	defer db2.Close()

	// Verify tables still exist and are functional
	var tableName string
	err = db2.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='users'`).Scan(&tableName)
	assert.NoError(t, err)
	assert.Equal(t, "users", tableName)

	// Verify we can insert data
	now := time.Now().Unix()
	_, err = db2.db.Exec(`INSERT INTO users (id, username, email, password_hash, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?)`, "test-user", "testuser", "test@example.com", "hash", now, now)
	assert.NoError(t, err, "Should be able to insert data after idempotent migration")
}

// TestTableSchemas verifies that table schemas match specifications
func TestTableSchemas(t *testing.T) {
	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	defer db.Close()

	t.Run("users table schema", func(t *testing.T) {
		rows, err := db.db.Query(`PRAGMA table_info(users)`)
		require.NoError(t, err)
		defer rows.Close()

		expectedColumns := map[string]bool{
			"id": false, "username": false, "email": false, "password_hash": false,
			"totp_secret": false, "totp_enabled": false, "active": false,
			"failed_login_attempts": false, "locked_until": false, "last_login": false,
			"created_at": false, "updated_at": false,
		}

		for rows.Next() {
			var cid int
			var name, colType string
			var notNull, pk int
			var dfltValue sql.NullString
			err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk)
			require.NoError(t, err)
			if _, exists := expectedColumns[name]; exists {
				expectedColumns[name] = true
			}
		}

		for col, found := range expectedColumns {
			assert.True(t, found, "Column %s should exist in users table", col)
		}
	})

	t.Run("groups table schema", func(t *testing.T) {
		rows, err := db.db.Query(`PRAGMA table_info(groups)`)
		require.NoError(t, err)
		defer rows.Close()

		expectedColumns := map[string]bool{
			"id": false, "name": false, "description": false,
			"active": false, "created_at": false, "updated_at": false,
		}

		for rows.Next() {
			var cid int
			var name, colType string
			var notNull, pk int
			var dfltValue sql.NullString
			err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk)
			require.NoError(t, err)
			if _, exists := expectedColumns[name]; exists {
				expectedColumns[name] = true
			}
		}

		for col, found := range expectedColumns {
			assert.True(t, found, "Column %s should exist in groups table", col)
		}
	})

	t.Run("permissions table schema", func(t *testing.T) {
		rows, err := db.db.Query(`PRAGMA table_info(permissions)`)
		require.NoError(t, err)
		defer rows.Close()

		expectedColumns := map[string]bool{
			"id": false, "name": false, "resource": false, "action": false,
			"description": false, "active": false, "created_at": false,
		}

		for rows.Next() {
			var cid int
			var name, colType string
			var notNull, pk int
			var dfltValue sql.NullString
			err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk)
			require.NoError(t, err)
			if _, exists := expectedColumns[name]; exists {
				expectedColumns[name] = true
			}
		}

		for col, found := range expectedColumns {
			assert.True(t, found, "Column %s should exist in permissions table", col)
		}
	})
}

// TestCreateTableErrors verifies error handling in table creation
func TestCreateTableErrors(t *testing.T) {
	// Test that NewDatabase handles table creation errors properly
	// This is tested indirectly through TestNewDatabase_CreateTableError
	// which verifies the error path when createTables fails

	// Additional test: Verify that createTables is called during NewDatabase
	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	require.NotNil(t, db)
	defer db.Close()

	// Verify all tables were created
	tables := []string{"messages", "users", "groups", "permissions", "user_groups", "group_permissions"}
	for _, table := range tables {
		var name string
		err := db.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		assert.NoError(t, err, "Table %s should be created", table)
	}
}

// TestUniqueConstraints verifies that unique constraints work on tables
func TestUniqueConstraints(t *testing.T) {
	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	defer db.Close()

	now := time.Now().Unix()

	t.Run("duplicate username should fail", func(t *testing.T) {
		// Insert first user
		_, err := db.db.Exec(`INSERT INTO users (id, username, email, password_hash, created_at, updated_at) 
			VALUES (?, ?, ?, ?, ?, ?)`, "user1", "uniqueuser", "user1@example.com", "hash1", now, now)
		require.NoError(t, err)

		// Try to insert user with same username
		_, err = db.db.Exec(`INSERT INTO users (id, username, email, password_hash, created_at, updated_at) 
			VALUES (?, ?, ?, ?, ?, ?)`, "user2", "uniqueuser", "user2@example.com", "hash2", now, now)
		assert.Error(t, err, "Should fail with duplicate username")
	})

	t.Run("duplicate group name should fail", func(t *testing.T) {
		// Insert first group
		_, err := db.db.Exec(`INSERT INTO groups (id, name, created_at, updated_at) 
			VALUES (?, ?, ?, ?)`, "group1", "uniquegroup", now, now)
		require.NoError(t, err)

		// Try to insert group with same name
		_, err = db.db.Exec(`INSERT INTO groups (id, name, created_at, updated_at) 
			VALUES (?, ?, ?, ?)`, "group2", "uniquegroup", now, now)
		assert.Error(t, err, "Should fail with duplicate group name")
	})

	t.Run("duplicate permission name should fail", func(t *testing.T) {
		// Insert first permission
		_, err := db.db.Exec(`INSERT INTO permissions (id, name, resource, action, created_at) 
			VALUES (?, ?, ?, ?, ?)`, "perm1", "uniqueperm", "sms", "read", now)
		require.NoError(t, err)

		// Try to insert permission with same name
		_, err = db.db.Exec(`INSERT INTO permissions (id, name, resource, action, created_at) 
			VALUES (?, ?, ?, ?, ?)`, "perm2", "uniqueperm", "users", "write", now)
		assert.Error(t, err, "Should fail with duplicate permission name")
	})
}

// TestDefaultValues verifies that default values are set correctly
func TestDefaultValues(t *testing.T) {
	db, err := NewDatabase(":memory:")
	require.NoError(t, err)
	defer db.Close()

	now := time.Now().Unix()

	t.Run("user default values", func(t *testing.T) {
		// Insert user without optional fields
		_, err := db.db.Exec(`INSERT INTO users (id, username, email, password_hash, created_at, updated_at) 
			VALUES (?, ?, ?, ?, ?, ?)`, "testuser", "defaultuser", "default@example.com", "hash", now, now)
		require.NoError(t, err)

		// Retrieve and check defaults
		var totpEnabled, active bool
		var failedAttempts int
		err = db.db.QueryRow(`SELECT totp_enabled, active, failed_login_attempts FROM users WHERE id = ?`,
			"testuser").Scan(&totpEnabled, &active, &failedAttempts)
		require.NoError(t, err)

		assert.False(t, totpEnabled, "totp_enabled should default to false")
		assert.True(t, active, "active should default to true")
		assert.Equal(t, 0, failedAttempts, "failed_login_attempts should default to 0")
	})

	t.Run("group default values", func(t *testing.T) {
		// Insert group without optional fields
		_, err := db.db.Exec(`INSERT INTO groups (id, name, created_at, updated_at) 
			VALUES (?, ?, ?, ?)`, "testgroup", "defaultgroup", now, now)
		require.NoError(t, err)

		// Retrieve and check defaults
		var active bool
		err = db.db.QueryRow(`SELECT active FROM groups WHERE id = ?`, "testgroup").Scan(&active)
		require.NoError(t, err)

		assert.True(t, active, "active should default to true")
	})

	t.Run("permission default values", func(t *testing.T) {
		// Insert permission without optional fields
		_, err := db.db.Exec(`INSERT INTO permissions (id, name, resource, action, created_at) 
			VALUES (?, ?, ?, ?, ?)`, "testperm", "defaultperm", "sms", "read", now)
		require.NoError(t, err)

		// Retrieve and check defaults
		var active bool
		err = db.db.QueryRow(`SELECT active FROM permissions WHERE id = ?`, "testperm").Scan(&active)
		require.NoError(t, err)

		assert.True(t, active, "active should default to true")
	})
}

// TestSeedDatabase tests the database seeding functionality
func TestSeedDatabase(t *testing.T) {
	t.Run("successful seeding", func(t *testing.T) {
		db, err := NewDatabase(":memory:")
		require.NoError(t, err)
		defer db.Close()

		// Seed the database
		err = db.SeedDatabase("testpassword123")
		require.NoError(t, err)

		// Verify admin user was created
		var username, email, passwordHash string
		var active bool
		err = db.db.QueryRow(`
			SELECT username, email, password_hash, active 
			FROM users WHERE username = ?`, "admin").
			Scan(&username, &email, &passwordHash, &active)
		require.NoError(t, err)
		assert.Equal(t, "admin", username)
		assert.Equal(t, "admin@localhost", email)
		assert.True(t, active)

		// Verify password is properly hashed
		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("testpassword123"))
		assert.NoError(t, err, "password should be correctly hashed")

		// Verify 8 permissions were created
		var permCount int
		err = db.db.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&permCount)
		require.NoError(t, err)
		assert.Equal(t, 8, permCount, "should create 8 permissions")

		// Verify specific permissions exist
		expectedPerms := []string{"sms:read", "sms:write", "sms:delete", "users:read", "users:write", "users:delete", "groups:manage", "permissions:manage"}
		for _, permName := range expectedPerms {
			var exists int
			err = db.db.QueryRow("SELECT COUNT(*) FROM permissions WHERE name = ?", permName).Scan(&exists)
			require.NoError(t, err)
			assert.Equal(t, 1, exists, "permission %s should exist", permName)
		}

		// Verify 2 groups were created
		var groupCount int
		err = db.db.QueryRow("SELECT COUNT(*) FROM groups").Scan(&groupCount)
		require.NoError(t, err)
		assert.Equal(t, 2, groupCount, "should create 2 groups")

		// Verify Administrators group has all 8 permissions
		var adminGroupPerms int
		err = db.db.QueryRow(`
			SELECT COUNT(*) FROM group_permissions gp
			JOIN groups g ON g.id = gp.group_id
			WHERE g.name = ?`, "Administrators").Scan(&adminGroupPerms)
		require.NoError(t, err)
		assert.Equal(t, 8, adminGroupPerms, "Administrators group should have all 8 permissions")

		// Verify Users group has 2 permissions (sms:read, sms:write)
		var usersGroupPerms int
		err = db.db.QueryRow(`
			SELECT COUNT(*) FROM group_permissions gp
			JOIN groups g ON g.id = gp.group_id
			WHERE g.name = ?`, "Users").Scan(&usersGroupPerms)
		require.NoError(t, err)
		assert.Equal(t, 2, usersGroupPerms, "Users group should have 2 permissions")

		// Verify admin user is assigned to Administrators group
		var userGroups int
		err = db.db.QueryRow(`
			SELECT COUNT(*) FROM user_groups ug
			JOIN users u ON u.id = ug.user_id
			JOIN groups g ON g.id = ug.group_id
			WHERE u.username = ? AND g.name = ?`, "admin", "Administrators").Scan(&userGroups)
		require.NoError(t, err)
		assert.Equal(t, 1, userGroups, "admin should be in Administrators group")
	})

	t.Run("idempotent seeding - skips if users exist", func(t *testing.T) {
		db, err := NewDatabase(":memory:")
		require.NoError(t, err)
		defer db.Close()

		// First seed
		err = db.SeedDatabase("password1")
		require.NoError(t, err)

		// Count users and permissions after first seed
		var userCount1, permCount1 int
		db.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount1)
		db.db.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&permCount1)

		// Second seed should skip
		err = db.SeedDatabase("password2")
		require.NoError(t, err)

		// Counts should be the same
		var userCount2, permCount2 int
		db.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount2)
		db.db.QueryRow("SELECT COUNT(*) FROM permissions").Scan(&permCount2)

		assert.Equal(t, userCount1, userCount2, "user count should not change on second seed")
		assert.Equal(t, permCount1, permCount2, "permission count should not change on second seed")

		// Verify password is from first seed, not second
		var passwordHash string
		err = db.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", "admin").Scan(&passwordHash)
		require.NoError(t, err)

		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("password1"))
		assert.NoError(t, err, "password should still be from first seed")

		err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("password2"))
		assert.Error(t, err, "password should not match second seed attempt")
	})

	t.Run("seeding with empty password", func(t *testing.T) {
		db, err := NewDatabase(":memory:")
		require.NoError(t, err)
		defer db.Close()

		// Empty password should still work (bcrypt will hash it)
		err = db.SeedDatabase("")
		require.NoError(t, err)

		// Verify admin user exists
		var username string
		err = db.db.QueryRow("SELECT username FROM users WHERE username = ?", "admin").Scan(&username)
		require.NoError(t, err)
		assert.Equal(t, "admin", username)
	})

	t.Run("verify all permission details", func(t *testing.T) {
		db, err := NewDatabase(":memory:")
		require.NoError(t, err)
		defer db.Close()

		err = db.SeedDatabase("testpass")
		require.NoError(t, err)

		// Verify each permission has correct resource and action
		tests := []struct {
			name     string
			resource string
			action   string
		}{
			{"sms:read", "sms", "read"},
			{"sms:write", "sms", "write"},
			{"sms:delete", "sms", "delete"},
			{"users:read", "users", "read"},
			{"users:write", "users", "write"},
			{"users:delete", "users", "delete"},
			{"groups:manage", "groups", "manage"},
			{"permissions:manage", "permissions", "manage"},
		}

		for _, tt := range tests {
			var resource, action string
			var active bool
			err = db.db.QueryRow(`
				SELECT resource, action, active FROM permissions WHERE name = ?`, tt.name).
				Scan(&resource, &action, &active)
			require.NoError(t, err, "permission %s should exist", tt.name)
			assert.Equal(t, tt.resource, resource, "permission %s resource mismatch", tt.name)
			assert.Equal(t, tt.action, action, "permission %s action mismatch", tt.name)
			assert.True(t, active, "permission %s should be active", tt.name)
		}
	})

	t.Run("verify group details", func(t *testing.T) {
		db, err := NewDatabase(":memory:")
		require.NoError(t, err)
		defer db.Close()

		err = db.SeedDatabase("testpass")
		require.NoError(t, err)

		// Verify Administrators group
		var adminDesc string
		var adminActive bool
		err = db.db.QueryRow(`
			SELECT description, active FROM groups WHERE name = ?`, "Administrators").
			Scan(&adminDesc, &adminActive)
		require.NoError(t, err)
		assert.Equal(t, "Full system access", adminDesc)
		assert.True(t, adminActive)

		// Verify Users group
		var usersDesc string
		var usersActive bool
		err = db.db.QueryRow(`
			SELECT description, active FROM groups WHERE name = ?`, "Users").
			Scan(&usersDesc, &usersActive)
		require.NoError(t, err)
		assert.Equal(t, "Basic SMS access", usersDesc)
		assert.True(t, usersActive)
	})
}
