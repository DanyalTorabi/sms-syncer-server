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
