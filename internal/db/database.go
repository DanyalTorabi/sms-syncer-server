package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "github.com/mattn/go-sqlite3"
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
	return err
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
		"INSERT INTO messages (user_id, smsId, smsTimestamp, eventTimestamp, phoneNumber, body, eventType, threadId, dateSent, person) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
		"SELECT id, user_id, smsId, smsTimestamp, eventTimestamp, phoneNumber, body, eventType, threadId, dateSent, person FROM messages WHERE user_id = ? ORDER BY eventTimestamp DESC LIMIT ? OFFSET ?",
		userID,
		limit,
		offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*SMSMessage
	for rows.Next() {
		msg := &SMSMessage{}
		err := rows.Scan(&msg.ID, &msg.UserID, &msg.SmsID, &msg.SmsTimestamp, &msg.EventTimestamp, &msg.PhoneNumber, &msg.Body, &msg.EventType, &msg.ThreadID, &msg.DateSent, &msg.Person)
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
