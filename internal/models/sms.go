package models

import "time"

// SMSMessage represents an SMS message in the system
// Updated to match the new DB schema
// All fields are exported for JSON and DB use

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

type SMS struct {
	UUID       string    `json:"uuid"`
	Sender     string    `json:"sender"`
	Message    string    `json:"message"`
	Timestamp  time.Time `json:"timestamp"`
	RetryCount int       `json:"retryCount"`
}
