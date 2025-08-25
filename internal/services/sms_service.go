package services

import (
	"fmt"
	"time"

	"sms-sync-server/internal/db"
)

// SMSService handles SMS message operations
type SMSService struct {
	db db.DatabaseInterface
}

// NewSMSService creates a new SMS service
func NewSMSService(db db.DatabaseInterface) *SMSService {
	return &SMSService{db: db}
}

// AddMessage adds a new SMS message
func (s *SMSService) AddMessage(msg *db.SMSMessage) error {
	if err := s.validateMessage(msg); err != nil {
		return err
	}

	return s.db.AddMessage(msg)
}

// GetMessages retrieves messages for a user with pagination
func (s *SMSService) GetMessages(userID string, limit, offset int) ([]*db.SMSMessage, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	if limit <= 0 {
		limit = 100 // default limit
	}

	if offset < 0 {
		offset = 0
	}

	return s.db.GetMessages(userID, limit, offset)
}

// validateMessage validates the SMS message fields
func (s *SMSService) validateMessage(msg *db.SMSMessage) error {
	if msg.UserID == "" {
		return fmt.Errorf("user ID is required")
	}

	if msg.PhoneNumber == "" {
		return fmt.Errorf("phone number is required")
	}

	if msg.Body == "" {
		return fmt.Errorf("message body is required")
	}

	if msg.EventType == "" {
		return fmt.Errorf("event type is required")
	}

	if msg.SmsTimestamp == 0 {
		return fmt.Errorf("SMS timestamp is required")
	}

	if msg.EventTimestamp == 0 {
		msg.EventTimestamp = time.Now().Unix()
	}

	return nil
}
