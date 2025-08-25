package services

import (
	"testing"
	"time"

	"sms-sync-server/internal/db"
)

type mockDatabase struct {
	addMessageFunc  func(*db.SMSMessage) error
	getMessagesFunc func(string, int, int) ([]*db.SMSMessage, error)
}

func (m *mockDatabase) Close() error {
	return nil
}

func (m *mockDatabase) AddMessage(msg *db.SMSMessage) error {
	return m.addMessageFunc(msg)
}

func (m *mockDatabase) GetMessages(userID string, limit, offset int) ([]*db.SMSMessage, error) {
	return m.getMessagesFunc(userID, limit, offset)
}

func TestNewSMSService(t *testing.T) {
	mockDB := &mockDatabase{}
	service := NewSMSService(mockDB)
	if service == nil {
		t.Error("Expected service to be created, got nil")
	}
}

func TestAddMessage(t *testing.T) {
	tests := []struct {
		name    string
		msg     *db.SMSMessage
		wantErr bool
	}{
		{
			name: "valid message",
			msg: &db.SMSMessage{
				UserID:         "user1",
				PhoneNumber:    "1234567890",
				Body:           "Hello",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			wantErr: false,
		},
		{
			name: "missing user ID",
			msg: &db.SMSMessage{
				PhoneNumber:    "1234567890",
				Body:           "Hello",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			wantErr: true,
		},
		{
			name: "missing phone number",
			msg: &db.SMSMessage{
				UserID:         "user1",
				Body:           "Hello",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			wantErr: true,
		},
		{
			name: "missing body",
			msg: &db.SMSMessage{
				UserID:         "user1",
				PhoneNumber:    "1234567890",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := &mockDatabase{
				addMessageFunc: func(msg *db.SMSMessage) error {
					return nil
				},
			}
			service := NewSMSService(mockDB)

			err := service.AddMessage(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetMessages(t *testing.T) {
	testMsg := &db.SMSMessage{
		UserID:         "user1",
		PhoneNumber:    "1234567890",
		Body:           "Hello",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	tests := []struct {
		name      string
		userID    string
		limit     int
		offset    int
		wantErr   bool
		mockMsgs  []*db.SMSMessage
		mockError error
	}{
		{
			name:     "valid request",
			userID:   "user1",
			limit:    10,
			offset:   0,
			mockMsgs: []*db.SMSMessage{testMsg},
			wantErr:  false,
		},
		{
			name:    "missing user ID",
			userID:  "",
			limit:   10,
			offset:  0,
			wantErr: true,
		},
		{
			name:     "negative limit",
			userID:   "user1",
			limit:    -1,
			offset:   0,
			mockMsgs: []*db.SMSMessage{testMsg},
			wantErr:  false,
		},
		{
			name:     "negative offset",
			userID:   "user1",
			limit:    10,
			offset:   -1,
			mockMsgs: []*db.SMSMessage{testMsg},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := &mockDatabase{
				getMessagesFunc: func(userID string, limit, offset int) ([]*db.SMSMessage, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockMsgs, nil
				},
			}
			service := NewSMSService(mockDB)

			msgs, err := service.GetMessages(tt.userID, tt.limit, tt.offset)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetMessages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(msgs) == 0 && tt.mockMsgs != nil {
				t.Error("GetMessages() returned no messages, expected at least one")
			}
		})
	}
}
