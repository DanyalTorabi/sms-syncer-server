package router

import (
	"sms-sync-server/internal/db"

	"github.com/stretchr/testify/mock"
)

type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) AddMessage(msg *db.SMSMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func (m *MockDatabase) GetMessages(userID string, limit, offset int) ([]*db.SMSMessage, error) {
	args := m.Called(userID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*db.SMSMessage), args.Error(1)
}

// matchMessage is a custom matcher for comparing SMSMessage objects
func matchMessage(expected *db.SMSMessage) interface{} {
	return mock.MatchedBy(func(actual *db.SMSMessage) bool {
		return actual.UserID == expected.UserID &&
			actual.PhoneNumber == expected.PhoneNumber &&
			actual.Body == expected.Body &&
			actual.EventType == expected.EventType
	})
}
