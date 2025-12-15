package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sms-sync-server/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestAddSMSMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	validMessage := &db.SMSMessage{
		UserID:         "test-user",
		PhoneNumber:    "+15551234567",
		Body:           "test message",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	tests := []struct {
		name           string
		message        *db.SMSMessage
		method         string
		contentType    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid SMS message",
			message:        validMessage,
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"success"}`,
		},
		{
			name: "Empty message body",
			message: &db.SMSMessage{
				UserID:         "test-user",
				PhoneNumber:    "+15551234567",
				Body:           "",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"message body is required"}`,
		},
		{
			name: "Missing user ID",
			message: &db.SMSMessage{
				PhoneNumber:    "+15551234567",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"user ID is required"}`,
		},
		{
			name: "Missing required fields",
			message: &db.SMSMessage{
				UserID: "test-user",
			},
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"phone number is required"}`,
		},
		{
			name:           "Invalid method",
			message:        validMessage,
			method:         http.MethodGet,
			contentType:    "application/json",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   `{"error":"method not allowed"}`,
		},
		{
			name:           "Invalid content type",
			message:        validMessage,
			method:         http.MethodPost,
			contentType:    "text/plain",
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedBody:   `{"error":"unsupported media type"}`,
		},
		{
			name: "Missing phone number",
			message: &db.SMSMessage{
				UserID:         "test-user",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"phone number is required"}`,
		},
		{
			name:           "Invalid JSON",
			message:        nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid request body"}`,
		},
		{
			name:           "Empty request body",
			message:        nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid request body"}`,
		},
		{
			name: "Auto-populated timestamps",
			message: &db.SMSMessage{
				UserID:       "test-user",
				PhoneNumber:  "+15551234567",
				Body:         "test message",
				EventType:    "RECEIVED",
				SmsTimestamp: time.Now().Unix(),
			},
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"success"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.ExpectedCalls = nil // Reset mock expectations

			if tt.message != nil && tt.expectedStatus == http.StatusOK {
				mockDB.On("AddMessage", matchMessage(tt.message)).Return(nil)
			}

			var body []byte
			if tt.message != nil {
				body, _ = json.Marshal(tt.message)
			} else {
				body = []byte("invalid json")
			}

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, "/api/sms/add", bytes.NewBuffer(body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestGetSMSMessages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	testMessages := []*db.SMSMessage{
		{
			UserID:         "test-user",
			PhoneNumber:    "+15551234567",
			Body:           "message1",
			EventType:      "RECEIVED",
			SmsTimestamp:   time.Now().Unix(),
			EventTimestamp: time.Now().Unix(),
		},
		{
			UserID:         "test-user",
			PhoneNumber:    "+15557654321",
			Body:           "message2",
			EventType:      "RECEIVED",
			SmsTimestamp:   time.Now().Unix(),
			EventTimestamp: time.Now().Unix(),
		},
	}

	tests := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
		expectedBody   string
		setupMock      func()
	}{
		{
			name:           "Valid request",
			path:           "/api/sms/get?user_id=test-user&limit=10&offset=0",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
			setupMock: func() {
				mockDB.On("GetMessages", "test-user", 10, 0).Return(testMessages, nil)
			},
		},
		{
			name:           "Missing user ID",
			path:           "/api/sms/get",
			method:         http.MethodGet,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"user ID is required"}`,
			setupMock:      func() {},
		},
		{
			name:           "Invalid limit",
			path:           "/api/sms/get?user_id=test-user&limit=-1",
			method:         http.MethodGet,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid limit value"}`,
			setupMock:      func() {},
		},
		{
			name:           "Invalid offset",
			path:           "/api/sms/get?user_id=test-user&limit=10&offset=-1",
			method:         http.MethodGet,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid offset value"}`,
			setupMock:      func() {},
		},
		{
			name:           "Invalid method",
			path:           "/api/sms/get?user_id=test-user",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   `{"error":"method not allowed"}`,
			setupMock:      func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.ExpectedCalls = nil // Reset mock expectations
			tt.setupMock()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}
