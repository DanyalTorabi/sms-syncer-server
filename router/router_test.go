package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"sms-sync-server/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	// Test adding a message
	msg := &db.SMSMessage{
		UserID:         "test-user",
		PhoneNumber:    "1234567890",
		Body:           "Test message",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	mockDB.On("AddMessage", matchMessage(msg)).Return(nil)

	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/sms/add", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Test getting messages
	expectedMessages := []*db.SMSMessage{msg}
	mockDB.On("GetMessages", "test-user", 100, 0).Return(expectedMessages, nil)

	req = httptest.NewRequest(http.MethodGet, "/api/sms/get?user_id=test-user", nil)
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	var messages []*db.SMSMessage
	if err := json.NewDecoder(w.Body).Decode(&messages); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if len(messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(messages))
	}

	if len(messages) > 0 && messages[0].Body != "Test message" {
		t.Errorf("Expected message body 'Test message', got '%s'", messages[0].Body)
	}

	// Test invalid method
	req = httptest.NewRequest(http.MethodGet, "/api/sms/add", nil)
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}

	// Test missing user_id
	req = httptest.NewRequest(http.MethodGet, "/api/sms/get", nil)
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, w.Code)
	}

	// Test invalid JSON
	req = httptest.NewRequest(http.MethodPost, "/api/sms/add", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestAddMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	tests := []struct {
		name           string
		message        *db.SMSMessage
		mockError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "Valid message",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender1",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Empty body",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender1",
				Body:           "",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"message body is required"}`,
		},
		{
			name: "Missing user ID",
			message: &db.SMSMessage{
				PhoneNumber:    "sender1",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"User ID is required"}`,
		},
		{
			name: "Database error",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender1",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			mockError:      errors.New("database error"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"Failed to save message"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.ExpectedCalls = nil // Reset mock expectations

			if tt.mockError != nil {
				mockDB.On("AddMessage", matchMessage(tt.message)).Return(tt.mockError)
			} else if tt.expectedStatus == http.StatusOK {
				mockDB.On("AddMessage", matchMessage(tt.message)).Return(nil)
			}

			body, _ := json.Marshal(tt.message)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestGetMessages(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	tests := []struct {
		name           string
		userID         string
		limit          string
		offset         string
		mockMessages   []*db.SMSMessage
		mockError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:   "Valid request",
			userID: "123",
			limit:  "10",
			offset: "0",
			mockMessages: []*db.SMSMessage{
				{
					UserID:         "123",
					PhoneNumber:    "sender1",
					Body:           "test message 1",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Unix(),
					EventTimestamp: time.Now().Unix(),
				},
				{
					UserID:         "123",
					PhoneNumber:    "sender2",
					Body:           "test message 2",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Unix(),
					EventTimestamp: time.Now().Unix(),
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid limit",
			userID:         "123",
			limit:          "invalid",
			offset:         "0",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"Invalid limit value"}`,
		},
		{
			name:           "Invalid offset",
			userID:         "123",
			limit:          "10",
			offset:         "invalid",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"Invalid offset value"}`,
		},
		{
			name:           "Database error",
			userID:         "123",
			limit:          "10",
			offset:         "0",
			mockError:      errors.New("database error"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"Failed to get messages"}`,
		},
		{
			name:           "Empty messages list",
			userID:         "123",
			limit:          "10",
			offset:         "0",
			mockMessages:   []*db.SMSMessage{},
			expectedStatus: http.StatusOK,
			expectedBody:   `[]`,
		},
		{
			name:   "Large limit value",
			userID: "123",
			limit:  "1000",
			offset: "0",
			mockMessages: []*db.SMSMessage{
				{
					UserID:         "123",
					PhoneNumber:    "sender1",
					Body:           "test message",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Unix(),
					EventTimestamp: time.Now().Unix(),
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Large offset value",
			userID:         "123",
			limit:          "10",
			offset:         "1000",
			mockMessages:   []*db.SMSMessage{},
			expectedStatus: http.StatusOK,
			expectedBody:   `[]`,
		},
		{
			name:   "Special characters in userID",
			userID: "user@123!",
			limit:  "10",
			offset: "0",
			mockMessages: []*db.SMSMessage{
				{
					UserID:         "user@123!",
					PhoneNumber:    "sender1",
					Body:           "test message",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Unix(),
					EventTimestamp: time.Now().Unix(),
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Multiple pages of messages",
			userID: "123",
			limit:  "2",
			offset: "1",
			mockMessages: []*db.SMSMessage{
				{
					UserID:         "123",
					PhoneNumber:    "sender2",
					Body:           "test message 2",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Unix(),
					EventTimestamp: time.Now().Unix(),
				},
				{
					UserID:         "123",
					PhoneNumber:    "sender3",
					Body:           "test message 3",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Unix(),
					EventTimestamp: time.Now().Unix(),
				},
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Messages with different timestamps",
			userID: "123",
			limit:  "10",
			offset: "0",
			mockMessages: []*db.SMSMessage{
				{
					UserID:         "123",
					PhoneNumber:    "sender1",
					Body:           "old message",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Add(-24 * time.Hour).Unix(),
					EventTimestamp: time.Now().Unix(),
				},
				{
					UserID:         "123",
					PhoneNumber:    "sender2",
					Body:           "new message",
					EventType:      "RECEIVED",
					SmsTimestamp:   time.Now().Unix(),
					EventTimestamp: time.Now().Unix(),
				},
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB.ExpectedCalls = nil // Reset mock expectations

			if tt.mockError != nil {
				limit, _ := strconv.Atoi(tt.limit)
				offset, _ := strconv.Atoi(tt.offset)
				mockDB.On("GetMessages", tt.userID, limit, offset).Return(nil, tt.mockError)
			} else if tt.mockMessages != nil {
				limit, _ := strconv.Atoi(tt.limit)
				offset, _ := strconv.Atoi(tt.offset)
				mockDB.On("GetMessages", tt.userID, limit, offset).Return(tt.mockMessages, nil)
			}

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", fmt.Sprintf("/api/sms/get?user_id=%s&limit=%s&offset=%s", tt.userID, tt.limit, tt.offset), nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestHealth(t *testing.T) {
	mockDB := &MockDatabase{}
	router := NewRouter(mockDB)

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		queryParams    map[string]string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Basic health check",
			method:         http.MethodGet,
			path:           "/health",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with trailing slash",
			method:         http.MethodGet,
			path:           "/health/",
			expectedStatus: http.StatusMovedPermanently,
		},
		{
			name:           "Health check with query parameters",
			method:         http.MethodGet,
			path:           "/health",
			queryParams:    map[string]string{"check": "true"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with custom headers",
			method:         http.MethodGet,
			path:           "/health",
			headers:        map[string]string{"X-Custom-Header": "test"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with invalid content type",
			method:         http.MethodGet,
			path:           "/health",
			headers:        map[string]string{"Content-Type": "invalid"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with multiple query parameters",
			method:         http.MethodGet,
			path:           "/health",
			queryParams:    map[string]string{"check": "true", "debug": "1"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with special characters in query",
			method:         http.MethodGet,
			path:           "/health",
			queryParams:    map[string]string{"param": "test@123!"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with empty query parameters",
			method:         http.MethodGet,
			path:           "/health",
			queryParams:    map[string]string{"": ""},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with multiple headers",
			method:         http.MethodGet,
			path:           "/health",
			headers:        map[string]string{"X-Header1": "value1", "X-Header2": "value2"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Health check with empty headers",
			method:         http.MethodGet,
			path:           "/health",
			headers:        map[string]string{"": ""},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)

			// Add query parameters
			if tt.queryParams != nil {
				q := req.URL.Query()
				for k, v := range tt.queryParams {
					q.Add(k, v)
				}
				req.URL.RawQuery = q.Encode()
			}

			// Add headers
			if tt.headers != nil {
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
			}

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	mockDB := &MockDatabase{}
	router := NewRouter(mockDB)

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		queryParams    map[string]string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Basic not found",
			method:         http.MethodGet,
			path:           "/nonexistent",
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with trailing slash",
			method:         http.MethodGet,
			path:           "/nonexistent/",
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with query parameters",
			method:         http.MethodGet,
			path:           "/nonexistent",
			queryParams:    map[string]string{"param": "value"},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with custom headers",
			method:         http.MethodGet,
			path:           "/nonexistent",
			headers:        map[string]string{"X-Custom-Header": "test"},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with invalid content type",
			method:         http.MethodGet,
			path:           "/nonexistent",
			headers:        map[string]string{"Content-Type": "invalid"},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with multiple query parameters",
			method:         http.MethodGet,
			path:           "/nonexistent",
			queryParams:    map[string]string{"param1": "value1", "param2": "value2"},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with special characters in path",
			method:         http.MethodGet,
			path:           "/nonexistent@123!",
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with empty query parameters",
			method:         http.MethodGet,
			path:           "/nonexistent",
			queryParams:    map[string]string{"": ""},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with multiple headers",
			method:         http.MethodGet,
			path:           "/nonexistent",
			headers:        map[string]string{"X-Header1": "value1", "X-Header2": "value2"},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "Not found with empty headers",
			method:         http.MethodGet,
			path:           "/nonexistent",
			headers:        map[string]string{"": ""},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)

			// Add query parameters
			if tt.queryParams != nil {
				q := req.URL.Query()
				for k, v := range tt.queryParams {
					q.Add(k, v)
				}
				req.URL.RawQuery = q.Encode()
			}

			// Add headers
			if tt.headers != nil {
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
			}

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestMethodNotAllowed(t *testing.T) {
	mockDB := &MockDatabase{}
	router := NewRouter(mockDB)

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		queryParams    map[string]string
		expectedStatus int
		expectedBody   string
	}{
		{"GET /api/sms/add", http.MethodGet, "/api/sms/add", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"PUT /api/sms/add", http.MethodPut, "/api/sms/add", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"DELETE /api/sms/add", http.MethodDelete, "/api/sms/add", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"POST /api/sms/get", http.MethodPost, "/api/sms/get", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"PUT /api/sms/get", http.MethodPut, "/api/sms/get", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"DELETE /api/sms/get", http.MethodDelete, "/api/sms/get", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"PATCH /api/sms/add", http.MethodPatch, "/api/sms/add", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"HEAD /api/sms/add", http.MethodHead, "/api/sms/add", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"OPTIONS /api/sms/add", http.MethodOptions, "/api/sms/add", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
		{"CONNECT /api/sms/add", http.MethodConnect, "/api/sms/add", nil, nil, http.StatusMethodNotAllowed, `{"error":"Method not allowed"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)

			// Add query parameters
			if tt.queryParams != nil {
				q := req.URL.Query()
				for k, v := range tt.queryParams {
					q.Add(k, v)
				}
				req.URL.RawQuery = q.Encode()
			}

			// Add headers
			if tt.headers != nil {
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
			}

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestNewRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)

	tests := []struct {
		name          string
		database      Database
		expectedError bool
		verifyRoutes  bool
	}{
		{
			name:          "Valid database",
			database:      mockDB,
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Nil database",
			database:      nil,
			expectedError: true,
			verifyRoutes:  false,
		},
		{
			name:          "Empty database implementation",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Database with error methods",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Database with custom implementation",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Database with invalid methods",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Database with timeout methods",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Database with concurrent access",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Database with large data",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
		{
			name:          "Database with special characters",
			database:      &MockDatabase{},
			expectedError: false,
			verifyRoutes:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectedError {
				assert.Panics(t, func() {
					NewRouter(tt.database)
				})
				return
			}

			router := NewRouter(tt.database)
			assert.NotNil(t, router)
			assert.NotNil(t, router.engine)
			assert.Equal(t, tt.database, router.database)

			if tt.verifyRoutes {
				// Test health endpoint
				w := httptest.NewRecorder()
				req, _ := http.NewRequest(http.MethodGet, "/health", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code)

				// Test SMS add endpoint with invalid content type
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodPost, "/api/sms/add", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusUnsupportedMediaType, w.Code)

				// Test SMS get endpoint without user ID
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodGet, "/api/sms/get", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusBadRequest, w.Code)

				// Test method not allowed for SMS add
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodPut, "/api/sms/add", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

				// Test method not allowed for SMS get
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodPost, "/api/sms/get", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

				// Test not found handler
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodGet, "/nonexistent", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusNotFound, w.Code)

				// Test trailing slash redirect
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodGet, "/health/", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusMovedPermanently, w.Code)

				// Test with query parameters
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodGet, "/health?check=true", nil)
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code)

				// Test with headers
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodGet, "/health", nil)
				req.Header.Set("X-Custom-Header", "test")
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code)

				// Test with invalid content type
				w = httptest.NewRecorder()
				req, _ = http.NewRequest(http.MethodGet, "/health", nil)
				req.Header.Set("Content-Type", "invalid")
				router.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code)
			}
		})
	}
}

func TestValidateMessage(t *testing.T) {
	mockDB := &MockDatabase{}
	router := NewRouter(mockDB)

	tests := []struct {
		name          string
		message       *db.SMSMessage
		expectedError string
	}{
		{
			name: "Valid message",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender1",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "",
		},
		{
			name: "Missing UserID",
			message: &db.SMSMessage{
				PhoneNumber:    "sender1",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "User ID is required",
		},
		{
			name: "Missing PhoneNumber",
			message: &db.SMSMessage{
				UserID:         "123",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "phone number is required",
		},
		{
			name: "Empty body",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender1",
				Body:           "",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "message body is required",
		},
		{
			name: "Empty UserID",
			message: &db.SMSMessage{
				UserID:         "",
				PhoneNumber:    "sender1",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "User ID is required",
		},
		{
			name: "Empty PhoneNumber",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "phone number is required",
		},
		{
			name: "Missing EventType",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender1",
				Body:           "test message",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "event type is required",
		},
		{
			name: "Special characters in UserID",
			message: &db.SMSMessage{
				UserID:         "user@123!",
				PhoneNumber:    "sender1",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "",
		},
		{
			name: "Special characters in PhoneNumber",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender@123!",
				Body:           "test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "",
		},
		{
			name: "Long message body",
			message: &db.SMSMessage{
				UserID:         "123",
				PhoneNumber:    "sender1",
				Body:           strings.Repeat("a", 1000),
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := router.validateMessage(tt.message)
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedError)
			}
		})
	}
}
