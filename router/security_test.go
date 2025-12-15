package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sms-sync-server/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"), "X-Request-ID should be present")
}

func TestStrictPhoneValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	tests := []struct {
		name        string
		phoneNumber string
		wantError   bool
	}{
		{"Valid E.164", "+14155552671", false},
		{"Valid No Plus", "14155552671", false},
		{"Too Short", "123", true},
		{"Letters", "12345abcde", true},
		{"Too Long", "1234567890123456", true}, // > 15 digits
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &db.SMSMessage{
				UserID:         "test-user",
				PhoneNumber:    tt.phoneNumber,
				Body:           "Test message",
				EventType:      "RECEIVED",
				SmsTimestamp:   time.Now().Unix(),
				EventTimestamp: time.Now().Unix(),
			}

			if !tt.wantError {
				mockDB.On("AddMessage", matchMessage(msg)).Return(nil).Once()
			}

			body, _ := json.Marshal(msg)
			req := httptest.NewRequest(http.MethodPost, "/api/sms/add", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if tt.wantError {
				assert.Equal(t, http.StatusBadRequest, w.Code)
				assert.Contains(t, w.Body.String(), "invalid phone number format")
			} else {
				assert.Equal(t, http.StatusOK, w.Code)
			}
		})
	}
}

func TestMessageBodySizeLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	largeBody := strings.Repeat("a", 2049) // 2049 characters
	msg := &db.SMSMessage{
		UserID:         "test-user",
		PhoneNumber:    "+15551234567",
		Body:           largeBody,
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	body, _ := json.Marshal(msg)
	req := httptest.NewRequest(http.MethodPost, "/api/sms/add", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "message body too large")
}

func TestCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockDB := new(MockDatabase)
	router := NewRouter(mockDB)

	req := httptest.NewRequest(http.MethodOptions, "/api/sms/add", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
}
