package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"sms-sync-server/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTestAuthHandler() (*gin.Engine, *AuthHandler) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	cfg := &config.Config{}
	cfg.JWT.Secret = "test-secret"
	handler := NewAuthHandler(cfg)

	return r, handler
}

func TestNewAuthHandler(t *testing.T) {
	cfg := &config.Config{}
	cfg.JWT.Secret = "test-secret"
	handler := NewAuthHandler(cfg)

	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
}

func TestLogin(t *testing.T) {
	r, handler := setupTestAuthHandler()
	r.POST("/login", handler.Login)

	tests := []struct {
		name           string
		requestBody    LoginRequest
		expectedStatus int
		expectedBody   map[string]string
	}{
		{
			name: "valid credentials",
			requestBody: LoginRequest{
				Username: "testuser",
				Password: "testpass",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]string{"token": ""},
		},
		{
			name: "invalid credentials",
			requestBody: LoginRequest{
				Username: "wronguser",
				Password: "wrongpass",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   map[string]string{"error": "Invalid credentials"},
		},
		{
			name: "missing username",
			requestBody: LoginRequest{
				Password: "testpass",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "Username and password are required"},
		},
		{
			name: "missing password",
			requestBody: LoginRequest{
				Username: "testuser",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "Username and password are required"},
		},
		{
			name:           "empty request",
			requestBody:    LoginRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]string{"error": "Username and password are required"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]string
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			if tt.expectedStatus == http.StatusOK {
				// For successful login, just check that a token is present
				assert.NotEmpty(t, response["token"])
			} else {
				assert.Equal(t, tt.expectedBody, response)
			}
		})
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	r, handler := setupTestAuthHandler()
	r.POST("/login", handler.Login)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Invalid request format", response["error"])
}
