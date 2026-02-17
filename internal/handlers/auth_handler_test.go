package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/models"
	"sms-sync-server/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func setupTestAuthHandler() (*gin.Engine, *AuthHandler, *MockUserService) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	cfg := &config.Config{}
	cfg.JWT.Secret = "test-secret"
	cfg.JWT.TokenExpiry = 1 * time.Hour

	mockService := new(MockUserService)
	handler := NewAuthHandler(cfg, mockService)

	return r, handler, mockService
}

func TestNewAuthHandler(t *testing.T) {
	cfg := &config.Config{}
	cfg.JWT.Secret = "test-secret"
	mockService := new(MockUserService)
	handler := NewAuthHandler(cfg, mockService)

	assert.NotNil(t, handler)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, mockService, handler.userService)
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    LoginRequest
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name: "valid credentials without TOTP",
			requestBody: LoginRequest{
				Username: "testuser",
				Password: "testpass",
			},
			mockSetup: func(m *MockUserService) {
				user := &models.User{
					ID:       "user-123",
					Username: "testuser",
					Email:    "test@example.com",
				}
				userWithPerms := &models.User{
					ID:       "user-123",
					Username: "testuser",
					Email:    "test@example.com",
					Permissions: []models.Permission{
						{ID: "perm-1", Name: "sms:read"},
						{ID: "perm-2", Name: "sms:write"},
					},
				}
				m.On("Authenticate", "testuser", "testpass", "").Return(user, nil)
				m.On("GetUserWithPermissions", "user-123").Return(userWithPerms, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.NotEmpty(t, resp["token"])
				assert.Equal(t, "user-123", resp["user_id"])
				assert.Equal(t, "testuser", resp["username"])
			},
		},
		{
			name: "valid credentials with TOTP",
			requestBody: LoginRequest{
				Username: "testuser",
				Password: "testpass",
				TOTPCode: "123456",
			},
			mockSetup: func(m *MockUserService) {
				user := &models.User{
					ID:       "user-123",
					Username: "testuser",
					Email:    "test@example.com",
				}
				userWithPerms := &models.User{
					ID:          "user-123",
					Username:    "testuser",
					Email:       "test@example.com",
					Permissions: []models.Permission{},
				}
				m.On("Authenticate", "testuser", "testpass", "123456").Return(user, nil)
				m.On("GetUserWithPermissions", "user-123").Return(userWithPerms, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.NotEmpty(t, resp["token"])
			},
		},
		{
			name: "invalid credentials",
			requestBody: LoginRequest{
				Username: "wronguser",
				Password: "wrongpass",
			},
			mockSetup: func(m *MockUserService) {
				m.On("Authenticate", "wronguser", "wrongpass", "").Return(nil, services.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "Invalid credentials", resp["error"])
			},
		},
		{
			name: "account locked",
			requestBody: LoginRequest{
				Username: "lockeduser",
				Password: "testpass",
			},
			mockSetup: func(m *MockUserService) {
				m.On("Authenticate", "lockeduser", "testpass", "").Return(nil, services.ErrAccountLocked)
			},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "locked")
			},
		},
		{
			name: "missing username",
			requestBody: LoginRequest{
				Password: "testpass",
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "Username and password are required", resp["error"])
			},
		},
		{
			name: "missing password",
			requestBody: LoginRequest{
				Username: "testuser",
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "Username and password are required", resp["error"])
			},
		},
		{
			name:           "empty request",
			requestBody:    LoginRequest{},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "Username and password are required", resp["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, handler, mockService := setupTestAuthHandler()
			r.POST("/login", handler.Login)
			tt.mockSetup(mockService)

			body, err := json.Marshal(tt.requestBody)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			tt.checkResponse(t, response)
			mockService.AssertExpectations(t)
		})
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	r, handler, _ := setupTestAuthHandler()
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

func TestLoginJWTClaims(t *testing.T) {
	r, handler, mockService := setupTestAuthHandler()
	r.POST("/login", handler.Login)

	// Setup mock
	user := &models.User{
		ID:       "user-123",
		Username: "testuser",
		Email:    "test@example.com",
	}
	userWithPerms := &models.User{
		ID:       "user-123",
		Username: "testuser",
		Email:    "test@example.com",
		Permissions: []models.Permission{
			{ID: "perm-1", Name: "sms:read", Resource: "sms", Action: "read"},
			{ID: "perm-2", Name: "sms:write", Resource: "sms", Action: "write"},
		},
	}
	mockService.On("Authenticate", "testuser", "testpass", "").Return(user, nil)
	mockService.On("GetUserWithPermissions", "user-123").Return(userWithPerms, nil)

	// Make request
	requestBody := LoginRequest{Username: "testuser", Password: "testpass"}
	body, _ := json.Marshal(requestBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response["token"])

	// Parse and verify JWT token
	tokenString := response["token"].(string)
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	// Verify claims
	claims, ok := token.Claims.(*Claims)
	assert.True(t, ok)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "testuser", claims.Username)
	assert.Len(t, claims.Permissions, 2)
	assert.Contains(t, claims.Permissions, "perm-1")
	assert.Contains(t, claims.Permissions, "perm-2")

	// Verify token expiry is approximately 1 hour from now
	expectedExpiry := time.Now().Add(1 * time.Hour)
	actualExpiry := claims.ExpiresAt.Time
	timeDiff := actualExpiry.Sub(expectedExpiry)
	assert.Less(t, timeDiff.Abs(), 5*time.Second) // Allow 5 second tolerance

	mockService.AssertExpectations(t)
}
