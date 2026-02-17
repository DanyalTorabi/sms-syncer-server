package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sms-sync-server/internal/models"
	"sms-sync-server/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestChangePassword(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		userID          string
		authenticatedID string
		requestBody     map[string]string
		setupMock       func(*MockUserService)
		expectedStatus  int
		expectedError   string
	}{
		{
			name:            "successful password change",
			userID:          "user-123",
			authenticatedID: "user-123",
			requestBody: map[string]string{
				"old_password": "oldpass123",
				"new_password": "newpass123",
			},
			setupMock: func(m *MockUserService) {
				m.On("ChangePassword", "user-123", "oldpass123", "newpass123").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:            "incorrect old password",
			userID:          "user-123",
			authenticatedID: "user-123",
			requestBody: map[string]string{
				"old_password": "wrongpass",
				"new_password": "newpass123",
			},
			setupMock: func(m *MockUserService) {
				m.On("ChangePassword", "user-123", "wrongpass", "newpass123").
					Return(services.ErrIncorrectOldPassword)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "incorrect old password",
		},
		{
			name:            "weak new password",
			userID:          "user-123",
			authenticatedID: "user-123",
			requestBody: map[string]string{
				"old_password": "oldpass123",
				"new_password": "weak",
			},
			setupMock: func(m *MockUserService) {
				m.On("ChangePassword", "user-123", "oldpass123", "weak").
					Return(services.ErrInvalidPassword)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "password must be at least 8 characters",
		},
		{
			name:            "attempt to change another user's password",
			userID:          "user-456",
			authenticatedID: "user-123",
			requestBody: map[string]string{
				"old_password": "oldpass123",
				"new_password": "newpass123",
			},
			setupMock:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Cannot change another user's password",
		},
		{
			name:            "missing old password",
			userID:          "user-123",
			authenticatedID: "user-123",
			requestBody: map[string]string{
				"new_password": "newpass123",
			},
			setupMock:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request format",
		},
		{
			name:            "missing new password",
			userID:          "user-123",
			authenticatedID: "user-123",
			requestBody: map[string]string{
				"old_password": "oldpass123",
			},
			setupMock:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request format",
		},
		{
			name:            "user not found",
			userID:          "nonexistent",
			authenticatedID: "nonexistent",
			requestBody: map[string]string{
				"old_password": "oldpass123",
				"new_password": "newpass123",
			},
			setupMock: func(m *MockUserService) {
				m.On("ChangePassword", "nonexistent", "oldpass123", "newpass123").
					Return(services.ErrUserNotFound)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := new(MockUserService)
			tt.setupMock(mockService)
			handler := NewUserHandler(mockService)

			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/users/"+tt.userID+"/password", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Setup gin context
			router := gin.New()
			router.POST("/api/users/:id/password", func(c *gin.Context) {
				// Simulate auth middleware setting userID
				c.Set("userID", tt.authenticatedID)
				handler.ChangePassword(c)
			})

			// Execute
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				var response map[string]string
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], tt.expectedError)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAdminResetPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name            string
		userID          string
		authenticatedID string
		requestBody     map[string]string
		setupMock       func(*MockUserService)
		expectedStatus  int
		expectedError   string
	}{
		{
			name:            "successful admin password reset",
			userID:          "user-123",
			authenticatedID: "admin-456",
			requestBody: map[string]string{
				"new_password": "newpass123",
			},
			setupMock: func(m *MockUserService) {
				m.On("GetUser", "user-123").Return(&models.User{
					ID:       "user-123",
					Username: "testuser",
					Active:   true,
				}, nil)
				m.On("AdminSetPassword", "user-123", "newpass123").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:            "user not found",
			userID:          "nonexistent",
			authenticatedID: "admin-456",
			requestBody: map[string]string{
				"new_password": "newpass123",
			},
			setupMock: func(m *MockUserService) {
				m.On("GetUser", "nonexistent").Return(nil, services.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "User not found",
		},
		{
			name:            "weak new password",
			userID:          "user-123",
			authenticatedID: "admin-456",
			requestBody: map[string]string{
				"new_password": "weak",
			},
			setupMock:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Password must be at least 8 characters",
		},
		{
			name:            "missing new password",
			userID:          "user-123",
			authenticatedID: "admin-456",
			requestBody:     map[string]string{},
			setupMock:       func(m *MockUserService) {},
			expectedStatus:  http.StatusBadRequest,
			expectedError:   "Invalid request format",
		},
		{
			name:            "password reset failure",
			userID:          "user-123",
			authenticatedID: "admin-456",
			requestBody: map[string]string{
				"new_password": "newpass123",
			},
			setupMock: func(m *MockUserService) {
				m.On("GetUser", "user-123").Return(&models.User{
					ID:       "user-123",
					Username: "testuser",
					Active:   true,
				}, nil)
				m.On("AdminSetPassword", "user-123", "newpass123").
					Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to reset password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := new(MockUserService)
			tt.setupMock(mockService)
			handler := NewUserHandler(mockService)

			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+tt.userID+"/password/reset", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Setup gin context
			router := gin.New()
			router.POST("/api/admin/users/:id/password/reset", func(c *gin.Context) {
				// Simulate auth middleware setting userID
				c.Set("userID", tt.authenticatedID)
				handler.AdminResetPassword(c)
			})

			// Execute
			router.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				var response map[string]string
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], tt.expectedError)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAdminSetPassword_Service(t *testing.T) {
	// This test verifies the service layer AdminSetPassword method exists
	// The actual service tests are in internal/services/user_service_test.go
	// This is just a smoke test to ensure the interface is satisfied
	mockService := new(MockUserService)
	mockService.On("AdminSetPassword", "user-123", "newpass123").Return(nil)

	err := mockService.AdminSetPassword("user-123", "newpass123")
	assert.NoError(t, err)
	mockService.AssertExpectations(t)
}
