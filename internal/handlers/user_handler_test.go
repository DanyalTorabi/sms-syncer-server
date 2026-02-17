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
	"github.com/stretchr/testify/mock"
)

// MockUserService is a mock implementation of UserServiceInterface for testing
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) CreateUser(username, email, password string) (*models.User, error) {
	args := m.Called(username, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) Authenticate(username, password, totpCode string) (*models.User, error) {
	args := m.Called(username, password, totpCode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetUserWithPermissions(userID string) (*models.User, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetUser(id string) (*models.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockUserService) DeleteUser(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserService) ChangePassword(id, oldPassword, newPassword string) error {
	args := m.Called(id, oldPassword, newPassword)
	return args.Error(0)
}

func (m *MockUserService) AdminSetPassword(id, newPassword string) error {
	args := m.Called(id, newPassword)
	return args.Error(0)
}

func (m *MockUserService) ListUsers(limit, offset int) ([]*models.User, error) {
	args := m.Called(limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.User), args.Error(1)
}

func (m *MockUserService) AssignToGroup(userID, groupID string) error {
	args := m.Called(userID, groupID)
	return args.Error(0)
}

func (m *MockUserService) RemoveFromGroup(userID, groupID string) error {
	args := m.Called(userID, groupID)
	return args.Error(0)
}

func (m *MockUserService) GenerateTOTPSecret(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *MockUserService) EnableTOTP(userID, totpCode string) error {
	args := m.Called(userID, totpCode)
	return args.Error(0)
}

func (m *MockUserService) DisableTOTP(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func TestNewUserHandler(t *testing.T) {
	mockService := new(MockUserService)
	handler := NewUserHandler(mockService)

	assert.NotNil(t, handler)
	assert.Equal(t, mockService, handler.userService)
}

func TestUserHandler_Register(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name: "successful registration",
			requestBody: models.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "SecurePass123!",
			},
			mockSetup: func(m *MockUserService) {
				user := &models.User{
					ID:        "user-123",
					Username:  "testuser",
					Email:     "test@example.com",
					Active:    true,
					CreatedAt: 1609459200,
				}
				m.On("CreateUser", "testuser", "test@example.com", "SecurePass123!").Return(user, nil)
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "user-123", resp["id"])
				assert.Equal(t, "testuser", resp["username"])
				assert.Equal(t, "test@example.com", resp["email"])
				assert.Equal(t, true, resp["active"])
			},
		},
		{
			name: "missing username",
			requestBody: map[string]interface{}{
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Username is required")
			},
		},
		{
			name: "missing email",
			requestBody: map[string]interface{}{
				"username": "testuser",
				"password": "SecurePass123!",
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Email is required")
			},
		},
		{
			name: "missing password",
			requestBody: map[string]interface{}{
				"username": "testuser",
				"email":    "test@example.com",
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Password is required")
			},
		},
		{
			name: "invalid request format",
			requestBody: map[string]interface{}{
				"username": 12345, // Invalid type
				"email":    "test@example.com",
				"password": "SecurePass123!",
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				// Gin binding will fail with invalid type, checks username field is empty
				assert.Contains(t, resp["error"], "required")
			},
		},
		{
			name: "duplicate username",
			requestBody: models.CreateUserRequest{
				Username: "existinguser",
				Email:    "test@example.com",
				Password: "SecurePass123!",
			},
			mockSetup: func(m *MockUserService) {
				m.On("CreateUser", "existinguser", "test@example.com", "SecurePass123!").
					Return(nil, errors.New("username already exists"))
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "username already exists")
			},
		},
		{
			name: "weak password",
			requestBody: models.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "weak",
			},
			mockSetup: func(m *MockUserService) {
				m.On("CreateUser", "testuser", "test@example.com", "weak").
					Return(nil, services.ErrInvalidPassword)
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "password")
			},
		},
		{
			name: "invalid email format",
			requestBody: models.CreateUserRequest{
				Username: "testuser",
				Email:    "invalid-email",
				Password: "SecurePass123!",
			},
			mockSetup: func(m *MockUserService) {
				m.On("CreateUser", "testuser", "invalid-email", "SecurePass123!").
					Return(nil, services.ErrInvalidEmail)
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "email")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			mockService := new(MockUserService)
			tt.mockSetup(mockService)
			handler := NewUserHandler(mockService)

			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Create gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Execute
			handler.Register(c)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			tt.checkResponse(t, response)
			mockService.AssertExpectations(t)
		})
	}
}

func TestUserHandler_Register_EmptyFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		username       string
		email          string
		password       string
		expectedError  string
		expectedStatus int
	}{
		{
			name:           "empty username",
			username:       "",
			email:          "test@example.com",
			password:       "SecurePass123!",
			expectedError:  "Username is required",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "empty email",
			username:       "testuser",
			email:          "",
			password:       "SecurePass123!",
			expectedError:  "Email is required",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "empty password",
			username:       "testuser",
			email:          "test@example.com",
			password:       "",
			expectedError:  "Password is required",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			handler := NewUserHandler(mockService)

			requestBody := models.CreateUserRequest{
				Username: tt.username,
				Email:    tt.email,
				Password: tt.password,
			}

			body, _ := json.Marshal(requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)
			c.Request = req

			handler.Register(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Contains(t, response["error"], tt.expectedError)
		})
	}
}
