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

// TODO(#102): Clean up permission test cases that verify handler-level permission checks
// After PR #101, permission validation moved to middleware layer (pkg/middleware/auth_test.go).
// Test cases checking for "missing permission" or "insufficient permissions" errors should be
// removed from handler tests since handlers no longer perform these checks.

// TestUserHandler_ListUsers tests the ListUsers handler
func TestUserHandler_ListUsers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		queryParams    string
		userID         string
		permissions    []string
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:        "successful list with defaults",
			queryParams: "",
			userID:      "user-123",
			permissions: []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				users := []*models.User{
					{ID: "user-1", Username: "user1", Email: "user1@example.com", Active: true},
					{ID: "user-2", Username: "user2", Email: "user2@example.com", Active: true},
				}
				m.On("ListUsers", 50, 0).Return(users, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				users := resp["users"].([]interface{})
				assert.Len(t, users, 2)
			},
		},
		{
			name:        "successful list with pagination",
			queryParams: "?limit=10&offset=20",
			userID:      "user-123",
			permissions: []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				users := []*models.User{
					{ID: "user-3", Username: "user3", Email: "user3@example.com", Active: true},
				}
				m.On("ListUsers", 10, 20).Return(users, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				users := resp["users"].([]interface{})
				assert.Len(t, users, 1)
			},
		},
		{
			name:           "unauthorized - missing permission",
			queryParams:    "",
			userID:         "user-123",
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "permission")
			},
		},
		{
			name:        "service error",
			queryParams: "",
			userID:      "user-123",
			permissions: []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				m.On("ListUsers", 50, 0).Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to list users")
			},
		},
		{
			name:           "invalid pagination parameters",
			queryParams:    "?limit=invalid",
			userID:         "user-123",
			permissions:    []string{"users:read"},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid limit")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.mockSetup(mockService)

			handler := NewUserHandler(mockService)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/api/users"+tt.queryParams, nil)
			c.Set("user_id", tt.userID)
			c.Set("permissions", tt.permissions)

			handler.ListUsers(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestUserHandler_GetUserByID tests the GetUserByID handler
func TestUserHandler_GetUserByID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		targetUserID   string
		currentUserID  string
		permissions    []string
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:          "successful get own profile",
			targetUserID:  "user-123",
			currentUserID: "user-123",
			permissions:   []string{},
			mockSetup: func(m *MockUserService) {
				user := &models.User{
					ID:       "user-123",
					Username: "testuser",
					Email:    "test@example.com",
					Active:   true,
					Groups: []models.Group{
						{ID: "group-1", Name: "Users"},
					},
				}
				m.On("GetUserWithPermissions", "user-123").Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "user-123", resp["id"])
				assert.Equal(t, "testuser", resp["username"])
				assert.NotNil(t, resp["groups"])
			},
		},
		{
			name:          "successful get other user with permission",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				user := &models.User{
					ID:       "user-456",
					Username: "otheruser",
					Email:    "other@example.com",
					Active:   true,
					Groups:   []models.Group{},
				}
				m.On("GetUserWithPermissions", "user-456").Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "user-456", resp["id"])
			},
		},
		{
			name:           "forbidden - accessing other user without permission",
			targetUserID:   "user-456",
			currentUserID:  "user-123",
			permissions:    []string{},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "permission")
			},
		},
		{
			name:          "user not found",
			targetUserID:  "nonexistent",
			currentUserID: "user-123",
			permissions:   []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				m.On("GetUserWithPermissions", "nonexistent").Return(nil, services.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "User not found")
			},
		},
		{
			name:          "service error",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				m.On("GetUserWithPermissions", "user-456").Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to get user")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.mockSetup(mockService)

			handler := NewUserHandler(mockService)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/api/users/"+tt.targetUserID, nil)
			c.Params = gin.Params{{Key: "id", Value: tt.targetUserID}}
			c.Set("user_id", tt.currentUserID)
			c.Set("permissions", tt.permissions)

			handler.GetUserByID(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestUserHandler_UpdateUserByID tests the UpdateUserByID handler
func TestUserHandler_UpdateUserByID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		targetUserID   string
		currentUserID  string
		permissions    []string
		requestBody    interface{}
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:          "self update email successfully",
			targetUserID:  "user-123",
			currentUserID: "user-123",
			permissions:   []string{},
			requestBody: map[string]interface{}{
				"email": "newemail@example.com",
			},
			mockSetup: func(m *MockUserService) {
				updates := map[string]interface{}{"email": "newemail@example.com"}
				m.On("UpdateUser", "user-123", updates).Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "successfully")
			},
		},
		{
			name:          "admin update user email and active status",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			requestBody: map[string]interface{}{
				"email":  "admin@example.com",
				"active": false,
			},
			mockSetup: func(m *MockUserService) {
				user := &models.User{ID: "user-456", Username: "otheruser"}
				m.On("GetUser", "user-456").Return(user, nil)
				updates := map[string]interface{}{"email": "admin@example.com", "active": false}
				m.On("UpdateUser", "user-456", updates).Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "successfully")
			},
		},
		{
			name:          "prevent deactivating admin user",
			targetUserID:  "admin-user",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			requestBody: map[string]interface{}{
				"active": false,
			},
			mockSetup: func(m *MockUserService) {
				user := &models.User{ID: "admin-user", Username: "admin"}
				m.On("GetUser", "admin-user").Return(user, nil)
			},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Cannot deactivate")
			},
		},
		{
			name:          "self trying to update active status",
			targetUserID:  "user-123",
			currentUserID: "user-123",
			permissions:   []string{},
			requestBody: map[string]interface{}{
				"active": false,
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "change active status")
			},
		},
		{
			name:           "forbidden - updating other user without permission",
			targetUserID:   "user-456",
			currentUserID:  "user-123",
			permissions:    []string{},
			requestBody:    map[string]interface{}{"email": "test@example.com"},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "permission")
			},
		},
		{
			name:           "invalid request body",
			targetUserID:   "user-123",
			currentUserID:  "user-123",
			permissions:    []string{},
			requestBody:    "invalid json",
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid request")
			},
		},
		{
			name:          "user not found",
			targetUserID:  "nonexistent",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			requestBody:   map[string]interface{}{"email": "test@example.com"},
			mockSetup: func(m *MockUserService) {
				m.On("GetUser", "nonexistent").Return(nil, services.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "User not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.mockSetup(mockService)

			handler := NewUserHandler(mockService)

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("PUT", "/api/users/"+tt.targetUserID, bytes.NewBuffer(body))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Params = gin.Params{{Key: "id", Value: tt.targetUserID}}
			c.Set("user_id", tt.currentUserID)
			c.Set("permissions", tt.permissions)

			handler.UpdateUserByID(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestUserHandler_DeleteUserByID tests the DeleteUserByID handler
func TestUserHandler_DeleteUserByID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		targetUserID   string
		currentUserID  string
		permissions    []string
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:          "successful delete user",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				user := &models.User{ID: "user-456", Username: "testuser"}
				m.On("GetUser", "user-456").Return(user, nil)
				updates := map[string]interface{}{"active": false}
				m.On("UpdateUser", "user-456", updates).Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "deleted successfully")
			},
		},
		{
			name:          "prevent deleting admin user",
			targetUserID:  "admin-user",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				user := &models.User{ID: "admin-user", Username: "admin"}
				m.On("GetUser", "admin-user").Return(user, nil)
			},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Cannot delete")
			},
		},
		{
			name:           "unauthorized - missing permission",
			targetUserID:   "user-456",
			currentUserID:  "user-123",
			permissions:    []string{},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "permission")
			},
		},
		{
			name:          "user not found",
			targetUserID:  "nonexistent",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				m.On("GetUser", "nonexistent").Return(nil, services.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "User not found")
			},
		},
		{
			name:          "service error during delete",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				user := &models.User{ID: "user-456", Username: "testuser"}
				m.On("GetUser", "user-456").Return(user, nil)
				updates := map[string]interface{}{"active": false}
				m.On("UpdateUser", "user-456", updates).Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to delete user")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.mockSetup(mockService)

			handler := NewUserHandler(mockService)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("DELETE", "/api/users/"+tt.targetUserID, nil)
			c.Params = gin.Params{{Key: "id", Value: tt.targetUserID}}
			c.Set("user_id", tt.currentUserID)
			c.Set("permissions", tt.permissions)

			handler.DeleteUserByID(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestUserHandler_AssignUserToGroup tests the AssignUserToGroup handler
func TestUserHandler_AssignUserToGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		targetUserID   string
		currentUserID  string
		permissions    []string
		requestBody    interface{}
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:          "successful group assignment",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			requestBody: models.AssignGroupRequest{
				GroupID: "group-789",
			},
			mockSetup: func(m *MockUserService) {
				m.On("AssignToGroup", "user-456", "group-789").Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "assigned")
			},
		},
		{
			name:          "unauthorized - missing permission",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{},
			requestBody: models.AssignGroupRequest{
				GroupID: "group-789",
			},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "permission")
			},
		},
		{
			name:           "invalid request body",
			targetUserID:   "user-456",
			currentUserID:  "user-123",
			permissions:    []string{"users:write"},
			requestBody:    "invalid json",
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid request")
			},
		},
		{
			name:          "service error",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			requestBody: models.AssignGroupRequest{
				GroupID: "group-789",
			},
			mockSetup: func(m *MockUserService) {
				m.On("AssignToGroup", "user-456", "group-789").Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to assign user to group")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.mockSetup(mockService)

			handler := NewUserHandler(mockService)

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/api/users/"+tt.targetUserID+"/groups", bytes.NewBuffer(body))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Params = gin.Params{{Key: "id", Value: tt.targetUserID}}
			c.Set("user_id", tt.currentUserID)
			c.Set("permissions", tt.permissions)

			handler.AssignUserToGroup(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestUserHandler_RemoveUserFromGroup tests the RemoveUserFromGroup handler
func TestUserHandler_RemoveUserFromGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		targetUserID   string
		groupID        string
		currentUserID  string
		permissions    []string
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:          "successful group removal",
			targetUserID:  "user-456",
			groupID:       "group-789",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				user := &models.User{ID: "user-456", Username: "testuser"}
				m.On("GetUser", "user-456").Return(user, nil)
				m.On("RemoveFromGroup", "user-456", "group-789").Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "removed")
			},
		},
		{
			name:          "prevent removing admin from admin group",
			targetUserID:  "admin-user",
			groupID:       "admin-group",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				adminUser := &models.User{
					ID:       "admin-user",
					Username: "admin",
					Groups: []models.Group{
						{ID: "admin-group", Name: "admin"},
					},
				}
				m.On("GetUser", "admin-user").Return(adminUser, nil)
			},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Cannot remove admin user")
			},
		},
		{
			name:           "unauthorized - missing permission",
			targetUserID:   "user-456",
			groupID:        "group-789",
			currentUserID:  "user-123",
			permissions:    []string{},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "permission")
			},
		},
		{
			name:          "user not found",
			targetUserID:  "nonexistent",
			groupID:       "group-789",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				m.On("GetUser", "nonexistent").Return(nil, services.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "User not found")
			},
		},
		{
			name:          "service error",
			targetUserID:  "user-456",
			groupID:       "group-789",
			currentUserID: "user-123",
			permissions:   []string{"users:write"},
			mockSetup: func(m *MockUserService) {
				user := &models.User{ID: "user-456", Username: "testuser"}
				m.On("GetUser", "user-456").Return(user, nil)
				m.On("RemoveFromGroup", "user-456", "group-789").Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to remove user from group")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.mockSetup(mockService)

			handler := NewUserHandler(mockService)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("DELETE", "/api/users/"+tt.targetUserID+"/groups/"+tt.groupID, nil)
			c.Params = gin.Params{
				{Key: "id", Value: tt.targetUserID},
				{Key: "groupId", Value: tt.groupID},
			}
			c.Set("user_id", tt.currentUserID)
			c.Set("permissions", tt.permissions)

			handler.RemoveUserFromGroup(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestUserHandler_ListUserGroups tests the ListUserGroups handler
func TestUserHandler_ListUserGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		targetUserID   string
		currentUserID  string
		permissions    []string
		mockSetup      func(*MockUserService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:          "successful list own groups",
			targetUserID:  "user-123",
			currentUserID: "user-123",
			permissions:   []string{},
			mockSetup: func(m *MockUserService) {
				user := &models.User{
					ID:       "user-123",
					Username: "testuser",
					Groups: []models.Group{
						{ID: "group-1", Name: "Users"},
						{ID: "group-2", Name: "Developers"},
					},
				}
				m.On("GetUserWithPermissions", "user-123").Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				groups := resp["groups"].([]interface{})
				assert.Len(t, groups, 2)
			},
		},
		{
			name:          "successful list other user groups with permission",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				user := &models.User{
					ID:       "user-456",
					Username: "otheruser",
					Groups: []models.Group{
						{ID: "group-1", Name: "Users"},
					},
				}
				m.On("GetUserWithPermissions", "user-456").Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				groups := resp["groups"].([]interface{})
				assert.Len(t, groups, 1)
			},
		},
		{
			name:           "unauthorized - accessing other user without permission",
			targetUserID:   "user-456",
			currentUserID:  "user-123",
			permissions:    []string{},
			mockSetup:      func(m *MockUserService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "permission")
			},
		},
		{
			name:          "user not found",
			targetUserID:  "nonexistent",
			currentUserID: "user-123",
			permissions:   []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				m.On("GetUserWithPermissions", "nonexistent").Return(nil, services.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "User not found")
			},
		},
		{
			name:          "service error",
			targetUserID:  "user-456",
			currentUserID: "user-123",
			permissions:   []string{"users:read"},
			mockSetup: func(m *MockUserService) {
				m.On("GetUserWithPermissions", "user-456").Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to list user groups")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockUserService)
			tt.mockSetup(mockService)

			handler := NewUserHandler(mockService)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/api/users/"+tt.targetUserID+"/groups", nil)
			c.Params = gin.Params{{Key: "id", Value: tt.targetUserID}}
			c.Set("user_id", tt.currentUserID)
			c.Set("permissions", tt.permissions)

			handler.ListUserGroups(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}
