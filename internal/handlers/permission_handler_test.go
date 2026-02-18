package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"sms-sync-server/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockPermissionService is a mock implementation of PermissionServiceInterface
type MockPermissionService struct {
	mock.Mock
}

func (m *MockPermissionService) CreatePermission(name, resource, action, description string) (*models.Permission, error) {
	args := m.Called(name, resource, action, description)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *MockPermissionService) GetPermission(id string) (*models.Permission, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Permission), args.Error(1)
}

func (m *MockPermissionService) UpdatePermission(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockPermissionService) DeletePermission(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockPermissionService) ListPermissions(limit, offset int) ([]*models.Permission, error) {
	args := m.Called(limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Permission), args.Error(1)
}

// TestPermissionHandler_CreatePermission tests the CreatePermission handler
func TestPermissionHandler_CreatePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		permissions    []string
		mockSetup      func(*MockPermissionService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name: "successful creation",
			requestBody: map[string]interface{}{
				"name":        "users:read",
				"resource":    "users",
				"action":      "read",
				"description": "Read user data",
			},
			permissions: []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				perm := &models.Permission{
					ID:          "perm-1",
					Name:        "users:read",
					Resource:    "users",
					Action:      "read",
					Description: "Read user data",
					Active:      true,
					CreatedAt:   1692864000,
				}
				m.On("CreatePermission", "users:read", "users", "read", "Read user data").Return(perm, nil)
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "perm-1", resp["id"])
				assert.Equal(t, "users:read", resp["name"])
			},
		},
		{
			name: "missing permission",
			requestBody: map[string]interface{}{
				"name":     "users:read",
				"resource": "users",
				"action":   "read",
			},
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockPermissionService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Insufficient permissions")
			},
		},
		{
			name: "invalid request format",
			requestBody: map[string]interface{}{
				"name": 123, // Invalid type
			},
			permissions:    []string{"permissions:write"},
			mockSetup:      func(m *MockPermissionService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid request format")
			},
		},
		{
			name: "permission already exists",
			requestBody: map[string]interface{}{
				"name":     "users:read",
				"resource": "users",
				"action":   "read",
			},
			permissions: []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("CreatePermission", "users:read", "users", "read", "").Return(nil, errors.New("permission already exists"))
			},
			expectedStatus: http.StatusConflict,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "already exists")
			},
		},
		{
			name: "invalid permission name format",
			requestBody: map[string]interface{}{
				"name":     "invalid_format",
				"resource": "users",
				"action":   "read",
			},
			permissions: []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("CreatePermission", "invalid_format", "users", "read", "").Return(nil, errors.New("permission name must match format resource:action"))
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "must match")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockPermissionService)
			tt.mockSetup(mockService)

			handler := NewPermissionHandler(mockService)

			router := gin.New()
			router.POST("/permissions", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.CreatePermission(c)
			})

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/permissions", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &response)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestPermissionHandler_ListPermissions tests the ListPermissions handler
func TestPermissionHandler_ListPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		queryParams    string
		permissions    []string
		mockSetup      func(*MockPermissionService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:        "successful list with defaults",
			queryParams: "",
			permissions: []string{"permissions:read"},
			mockSetup: func(m *MockPermissionService) {
				perms := []*models.Permission{
					{ID: "perm-1", Name: "users:read", Resource: "users", Action: "read", Active: true},
					{ID: "perm-2", Name: "users:write", Resource: "users", Action: "write", Active: true},
				}
				m.On("ListPermissions", 50, 0).Return(perms, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				perms := resp["permissions"].([]interface{})
				assert.Len(t, perms, 2)
				assert.Equal(t, float64(50), resp["limit"])
				assert.Equal(t, float64(0), resp["offset"])
			},
		},
		{
			name:        "successful list with pagination",
			queryParams: "?limit=10&offset=20",
			permissions: []string{"permissions:read"},
			mockSetup: func(m *MockPermissionService) {
				perms := []*models.Permission{
					{ID: "perm-3", Name: "groups:read", Resource: "groups", Action: "read", Active: true},
				}
				m.On("ListPermissions", 10, 20).Return(perms, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				perms := resp["permissions"].([]interface{})
				assert.Len(t, perms, 1)
			},
		},
		{
			name:           "missing permission",
			queryParams:    "",
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockPermissionService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Insufficient permissions")
			},
		},
		{
			name:        "service error",
			queryParams: "",
			permissions: []string{"permissions:read"},
			mockSetup: func(m *MockPermissionService) {
				m.On("ListPermissions", 50, 0).Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to list permissions")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockPermissionService)
			tt.mockSetup(mockService)

			handler := NewPermissionHandler(mockService)

			router := gin.New()
			router.GET("/permissions", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.ListPermissions(c)
			})

			req := httptest.NewRequest(http.MethodGet, "/permissions"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &response)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestPermissionHandler_GetPermissionByID tests the GetPermissionByID handler
func TestPermissionHandler_GetPermissionByID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		permissionID   string
		permissions    []string
		mockSetup      func(*MockPermissionService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:         "successful retrieval",
			permissionID: "perm-1",
			permissions:  []string{"permissions:read"},
			mockSetup: func(m *MockPermissionService) {
				perm := &models.Permission{
					ID:          "perm-1",
					Name:        "users:read",
					Resource:    "users",
					Action:      "read",
					Description: "Read user data",
					Active:      true,
				}
				m.On("GetPermission", "perm-1").Return(perm, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "perm-1", resp["id"])
				assert.Equal(t, "users:read", resp["name"])
			},
		},
		{
			name:           "missing permission",
			permissionID:   "perm-1",
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockPermissionService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Insufficient permissions")
			},
		},
		{
			name:         "permission not found",
			permissionID: "nonexistent",
			permissions:  []string{"permissions:read"},
			mockSetup: func(m *MockPermissionService) {
				m.On("GetPermission", "nonexistent").Return(nil, errors.New("permission not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Permission not found")
			},
		},
		{
			name:         "service error",
			permissionID: "perm-1",
			permissions:  []string{"permissions:read"},
			mockSetup: func(m *MockPermissionService) {
				m.On("GetPermission", "perm-1").Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to retrieve permission")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockPermissionService)
			tt.mockSetup(mockService)

			handler := NewPermissionHandler(mockService)

			router := gin.New()
			router.GET("/permissions/:id", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.GetPermissionByID(c)
			})

			req := httptest.NewRequest(http.MethodGet, "/permissions/"+tt.permissionID, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &response)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestPermissionHandler_UpdatePermission tests the UpdatePermission handler
func TestPermissionHandler_UpdatePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		permissionID   string
		requestBody    map[string]interface{}
		permissions    []string
		mockSetup      func(*MockPermissionService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:         "successful update description",
			permissionID: "perm-1",
			requestBody: map[string]interface{}{
				"description": "Updated description",
			},
			permissions: []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("UpdatePermission", "perm-1", mock.MatchedBy(func(updates map[string]interface{}) bool {
					return updates["description"] == "Updated description"
				})).Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "updated successfully")
			},
		},
		{
			name:         "successful update active status",
			permissionID: "perm-1",
			requestBody: map[string]interface{}{
				"active": false,
			},
			permissions: []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("UpdatePermission", "perm-1", mock.MatchedBy(func(updates map[string]interface{}) bool {
					return updates["active"] == false
				})).Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "updated successfully")
			},
		},
		{
			name:         "missing permission",
			permissionID: "perm-1",
			requestBody: map[string]interface{}{
				"description": "Updated",
			},
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockPermissionService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Insufficient permissions")
			},
		},
		{
			name:           "no fields to update",
			permissionID:   "perm-1",
			requestBody:    map[string]interface{}{},
			permissions:    []string{"permissions:write"},
			mockSetup:      func(m *MockPermissionService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "No valid fields to update")
			},
		},
		{
			name:         "permission not found",
			permissionID: "nonexistent",
			requestBody: map[string]interface{}{
				"description": "Updated",
			},
			permissions: []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("UpdatePermission", "nonexistent", mock.Anything).Return(errors.New("permission not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Permission not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockPermissionService)
			tt.mockSetup(mockService)

			handler := NewPermissionHandler(mockService)

			router := gin.New()
			router.PUT("/permissions/:id", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.UpdatePermission(c)
			})

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPut, "/permissions/"+tt.permissionID, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &response)
			tt.checkResponse(t, response)

			mockService.AssertExpectations(t)
		})
	}
}

// TestPermissionHandler_DeletePermission tests the DeletePermission handler
func TestPermissionHandler_DeletePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		permissionID   string
		permissions    []string
		mockSetup      func(*MockPermissionService)
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:         "successful deletion",
			permissionID: "perm-1",
			permissions:  []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("DeletePermission", "perm-1").Return(nil)
			},
			expectedStatus: http.StatusNoContent,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Empty(t, w.Body.String())
			},
		},
		{
			name:           "missing permission",
			permissionID:   "perm-1",
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockPermissionService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], "Insufficient permissions")
			},
		},
		{
			name:         "permission not found",
			permissionID: "nonexistent",
			permissions:  []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("DeletePermission", "nonexistent").Return(errors.New("permission not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], "Permission not found")
			},
		},
		{
			name:         "permission in use by groups",
			permissionID: "perm-1",
			permissions:  []string{"permissions:write"},
			mockSetup: func(m *MockPermissionService) {
				m.On("DeletePermission", "perm-1").Return(errors.New("permission is in use by groups"))
			},
			expectedStatus: http.StatusConflict,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], "in use")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockPermissionService)
			tt.mockSetup(mockService)

			handler := NewPermissionHandler(mockService)

			router := gin.New()
			router.DELETE("/permissions/:id", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.DeletePermission(c)
			})

			req := httptest.NewRequest(http.MethodDelete, "/permissions/"+tt.permissionID, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			tt.checkResponse(t, w)

			mockService.AssertExpectations(t)
		})
	}
}
