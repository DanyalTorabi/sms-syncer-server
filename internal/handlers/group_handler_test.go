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

// MockGroupService is a mock implementation of GroupServiceInterface
type MockGroupService struct {
	mock.Mock
}

func (m *MockGroupService) CreateGroup(name, description string) (*models.Group, error) {
	args := m.Called(name, description)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockGroupService) GetGroup(id string) (*models.Group, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Group), args.Error(1)
}

func (m *MockGroupService) UpdateGroup(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockGroupService) DeleteGroup(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockGroupService) ListGroups(limit, offset int) ([]*models.Group, error) {
	args := m.Called(limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Group), args.Error(1)
}

func (m *MockGroupService) AddPermission(groupID, permissionID string) error {
	args := m.Called(groupID, permissionID)
	return args.Error(0)
}

func (m *MockGroupService) RemovePermission(groupID, permissionID string) error {
	args := m.Called(groupID, permissionID)
	return args.Error(0)
}

// TestGroupHandler_CreateGroup tests the CreateGroup handler
func TestGroupHandler_CreateGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		permissions    []string
		mockSetup      func(*MockGroupService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name: "successful creation",
			requestBody: map[string]interface{}{
				"name":        "Developers",
				"description": "Development team",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				group := &models.Group{
					ID:          "group-1",
					Name:        "Developers",
					Description: "Development team",
					Active:      true,
					CreatedAt:   1692864000,
					UpdatedAt:   1692864000,
				}
				m.On("CreateGroup", "Developers", "Development team").Return(group, nil)
			},
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "group-1", resp["id"])
				assert.Equal(t, "Developers", resp["name"])
			},
		},
		{
			name: "missing permission",
			requestBody: map[string]interface{}{
				"name": "Developers",
			},
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockGroupService) {},
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
			permissions:    []string{"groups:write"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Invalid request format")
			},
		},
		{
			name: "group already exists",
			requestBody: map[string]interface{}{
				"name": "Developers",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("CreateGroup", "Developers", "").Return(nil, errors.New("group already exists"))
			},
			expectedStatus: http.StatusConflict,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "already exists")
			},
		},
		{
			name: "service error",
			requestBody: map[string]interface{}{
				"name": "Developers",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("CreateGroup", "Developers", "").Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "database error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockGroupService)
			tt.mockSetup(mockService)

			handler := NewGroupHandler(mockService)

			router := gin.New()
			router.POST("/groups", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.CreateGroup(c)
			})

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/groups", bytes.NewBuffer(body))
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

// TestGroupHandler_ListGroups tests the ListGroups handler
func TestGroupHandler_ListGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		queryParams    string
		permissions    []string
		mockSetup      func(*MockGroupService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:        "successful list with defaults",
			queryParams: "",
			permissions: []string{"groups:read"},
			mockSetup: func(m *MockGroupService) {
				groups := []*models.Group{
					{ID: "group-1", Name: "Developers", Active: true},
					{ID: "group-2", Name: "Admins", Active: true},
				}
				m.On("ListGroups", 50, 0).Return(groups, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				groups := resp["groups"].([]interface{})
				assert.Len(t, groups, 2)
				assert.Equal(t, float64(50), resp["limit"])
				assert.Equal(t, float64(0), resp["offset"])
			},
		},
		{
			name:        "successful list with pagination",
			queryParams: "?limit=10&offset=20",
			permissions: []string{"groups:read"},
			mockSetup: func(m *MockGroupService) {
				groups := []*models.Group{
					{ID: "group-3", Name: "QA", Active: true},
				}
				m.On("ListGroups", 10, 20).Return(groups, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				groups := resp["groups"].([]interface{})
				assert.Len(t, groups, 1)
			},
		},
		{
			name:           "missing permission",
			queryParams:    "",
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Insufficient permissions")
			},
		},
		{
			name:        "service error",
			queryParams: "",
			permissions: []string{"groups:read"},
			mockSetup: func(m *MockGroupService) {
				m.On("ListGroups", 50, 0).Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to list groups")
			},
		},
		{
			name:        "pagination limits enforced",
			queryParams: "?limit=200&offset=-5",
			permissions: []string{"groups:read"},
			mockSetup: func(m *MockGroupService) {
				groups := []*models.Group{}
				m.On("ListGroups", 50, 0).Return(groups, nil) // limit capped at 50, offset floored at 0
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, float64(50), resp["limit"])
				assert.Equal(t, float64(0), resp["offset"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockGroupService)
			tt.mockSetup(mockService)

			handler := NewGroupHandler(mockService)

			router := gin.New()
			router.GET("/groups", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.ListGroups(c)
			})

			req := httptest.NewRequest(http.MethodGet, "/groups"+tt.queryParams, nil)
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

// TestGroupHandler_GetGroupByID tests the GetGroupByID handler
func TestGroupHandler_GetGroupByID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		groupID        string
		permissions    []string
		mockSetup      func(*MockGroupService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:        "successful retrieval",
			groupID:     "group-1",
			permissions: []string{"groups:read"},
			mockSetup: func(m *MockGroupService) {
				group := &models.Group{
					ID:          "group-1",
					Name:        "Developers",
					Description: "Dev team",
					Active:      true,
				}
				m.On("GetGroup", "group-1").Return(group, nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Equal(t, "group-1", resp["id"])
				assert.Equal(t, "Developers", resp["name"])
			},
		},
		{
			name:           "missing permission",
			groupID:        "group-1",
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Insufficient permissions")
			},
		},
		{
			name:        "group not found",
			groupID:     "nonexistent",
			permissions: []string{"groups:read"},
			mockSetup: func(m *MockGroupService) {
				m.On("GetGroup", "nonexistent").Return(nil, errors.New("group not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Group not found")
			},
		},
		{
			name:        "service error",
			groupID:     "group-1",
			permissions: []string{"groups:read"},
			mockSetup: func(m *MockGroupService) {
				m.On("GetGroup", "group-1").Return(nil, errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Failed to retrieve group")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockGroupService)
			tt.mockSetup(mockService)

			handler := NewGroupHandler(mockService)

			router := gin.New()
			router.GET("/groups/:id", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.GetGroupByID(c)
			})

			req := httptest.NewRequest(http.MethodGet, "/groups/"+tt.groupID, nil)
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

// TestGroupHandler_UpdateGroup tests the UpdateGroup handler
func TestGroupHandler_UpdateGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		groupID        string
		requestBody    map[string]interface{}
		permissions    []string
		mockSetup      func(*MockGroupService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:    "successful update",
			groupID: "group-1",
			requestBody: map[string]interface{}{
				"name": "Updated Developers",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("UpdateGroup", "group-1", mock.MatchedBy(func(updates map[string]interface{}) bool {
					return updates["name"] == "Updated Developers"
				})).Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["message"], "updated successfully")
			},
		},
		{
			name:    "missing permission",
			groupID: "group-1",
			requestBody: map[string]interface{}{
				"name": "Updated Developers",
			},
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Insufficient permissions")
			},
		},
		{
			name:           "no fields to update",
			groupID:        "group-1",
			requestBody:    map[string]interface{}{},
			permissions:    []string{"groups:write"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "No valid fields to update")
			},
		},
		{
			name:    "group not found",
			groupID: "nonexistent",
			requestBody: map[string]interface{}{
				"name": "Updated",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("UpdateGroup", "nonexistent", mock.Anything).Return(errors.New("group not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "Group not found")
			},
		},
		{
			name:    "name already exists",
			groupID: "group-1",
			requestBody: map[string]interface{}{
				"name": "Admins",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("UpdateGroup", "group-1", mock.Anything).Return(errors.New("group name already exists"))
			},
			expectedStatus: http.StatusConflict,
			checkResponse: func(t *testing.T, resp map[string]interface{}) {
				assert.Contains(t, resp["error"], "already exists")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockGroupService)
			tt.mockSetup(mockService)

			handler := NewGroupHandler(mockService)

			router := gin.New()
			router.PUT("/groups/:id", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.UpdateGroup(c)
			})

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPut, "/groups/"+tt.groupID, bytes.NewBuffer(body))
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

// TestGroupHandler_DeleteGroup tests the DeleteGroup handler
func TestGroupHandler_DeleteGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		groupID        string
		permissions    []string
		mockSetup      func(*MockGroupService)
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:        "successful deletion",
			groupID:     "group-1",
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("DeleteGroup", "group-1").Return(nil)
			},
			expectedStatus: http.StatusNoContent,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Empty(t, w.Body.String())
			},
		},
		{
			name:           "missing permission",
			groupID:        "group-1",
			permissions:    []string{"other:permission"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], "Insufficient permissions")
			},
		},
		{
			name:        "group not found",
			groupID:     "nonexistent",
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("DeleteGroup", "nonexistent").Return(errors.New("group not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], "Group not found")
			},
		},
		{
			name:        "admin group protection",
			groupID:     "admin-group",
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("DeleteGroup", "admin-group").Return(errors.New("admin group cannot be deleted"))
			},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"], "cannot be deleted")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockGroupService)
			tt.mockSetup(mockService)

			handler := NewGroupHandler(mockService)

			router := gin.New()
			router.DELETE("/groups/:id", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.DeleteGroup(c)
			})

			req := httptest.NewRequest(http.MethodDelete, "/groups/"+tt.groupID, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			tt.checkResponse(t, w)

			mockService.AssertExpectations(t)
		})
	}
}

// TestGroupHandler_AddPermissionToGroup tests the AddPermissionToGroup handler
func TestGroupHandler_AddPermissionToGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		groupID        string
		requestBody    map[string]interface{}
		permissions    []string
		mockSetup      func(*MockGroupService)
		expectedStatus int
		checkResponse  func(*testing.T, map[string]interface{})
	}{
		{
			name:    "successful permission assignment",
			groupID: "group-123",
			requestBody: map[string]interface{}{
				"permission_id": "perm-456",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("AddPermission", "group-123", "perm-456").Return(nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response map[string]interface{}) {
				assert.Equal(t, "Permission added to group successfully", response["message"])
			},
		},

		{
			name:           "invalid request format",
			groupID:        "group-123",
			requestBody:    map[string]interface{}{},
			permissions:    []string{"groups:write"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response map[string]interface{}) {
				assert.Contains(t, response["error"], "Invalid request format")
			},
		},
		{
			name:    "group not found",
			groupID: "nonexistent",
			requestBody: map[string]interface{}{
				"permission_id": "perm-456",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("AddPermission", "nonexistent", "perm-456").Return(errors.New("group not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, response map[string]interface{}) {
				assert.Equal(t, "Group not found", response["error"])
			},
		},
		{
			name:    "permission not found",
			groupID: "group-123",
			requestBody: map[string]interface{}{
				"permission_id": "nonexistent",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("AddPermission", "group-123", "nonexistent").Return(errors.New("permission not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, response map[string]interface{}) {
				assert.Equal(t, "Permission not found", response["error"])
			},
		},
		{
			name:    "permission already assigned",
			groupID: "group-123",
			requestBody: map[string]interface{}{
				"permission_id": "perm-456",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("AddPermission", "group-123", "perm-456").Return(errors.New("permission already assigned"))
			},
			expectedStatus: http.StatusConflict,
			checkResponse: func(t *testing.T, response map[string]interface{}) {
				assert.Equal(t, "Permission already assigned to group", response["error"])
			},
		},
		{
			name:    "insufficient permissions",
			groupID: "group-123",
			requestBody: map[string]interface{}{
				"permission_id": "perm-456",
			},
			permissions:    []string{"groups:read"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, response map[string]interface{}) {
				assert.Equal(t, "Insufficient permissions", response["error"])
			},
		},
		{
			name:    "service error",
			groupID: "group-123",
			requestBody: map[string]interface{}{
				"permission_id": "perm-456",
			},
			permissions: []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("AddPermission", "group-123", "perm-456").Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, response map[string]interface{}) {
				assert.Equal(t, "Failed to add permission to group", response["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockGroupService)
			tt.mockSetup(mockService)

			handler := NewGroupHandler(mockService)

			router := gin.New()
			router.POST("/groups/:id/permissions", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.AddPermissionToGroup(c)
			})

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/groups/"+tt.groupID+"/permissions", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if w.Code != http.StatusNoContent {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				tt.checkResponse(t, response)
			}

			mockService.AssertExpectations(t)
		})
	}
}

// TestGroupHandler_RemovePermissionFromGroup tests the RemovePermissionFromGroup handler
func TestGroupHandler_RemovePermissionFromGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		groupID        string
		permissionID   string
		permissions    []string
		mockSetup      func(*MockGroupService)
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:         "successful permission removal",
			groupID:      "group-123",
			permissionID: "perm-456",
			permissions:  []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("RemovePermission", "group-123", "perm-456").Return(nil)
			},
			expectedStatus: http.StatusNoContent,
			checkResponse:  func(t *testing.T, w *httptest.ResponseRecorder) {},
		},
		{
			name:         "group not found",
			groupID:      "nonexistent",
			permissionID: "perm-456",
			permissions:  []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("RemovePermission", "nonexistent", "perm-456").Return(errors.New("group not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Equal(t, "Group not found", response["error"])
			},
		},
		{
			name:         "permission not found",
			groupID:      "group-123",
			permissionID: "nonexistent",
			permissions:  []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("RemovePermission", "group-123", "nonexistent").Return(errors.New("permission not found"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Equal(t, "Permission not found", response["error"])
			},
		},
		{
			name:         "permission not assigned to group",
			groupID:      "group-123",
			permissionID: "perm-456",
			permissions:  []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("RemovePermission", "group-123", "perm-456").Return(errors.New("permission not assigned to group"))
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Equal(t, "Permission not assigned to group", response["error"])
			},
		},
		{
			name:           "insufficient permissions",
			groupID:        "group-123",
			permissionID:   "perm-456",
			permissions:    []string{"groups:read"},
			mockSetup:      func(m *MockGroupService) {},
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Equal(t, "Insufficient permissions", response["error"])
			},
		},
		{
			name:         "service error",
			groupID:      "group-123",
			permissionID: "perm-456",
			permissions:  []string{"groups:write"},
			mockSetup: func(m *MockGroupService) {
				m.On("RemovePermission", "group-123", "perm-456").Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Equal(t, "Failed to remove permission from group", response["error"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := new(MockGroupService)
			tt.mockSetup(mockService)

			handler := NewGroupHandler(mockService)

			router := gin.New()
			router.DELETE("/groups/:id/permissions/:permissionId", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				handler.RemovePermissionFromGroup(c)
			})

			url := "/groups/" + tt.groupID + "/permissions/" + tt.permissionID
			req := httptest.NewRequest(http.MethodDelete, url, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			tt.checkResponse(t, w)

			mockService.AssertExpectations(t)
		})
	}
}
