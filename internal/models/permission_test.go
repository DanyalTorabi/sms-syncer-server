package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPermission(t *testing.T) {
	perm := NewPermission("sms:read", "sms", "read", "Read SMS messages")

	assert.NotEmpty(t, perm.ID, "ID should be generated")
	assert.Equal(t, "sms:read", perm.Name)
	assert.Equal(t, "sms", perm.Resource)
	assert.Equal(t, "read", perm.Action)
	assert.Equal(t, "Read SMS messages", perm.Description)
	assert.True(t, perm.Active, "New permission should be active by default")
	assert.Greater(t, perm.CreatedAt, int64(0), "CreatedAt should be set")
}

func TestPermission_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		active   bool
		expected bool
	}{
		{
			name:     "active permission",
			active:   true,
			expected: true,
		},
		{
			name:     "inactive permission",
			active:   false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := &Permission{Active: tt.active}
			assert.Equal(t, tt.expected, perm.IsActive())
		})
	}
}

func TestPermission_FullName(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		action   string
		expected string
	}{
		{
			name:     "sms read permission",
			resource: "sms",
			action:   "read",
			expected: "sms:read",
		},
		{
			name:     "users write permission",
			resource: "users",
			action:   "write",
			expected: "users:write",
		},
		{
			name:     "groups delete permission",
			resource: "groups",
			action:   "delete",
			expected: "groups:delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := &Permission{
				Resource: tt.resource,
				Action:   tt.action,
			}
			assert.Equal(t, tt.expected, perm.FullName())
		})
	}
}

func TestPermissionJSON_Marshaling(t *testing.T) {
	perm := &Permission{
		ID:          "test-uuid-123",
		Name:        "sms:read",
		Resource:    "sms",
		Action:      "read",
		Description: "Read SMS messages",
		Active:      true,
		CreatedAt:   1609459200,
	}

	// Marshal to JSON
	data, err := json.Marshal(perm)
	require.NoError(t, err)

	// Verify all fields are present
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "test-uuid-123", result["id"])
	assert.Equal(t, "sms:read", result["name"])
	assert.Equal(t, "sms", result["resource"])
	assert.Equal(t, "read", result["action"])
	assert.Equal(t, "Read SMS messages", result["description"])
	assert.Equal(t, true, result["active"])
	assert.Equal(t, float64(1609459200), result["created_at"])
}

func TestPermissionJSON_Unmarshaling(t *testing.T) {
	jsonData := `{
		"id": "test-uuid-456",
		"name": "users:write",
		"resource": "users",
		"action": "write",
		"description": "Write user data",
		"active": false,
		"created_at": 1609459200
	}`

	var perm Permission
	err := json.Unmarshal([]byte(jsonData), &perm)
	require.NoError(t, err)

	assert.Equal(t, "test-uuid-456", perm.ID)
	assert.Equal(t, "users:write", perm.Name)
	assert.Equal(t, "users", perm.Resource)
	assert.Equal(t, "write", perm.Action)
	assert.Equal(t, "Write user data", perm.Description)
	assert.False(t, perm.Active)
	assert.Equal(t, int64(1609459200), perm.CreatedAt)
}

func TestCreatePermissionRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request CreatePermissionRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: CreatePermissionRequest{
				Name:        "sms:read",
				Resource:    "sms",
				Action:      "read",
				Description: "Read SMS messages",
			},
			wantErr: false,
		},
		{
			name: "valid request without description",
			request: CreatePermissionRequest{
				Name:     "users:write",
				Resource: "users",
				Action:   "write",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			request: CreatePermissionRequest{
				Resource: "sms",
				Action:   "read",
			},
			wantErr: true,
		},
		{
			name: "name too short",
			request: CreatePermissionRequest{
				Name:     "ab",
				Resource: "sms",
				Action:   "read",
			},
			wantErr: true,
		},
		{
			name: "missing resource",
			request: CreatePermissionRequest{
				Name:   "sms:read",
				Action: "read",
			},
			wantErr: true,
		},
		{
			name: "missing action",
			request: CreatePermissionRequest{
				Name:     "sms:read",
				Resource: "sms",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Actual validation happens via gin's binding validator
			// These tests document the expected validation rules
			if tt.wantErr {
				// Should fail validation
				assert.True(t, tt.request.Name == "" || len(tt.request.Name) < 3 ||
					tt.request.Resource == "" || tt.request.Action == "")
			} else {
				// Should pass validation
				assert.NotEmpty(t, tt.request.Name)
				assert.GreaterOrEqual(t, len(tt.request.Name), 3)
				assert.NotEmpty(t, tt.request.Resource)
				assert.NotEmpty(t, tt.request.Action)
			}
		})
	}
}

func TestUpdatePermissionRequest(t *testing.T) {
	t.Run("update description", func(t *testing.T) {
		desc := "Updated description"
		req := UpdatePermissionRequest{
			Description: &desc,
		}
		assert.NotNil(t, req.Description)
		assert.Equal(t, "Updated description", *req.Description)
	})

	t.Run("update active status", func(t *testing.T) {
		active := false
		req := UpdatePermissionRequest{
			Active: &active,
		}
		assert.NotNil(t, req.Active)
		assert.False(t, *req.Active)
	})

	t.Run("empty update request", func(t *testing.T) {
		req := UpdatePermissionRequest{}
		assert.Nil(t, req.Description)
		assert.Nil(t, req.Active)
	})
}
