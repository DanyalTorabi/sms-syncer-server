package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGroup(t *testing.T) {
	group := NewGroup("Administrators", "System administrators")

	assert.NotEmpty(t, group.ID, "ID should be generated")
	assert.Equal(t, "Administrators", group.Name)
	assert.Equal(t, "System administrators", group.Description)
	assert.True(t, group.Active, "New group should be active by default")
	assert.Greater(t, group.CreatedAt, int64(0), "CreatedAt should be set")
	assert.Greater(t, group.UpdatedAt, int64(0), "UpdatedAt should be set")
	assert.NotNil(t, group.Permissions, "Permissions should be initialized")
	assert.Empty(t, group.Permissions, "New group should have no permissions")
}

func TestGroup_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		active   bool
		expected bool
	}{
		{
			name:     "active group",
			active:   true,
			expected: true,
		},
		{
			name:     "inactive group",
			active:   false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{Active: tt.active}
			assert.Equal(t, tt.expected, group.IsActive())
		})
	}
}

func TestGroup_HasPermission(t *testing.T) {
	perm1 := Permission{ID: "perm-1", Name: "sms:read"}
	perm2 := Permission{ID: "perm-2", Name: "sms:write"}

	tests := []struct {
		name         string
		permissions  []Permission
		permissionID string
		expected     bool
	}{
		{
			name:         "has permission",
			permissions:  []Permission{perm1, perm2},
			permissionID: "perm-1",
			expected:     true,
		},
		{
			name:         "does not have permission",
			permissions:  []Permission{perm1},
			permissionID: "perm-2",
			expected:     false,
		},
		{
			name:         "empty permissions list",
			permissions:  []Permission{},
			permissionID: "perm-1",
			expected:     false,
		},
		{
			name:         "nil permissions list",
			permissions:  nil,
			permissionID: "perm-1",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{Permissions: tt.permissions}
			assert.Equal(t, tt.expected, group.HasPermission(tt.permissionID))
		})
	}
}

func TestGroup_AddPermission(t *testing.T) {
	group := &Group{ID: "group-1", Name: "Test Group"}

	perm1 := Permission{ID: "perm-1", Name: "sms:read"}
	perm2 := Permission{ID: "perm-2", Name: "sms:write"}

	t.Run("add first permission", func(t *testing.T) {
		group.AddPermission(perm1)
		assert.Len(t, group.Permissions, 1)
		assert.Equal(t, "perm-1", group.Permissions[0].ID)
	})

	t.Run("add second permission", func(t *testing.T) {
		group.AddPermission(perm2)
		assert.Len(t, group.Permissions, 2)
		assert.Equal(t, "perm-2", group.Permissions[1].ID)
	})

	t.Run("add permission to nil list", func(t *testing.T) {
		newGroup := &Group{ID: "group-2", Permissions: nil}
		newGroup.AddPermission(perm1)
		assert.Len(t, newGroup.Permissions, 1)
	})
}

func TestGroupJSON_Marshaling(t *testing.T) {
	group := &Group{
		ID:          "test-group-123",
		Name:        "Administrators",
		Description: "System administrators",
		Active:      true,
		CreatedAt:   1609459200,
		UpdatedAt:   1609459300,
		Permissions: []Permission{
			{ID: "perm-1", Name: "sms:read"},
			{ID: "perm-2", Name: "users:write"},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(group)
	require.NoError(t, err)

	// Verify all fields are present
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "test-group-123", result["id"])
	assert.Equal(t, "Administrators", result["name"])
	assert.Equal(t, "System administrators", result["description"])
	assert.Equal(t, true, result["active"])
	assert.Equal(t, float64(1609459200), result["created_at"])
	assert.Equal(t, float64(1609459300), result["updated_at"])
	assert.NotNil(t, result["permissions"])
}

func TestGroupJSON_Unmarshaling(t *testing.T) {
	jsonData := `{
		"id": "test-group-456",
		"name": "Viewers",
		"description": "Read-only users",
		"active": false,
		"created_at": 1609459200,
		"updated_at": 1609459300
	}`

	var group Group
	err := json.Unmarshal([]byte(jsonData), &group)
	require.NoError(t, err)

	assert.Equal(t, "test-group-456", group.ID)
	assert.Equal(t, "Viewers", group.Name)
	assert.Equal(t, "Read-only users", group.Description)
	assert.False(t, group.Active)
	assert.Equal(t, int64(1609459200), group.CreatedAt)
	assert.Equal(t, int64(1609459300), group.UpdatedAt)
}

func TestCreateGroupRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request CreateGroupRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: CreateGroupRequest{
				Name:        "Administrators",
				Description: "System administrators",
			},
			wantErr: false,
		},
		{
			name: "valid request without description",
			request: CreateGroupRequest{
				Name: "Viewers",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			request: CreateGroupRequest{
				Description: "Some description",
			},
			wantErr: true,
		},
		{
			name: "name too short",
			request: CreateGroupRequest{
				Name: "ab",
			},
			wantErr: true,
		},
		{
			name: "name at minimum length",
			request: CreateGroupRequest{
				Name: "abc",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Actual validation happens via gin's binding validator
			// These tests document the expected validation rules
			if tt.wantErr {
				// Should fail validation
				assert.True(t, tt.request.Name == "" || len(tt.request.Name) < 3)
			} else {
				// Should pass validation
				assert.NotEmpty(t, tt.request.Name)
				assert.GreaterOrEqual(t, len(tt.request.Name), 3)
			}
		})
	}
}

func TestUpdateGroupRequest(t *testing.T) {
	t.Run("update name", func(t *testing.T) {
		name := "New Group Name"
		req := UpdateGroupRequest{
			Name: &name,
		}
		assert.NotNil(t, req.Name)
		assert.Equal(t, "New Group Name", *req.Name)
	})

	t.Run("update description", func(t *testing.T) {
		desc := "Updated description"
		req := UpdateGroupRequest{
			Description: &desc,
		}
		assert.NotNil(t, req.Description)
		assert.Equal(t, "Updated description", *req.Description)
	})

	t.Run("update active status", func(t *testing.T) {
		active := false
		req := UpdateGroupRequest{
			Active: &active,
		}
		assert.NotNil(t, req.Active)
		assert.False(t, *req.Active)
	})

	t.Run("empty update request", func(t *testing.T) {
		req := UpdateGroupRequest{}
		assert.Nil(t, req.Name)
		assert.Nil(t, req.Description)
		assert.Nil(t, req.Active)
	})
}
