package services

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sms-sync-server/internal/db"
	"sms-sync-server/internal/models"
)

func setupTestPermissionService(t *testing.T) (*sql.DB, *PermissionService) {
	database := db.SetupTestDB(t)
	repo := db.NewPermissionRepository(database)
	groupRepo := db.NewGroupRepository(database)
	service := NewPermissionService(repo, groupRepo)
	return database, service
}

func TestPermissionService_CreatePermission(t *testing.T) {
	tests := []struct {
		name        string
		permName    string
		resource    string
		action      string
		description string
		wantErr     bool
		errContains string
	}{
		{
			name:        "successful creation",
			permName:    "users:read",
			resource:    "users",
			action:      "read",
			description: "Read users",
			wantErr:     false,
		},
		{
			name:        "successful creation without description",
			permName:    "users:write",
			resource:    "users",
			action:      "write",
			description: "",
			wantErr:     false,
		},
		{
			name:        "invalid name format - no colon",
			permName:    "usersread",
			resource:    "users",
			action:      "read",
			description: "Read users",
			wantErr:     true,
			errContains: "resource:action format",
		},
		{
			name:        "invalid name format - multiple colons",
			permName:    "users:read:extra",
			resource:    "users",
			action:      "read",
			description: "Read users",
			wantErr:     true,
			errContains: "resource:action format",
		},
		{
			name:        "empty name",
			permName:    "",
			resource:    "users",
			action:      "read",
			description: "Read users",
			wantErr:     true,
			errContains: "resource:action format",
		},
		{
			name:        "empty resource",
			permName:    "users:read",
			resource:    "",
			action:      "read",
			description: "Read users",
			wantErr:     true,
			errContains: "resource cannot be empty",
		},
		{
			name:        "empty action",
			permName:    "users:read",
			resource:    "users",
			action:      "",
			description: "Read users",
			wantErr:     true,
			errContains: "action cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, service := setupTestPermissionService(t)

			permission, err := service.CreatePermission(tt.permName, tt.resource, tt.action, tt.description)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, permission)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, permission)
				assert.Equal(t, tt.permName, permission.Name)
				assert.Equal(t, tt.resource, permission.Resource)
				assert.Equal(t, tt.action, permission.Action)
				assert.Equal(t, tt.description, permission.Description)
				assert.NotEmpty(t, permission.ID)
				assert.True(t, permission.Active)
			}
		})
	}
}

func TestPermissionService_CreatePermission_DuplicateName(t *testing.T) {
	_, service := setupTestPermissionService(t)

	// Create first permission
	_, err := service.CreatePermission("users:read", "users", "read", "Read users")
	require.NoError(t, err)

	// Try to create permission with same name
	_, err = service.CreatePermission("users:read", "users", "read", "Read users again")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestPermissionService_GetPermission(t *testing.T) {
	tests := []struct {
		name            string
		setupPermission bool
		permissionID    string
		wantErr         bool
		errContains     string
	}{
		{
			name:            "successful retrieval",
			setupPermission: true,
			wantErr:         false,
		},
		{
			name:            "empty permission ID",
			setupPermission: false,
			permissionID:    "",
			wantErr:         true,
			errContains:     "cannot be empty",
		},
		{
			name:            "non-existent permission",
			setupPermission: false,
			permissionID:    "non-existent-id",
			wantErr:         true,
			errContains:     "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, service := setupTestPermissionService(t)

			var permissionID string
			if tt.setupPermission {
				perm, err := service.CreatePermission("users:read", "users", "read", "Read users")
				require.NoError(t, err)
				permissionID = perm.ID
			} else {
				permissionID = tt.permissionID
			}

			permission, err := service.GetPermission(permissionID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, permission)
				assert.Equal(t, permissionID, permission.ID)
			}
		})
	}
}

func TestPermissionService_UpdatePermission(t *testing.T) {
	_, service := setupTestPermissionService(t)

	// Create permission
	permission, err := service.CreatePermission("users:read", "users", "read", "Original description")
	require.NoError(t, err)

	tests := []struct {
		name        string
		updates     map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name: "update name",
			updates: map[string]interface{}{
				"name": "users:list",
			},
			wantErr: false,
		},
		{
			name: "update resource",
			updates: map[string]interface{}{
				"resource": "accounts",
			},
			wantErr: false,
		},
		{
			name: "update action",
			updates: map[string]interface{}{
				"action": "write",
			},
			wantErr: false,
		},
		{
			name: "update description",
			updates: map[string]interface{}{
				"description": "Updated description",
			},
			wantErr: false,
		},
		{
			name: "update active status",
			updates: map[string]interface{}{
				"active": false,
			},
			wantErr: false,
		},
		{
			name: "invalid name format",
			updates: map[string]interface{}{
				"name": "invalid-name",
			},
			wantErr:     true,
			errContains: "resource:action format",
		},
		{
			name: "empty resource",
			updates: map[string]interface{}{
				"resource": "",
			},
			wantErr:     true,
			errContains: "resource cannot be empty",
		},
		{
			name: "empty action",
			updates: map[string]interface{}{
				"action": "",
			},
			wantErr:     true,
			errContains: "action cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.UpdatePermission(permission.ID, tt.updates)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify update
				updatedPermission, err := service.GetPermission(permission.ID)
				require.NoError(t, err)

				if name, ok := tt.updates["name"].(string); ok {
					assert.Equal(t, name, updatedPermission.Name)
				}
				if resource, ok := tt.updates["resource"].(string); ok {
					assert.Equal(t, resource, updatedPermission.Resource)
				}
				if action, ok := tt.updates["action"].(string); ok {
					assert.Equal(t, action, updatedPermission.Action)
				}
				if description, ok := tt.updates["description"].(string); ok {
					assert.Equal(t, description, updatedPermission.Description)
				}
				if active, ok := tt.updates["active"].(bool); ok {
					assert.Equal(t, active, updatedPermission.Active)
				}
			}
		})
	}
}

func TestPermissionService_DeletePermission(t *testing.T) {
	_, service := setupTestPermissionService(t)

	// Create permission
	permission, err := service.CreatePermission("users:read", "users", "read", "Read users")
	require.NoError(t, err)

	// Delete permission
	err = service.DeletePermission(permission.ID)
	assert.NoError(t, err)

	// Verify permission is deleted
	_, err = service.GetPermission(permission.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPermissionService_DeletePermission_InUseByGroup(t *testing.T) {
	database, service := setupTestPermissionService(t)

	// Create permission
	permission, err := service.CreatePermission("users:read", "users", "read", "Read users")
	require.NoError(t, err)

	// Create group and assign permission
	groupRepo := db.NewGroupRepository(database)
	group := &models.Group{
		Name:        "TestGroup",
		Description: "Test group",
		Active:      true,
	}
	err = groupRepo.Create(group)
	require.NoError(t, err)

	err = groupRepo.AddPermission(group.ID, permission.ID)
	require.NoError(t, err)

	// Try to delete permission - should fail
	err = service.DeletePermission(permission.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "in use by groups")

	// Verify permission still exists
	retrievedPermission, err := service.GetPermission(permission.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedPermission)
}

func TestPermissionService_ListPermissions(t *testing.T) {
	_, service := setupTestPermissionService(t)

	// Create multiple permissions
	for i := 0; i < 5; i++ {
		name := "resource" + string(rune(i+'0')) + ":action"
		_, err := service.CreatePermission(name, "resource"+string(rune(i+'0')), "action", "Description")
		require.NoError(t, err)
	}

	tests := []struct {
		name      string
		limit     int
		offset    int
		wantCount int
		wantErr   bool
	}{
		{
			name:      "list all permissions",
			limit:     10,
			offset:    0,
			wantCount: 5,
			wantErr:   false,
		},
		{
			name:      "list with limit",
			limit:     3,
			offset:    0,
			wantCount: 3,
			wantErr:   false,
		},
		{
			name:      "list with offset",
			limit:     10,
			offset:    2,
			wantCount: 3,
			wantErr:   false,
		},
		{
			name:    "negative limit",
			limit:   -1,
			offset:  0,
			wantErr: true,
		},
		{
			name:    "negative offset",
			limit:   10,
			offset:  -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permissions, err := service.ListPermissions(tt.limit, tt.offset)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, permissions, tt.wantCount)
			}
		})
	}
}

func TestPermissionService_IntegrationFullLifecycle(t *testing.T) {
	database, service := setupTestPermissionService(t)

	// 1. Create permission
	permission, err := service.CreatePermission("users:read", "users", "read", "Read users")
	require.NoError(t, err)
	assert.NotEmpty(t, permission.ID)

	// 2. Get permission
	retrievedPermission, err := service.GetPermission(permission.ID)
	require.NoError(t, err)
	assert.Equal(t, permission.ID, retrievedPermission.ID)

	// 3. Update permission
	err = service.UpdatePermission(permission.ID, map[string]interface{}{
		"description": "Updated description",
	})
	require.NoError(t, err)

	updatedPermission, err := service.GetPermission(permission.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated description", updatedPermission.Description)

	// 4. Test with group assignment
	groupRepo := db.NewGroupRepository(database)
	group := &models.Group{
		Name:        "TestGroup",
		Description: "Test group",
		Active:      true,
	}
	err = groupRepo.Create(group)
	require.NoError(t, err)

	err = groupRepo.AddPermission(group.ID, permission.ID)
	require.NoError(t, err)

	// 5. Try to delete while in use - should fail
	err = service.DeletePermission(permission.ID)
	assert.Error(t, err)

	// 6. Remove from group
	err = groupRepo.RemovePermission(group.ID, permission.ID)
	require.NoError(t, err)

	// 7. List permissions
	permissions, err := service.ListPermissions(10, 0)
	require.NoError(t, err)
	assert.Len(t, permissions, 1)

	// 8. Delete permission - should succeed now
	err = service.DeletePermission(permission.ID)
	require.NoError(t, err)

	_, err = service.GetPermission(permission.ID)
	assert.Error(t, err)
}

func TestValidatePermissionName(t *testing.T) {
	tests := []struct {
		name     string
		permName string
		wantErr  bool
	}{
		{"valid format", "users:read", false},
		{"valid with underscores", "user_accounts:read_all", false},
		{"valid with hyphens", "user-accounts:read-all", false},
		{"valid with numbers", "users123:read456", false},
		{"empty name", "", true},
		{"no colon", "usersread", true},
		{"multiple colons", "users:read:extra", true},
		{"only colon", ":", true},
		{"starts with colon", ":read", true},
		{"ends with colon", "users:", true},
		{"spaces", "users :read", true},
		{"special chars", "users@:read", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePermissionName(tt.permName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
