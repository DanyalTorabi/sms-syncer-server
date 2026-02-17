package services

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sms-sync-server/internal/db"
	"sms-sync-server/internal/models"
)

func setupTestGroupService(t *testing.T) (*sql.DB, *GroupService) {
	database := db.SetupTestDB(t)
	repo := db.NewGroupRepository(database)
	service := NewGroupService(repo)
	return database, service
}

func TestGroupService_CreateGroup(t *testing.T) {
	tests := []struct {
		name        string
		groupName   string
		description string
		wantErr     bool
		errContains string
	}{
		{
			name:        "successful creation",
			groupName:   "TestGroup",
			description: "Test group description",
			wantErr:     false,
		},
		{
			name:        "successful creation without description",
			groupName:   "AnotherGroup",
			description: "",
			wantErr:     false,
		},
		{
			name:        "empty group name",
			groupName:   "",
			description: "Test description",
			wantErr:     true,
			errContains: "must be unique and not empty",
		},
		{
			name:        "whitespace only name",
			groupName:   "   ",
			description: "Test description",
			wantErr:     true,
			errContains: "must be unique and not empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, service := setupTestGroupService(t)

			group, err := service.CreateGroup(tt.groupName, tt.description)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, group)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, group)
				assert.Equal(t, tt.groupName, group.Name)
				assert.Equal(t, tt.description, group.Description)
				assert.NotEmpty(t, group.ID)
				assert.True(t, group.Active)
			}
		})
	}
}

func TestGroupService_CreateGroup_DuplicateName(t *testing.T) {
	_, service := setupTestGroupService(t)

	// Create first group
	_, err := service.CreateGroup("TestGroup", "First group")
	require.NoError(t, err)

	// Try to create group with same name
	_, err = service.CreateGroup("TestGroup", "Second group")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestGroupService_GetGroup(t *testing.T) {
	tests := []struct {
		name        string
		setupGroup  bool
		groupID     string
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful retrieval",
			setupGroup: true,
			wantErr:    false,
		},
		{
			name:        "empty group ID",
			setupGroup:  false,
			groupID:     "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "non-existent group",
			setupGroup:  false,
			groupID:     "non-existent-id",
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, service := setupTestGroupService(t)

			var groupID string
			if tt.setupGroup {
				group, err := service.CreateGroup("TestGroup", "Test description")
				require.NoError(t, err)
				groupID = group.ID
			} else {
				groupID = tt.groupID
			}

			group, err := service.GetGroup(groupID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, group)
				assert.Equal(t, groupID, group.ID)
			}
		})
	}
}

func TestGroupService_UpdateGroup(t *testing.T) {
	_, service := setupTestGroupService(t)

	// Create group
	group, err := service.CreateGroup("TestGroup", "Original description")
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
				"name": "UpdatedGroup",
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
			name: "empty name",
			updates: map[string]interface{}{
				"name": "",
			},
			wantErr:     true,
			errContains: "unique and not empty",
		},
		{
			name: "whitespace only name",
			updates: map[string]interface{}{
				"name": "   ",
			},
			wantErr:     true,
			errContains: "unique and not empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.UpdateGroup(group.ID, tt.updates)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify update
				updatedGroup, err := service.GetGroup(group.ID)
				require.NoError(t, err)

				if name, ok := tt.updates["name"].(string); ok {
					assert.Equal(t, name, updatedGroup.Name)
				}
				if description, ok := tt.updates["description"].(string); ok {
					assert.Equal(t, description, updatedGroup.Description)
				}
				if active, ok := tt.updates["active"].(bool); ok {
					assert.Equal(t, active, updatedGroup.Active)
				}
			}
		})
	}
}

func TestGroupService_DeleteGroup(t *testing.T) {
	_, service := setupTestGroupService(t)

	// Create regular group
	group, err := service.CreateGroup("TestGroup", "Test description")
	require.NoError(t, err)

	// Delete group
	err = service.DeleteGroup(group.ID)
	assert.NoError(t, err)

	// Verify group is deleted
	_, err = service.GetGroup(group.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGroupService_DeleteGroup_AdminProtection(t *testing.T) {
	_, service := setupTestGroupService(t)

	// Create admin group
	adminGroup, err := service.CreateGroup("admin", "Admin group")
	require.NoError(t, err)

	// Try to delete admin group
	err = service.DeleteGroup(adminGroup.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "admin group cannot be deleted")

	// Verify admin group still exists
	retrievedGroup, err := service.GetGroup(adminGroup.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedGroup)
}

func TestGroupService_DeleteGroup_AdminProtection_CaseInsensitive(t *testing.T) {
	_, service := setupTestGroupService(t)

	// Create admin group with mixed case
	adminGroup, err := service.CreateGroup("Admin", "Admin group")
	require.NoError(t, err)

	// Try to delete - should be protected
	err = service.DeleteGroup(adminGroup.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "admin group cannot be deleted")
}

func TestGroupService_ListGroups(t *testing.T) {
	_, service := setupTestGroupService(t)

	// Create multiple groups
	for i := 0; i < 5; i++ {
		_, err := service.CreateGroup("Group"+string(rune(i+'0')), "Description")
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
			name:      "list all groups",
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
			groups, err := service.ListGroups(tt.limit, tt.offset)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, groups, tt.wantCount)
			}
		})
	}
}

func TestGroupService_AddPermission(t *testing.T) {
	database, service := setupTestGroupService(t)

	// Create group
	group, err := service.CreateGroup("TestGroup", "Test description")
	require.NoError(t, err)

	// Create permission
	permRepo := db.NewPermissionRepository(database)
	permission := &models.Permission{
		Name:        "test:read",
		Resource:    "test",
		Action:      "read",
		Description: "Test permission",
		Active:      true,
	}
	err = permRepo.Create(permission)
	require.NoError(t, err)

	// Add permission to group
	err = service.AddPermission(group.ID, permission.ID)
	assert.NoError(t, err)

	// Verify permission was added
	groupRepo := db.NewGroupRepository(database)
	permissions, err := groupRepo.GetGroupPermissions(group.ID)
	assert.NoError(t, err)
	assert.Len(t, permissions, 1)
	assert.Equal(t, permission.ID, permissions[0].ID)
}

func TestGroupService_RemovePermission(t *testing.T) {
	database, service := setupTestGroupService(t)

	// Create group
	group, err := service.CreateGroup("TestGroup", "Test description")
	require.NoError(t, err)

	// Create permission
	permRepo := db.NewPermissionRepository(database)
	permission := &models.Permission{
		Name:        "test:read",
		Resource:    "test",
		Action:      "read",
		Description: "Test permission",
		Active:      true,
	}
	err = permRepo.Create(permission)
	require.NoError(t, err)

	// Add permission to group
	err = service.AddPermission(group.ID, permission.ID)
	require.NoError(t, err)

	// Remove permission from group
	err = service.RemovePermission(group.ID, permission.ID)
	assert.NoError(t, err)

	// Verify permission was removed
	groupRepo := db.NewGroupRepository(database)
	permissions, err := groupRepo.GetGroupPermissions(group.ID)
	assert.NoError(t, err)
	assert.Len(t, permissions, 0)
}

func TestGroupService_IntegrationFullLifecycle(t *testing.T) {
	database, service := setupTestGroupService(t)

	// 1. Create group
	group, err := service.CreateGroup("TestGroup", "Test description")
	require.NoError(t, err)
	assert.NotEmpty(t, group.ID)

	// 2. Get group
	retrievedGroup, err := service.GetGroup(group.ID)
	require.NoError(t, err)
	assert.Equal(t, group.ID, retrievedGroup.ID)

	// 3. Update group
	err = service.UpdateGroup(group.ID, map[string]interface{}{
		"description": "Updated description",
	})
	require.NoError(t, err)

	updatedGroup, err := service.GetGroup(group.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated description", updatedGroup.Description)

	// 4. Add permission
	permRepo := db.NewPermissionRepository(database)
	permission := &models.Permission{
		Name:        "test:read",
		Resource:    "test",
		Action:      "read",
		Description: "Test permission",
		Active:      true,
	}
	err = permRepo.Create(permission)
	require.NoError(t, err)

	err = service.AddPermission(group.ID, permission.ID)
	require.NoError(t, err)

	// 5. Remove permission
	err = service.RemovePermission(group.ID, permission.ID)
	require.NoError(t, err)

	// 6. List groups
	groups, err := service.ListGroups(10, 0)
	require.NoError(t, err)
	assert.Len(t, groups, 1)

	// 7. Delete group
	err = service.DeleteGroup(group.ID)
	require.NoError(t, err)

	_, err = service.GetGroup(group.ID)
	assert.Error(t, err)
}
