package db

import (
	"testing"
	"time"

	"sms-sync-server/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestGroupRepository(t *testing.T) GroupRepository {
	db := SetupTestDB(t)
	return NewGroupRepository(db)
}

func TestGroupRepository_Create(t *testing.T) {
	tests := []struct {
		name        string
		group       *models.Group
		wantErr     bool
		errContains string
	}{
		{
			name: "successful create",
			group: &models.Group{
				Name:        "TestGroup",
				Description: "Test description",
				Active:      true,
			},
			wantErr: false,
		},
		{
			name: "create with provided ID",
			group: &models.Group{
				ID:          "custom-uuid",
				Name:        "TestGroup2",
				Description: "Test description",
				Active:      true,
			},
			wantErr: false,
		},
		{
			name:        "nil group",
			group:       nil,
			wantErr:     true,
			errContains: "cannot be nil",
		},
		{
			name: "duplicate name",
			group: &models.Group{
				Name:        "TestGroup",
				Description: "Different description",
				Active:      true,
			},
			wantErr:     true,
			errContains: "failed to create group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestGroupRepository(t)

			// Create first group for duplicate test
			if tt.name == "duplicate name" {
				firstGroup := &models.Group{
					Name:        "TestGroup",
					Description: "Original description",
					Active:      true,
				}
				err := repo.Create(firstGroup)
				require.NoError(t, err)
			}

			err := repo.Create(tt.group)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, tt.group.ID)
				assert.NotZero(t, tt.group.CreatedAt)
				assert.NotZero(t, tt.group.UpdatedAt)
				assert.Equal(t, tt.group.CreatedAt, tt.group.UpdatedAt)
			}
		})
	}
}

func TestGroupRepository_GetByID(t *testing.T) {
	tests := []struct {
		name        string
		setupGroup  *models.Group
		lookupID    string
		wantGroup   bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful get",
			setupGroup: &models.Group{
				Name:        "TestGroup",
				Description: "Test description",
				Active:      true,
			},
			wantGroup: true,
			wantErr:   false,
		},
		{
			name:      "group not found",
			lookupID:  "non-existent-id",
			wantGroup: false,
			wantErr:   false,
		},
		{
			name:        "empty ID",
			lookupID:    "",
			wantGroup:   false,
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestGroupRepository(t)

			var lookupID string
			if tt.setupGroup != nil {
				err := repo.Create(tt.setupGroup)
				require.NoError(t, err)
				lookupID = tt.setupGroup.ID
			} else {
				lookupID = tt.lookupID
			}

			group, err := repo.GetByID(lookupID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantGroup {
					assert.NotNil(t, group)
					assert.Equal(t, tt.setupGroup.Name, group.Name)
				} else {
					assert.Nil(t, group)
				}
			}
		})
	}
}

func TestGroupRepository_GetByName(t *testing.T) {
	tests := []struct {
		name        string
		setupGroup  *models.Group
		groupName   string
		wantGroup   bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful get",
			setupGroup: &models.Group{
				Name:        "TestGroup",
				Description: "Test description",
				Active:      true,
			},
			groupName: "TestGroup",
			wantGroup: true,
			wantErr:   false,
		},
		{
			name:      "group not found",
			groupName: "NonExistent",
			wantGroup: false,
			wantErr:   false,
		},
		{
			name:        "empty name",
			groupName:   "",
			wantGroup:   false,
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestGroupRepository(t)

			if tt.setupGroup != nil {
				err := repo.Create(tt.setupGroup)
				require.NoError(t, err)
			}

			group, err := repo.GetByName(tt.groupName)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantGroup {
					assert.NotNil(t, group)
					assert.Equal(t, tt.setupGroup.Name, group.Name)
				} else {
					assert.Nil(t, group)
				}
			}
		})
	}
}

func TestGroupRepository_Update(t *testing.T) {
	tests := []struct {
		name        string
		setupGroup  *models.Group
		updateGroup *models.Group
		wantErr     bool
		errContains string
	}{
		{
			name: "successful update",
			setupGroup: &models.Group{
				Name:        "TestGroup",
				Description: "Original description",
				Active:      true,
			},
			updateGroup: &models.Group{
				Name:        "UpdatedGroup",
				Description: "Updated description",
				Active:      false,
			},
			wantErr: false,
		},
		{
			name:        "nil group",
			updateGroup: nil,
			wantErr:     true,
			errContains: "cannot be nil",
		},
		{
			name: "empty ID",
			updateGroup: &models.Group{
				Name: "TestGroup",
			},
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name: "group not found",
			updateGroup: &models.Group{
				ID:   "non-existent-id",
				Name: "TestGroup",
			},
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestGroupRepository(t)

			if tt.setupGroup != nil {
				err := repo.Create(tt.setupGroup)
				require.NoError(t, err)
				if tt.updateGroup != nil && tt.updateGroup.ID == "" {
					tt.updateGroup.ID = tt.setupGroup.ID
				}
			}

			originalUpdatedAt := int64(0)
			if tt.updateGroup != nil && tt.updateGroup.ID != "" {
				group, _ := repo.GetByID(tt.updateGroup.ID)
				if group != nil {
					originalUpdatedAt = group.UpdatedAt
				}
			}

			time.Sleep(10 * time.Millisecond) // Ensure updated_at changes

			err := repo.Update(tt.updateGroup)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				// Use GreaterOrEqual because sometimes timing isn't precise enough
				assert.GreaterOrEqual(t, tt.updateGroup.UpdatedAt, originalUpdatedAt)

				// Verify update
				group, err := repo.GetByID(tt.updateGroup.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.updateGroup.Name, group.Name)
				assert.Equal(t, tt.updateGroup.Description, group.Description)
				assert.Equal(t, tt.updateGroup.Active, group.Active)
			}
		})
	}
}

func TestGroupRepository_Delete(t *testing.T) {
	tests := []struct {
		name        string
		setupGroup  *models.Group
		deleteID    string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful delete",
			setupGroup: &models.Group{
				Name:        "TestGroup",
				Description: "Test description",
				Active:      true,
			},
			wantErr: false,
		},
		{
			name:        "group not found",
			deleteID:    "non-existent-id",
			wantErr:     true,
			errContains: "not found",
		},
		{
			name:        "empty ID",
			deleteID:    "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestGroupRepository(t)

			var deleteID string
			if tt.setupGroup != nil {
				err := repo.Create(tt.setupGroup)
				require.NoError(t, err)
				deleteID = tt.setupGroup.ID
			} else {
				deleteID = tt.deleteID
			}

			err := repo.Delete(deleteID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify deletion
				group, err := repo.GetByID(deleteID)
				assert.NoError(t, err)
				assert.Nil(t, group)
			}
		})
	}
}

func TestGroupRepository_List(t *testing.T) {
	tests := []struct {
		name        string
		setupCount  int
		limit       int
		offset      int
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:       "list all groups",
			setupCount: 5,
			limit:      10,
			offset:     0,
			wantCount:  5,
			wantErr:    false,
		},
		{
			name:       "list with limit",
			setupCount: 5,
			limit:      3,
			offset:     0,
			wantCount:  3,
			wantErr:    false,
		},
		{
			name:       "list with offset",
			setupCount: 5,
			limit:      10,
			offset:     2,
			wantCount:  3,
			wantErr:    false,
		},
		{
			name:       "list empty",
			setupCount: 0,
			limit:      10,
			offset:     0,
			wantCount:  0,
			wantErr:    false,
		},
		{
			name:        "negative limit",
			limit:       -1,
			offset:      0,
			wantErr:     true,
			errContains: "cannot be negative",
		},
		{
			name:        "negative offset",
			limit:       10,
			offset:      -1,
			wantErr:     true,
			errContains: "cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestGroupRepository(t)

			// Setup groups
			for i := 0; i < tt.setupCount; i++ {
				group := &models.Group{
					Name:        "Group" + string(rune(i+'A')),
					Description: "Test group " + string(rune(i+'0')),
					Active:      true,
				}
				err := repo.Create(group)
				require.NoError(t, err)
			}

			groups, err := repo.List(tt.limit, tt.offset)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, groups, tt.wantCount)

				// Verify ordering (by name)
				if len(groups) > 1 {
					for i := 0; i < len(groups)-1; i++ {
						assert.LessOrEqual(t, groups[i].Name, groups[i+1].Name)
					}
				}
			}
		})
	}
}

func TestGroupRepository_AddPermission(t *testing.T) {
	tests := []struct {
		name        string
		setupGroup  bool
		setupPerm   bool
		groupID     string
		permID      string
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful add",
			setupGroup: true,
			setupPerm:  true,
			wantErr:    false,
		},
		{
			name:        "empty group ID",
			groupID:     "",
			permID:      "some-perm",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "empty permission ID",
			groupID:     "some-group",
			permID:      "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "group not found",
			setupGroup:  false,
			setupPerm:   true,
			groupID:     "non-existent-group",
			wantErr:     true,
			errContains: "failed to add permission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := SetupTestDB(t)
			repo := NewGroupRepository(db)
			permRepo := NewPermissionRepository(db)

			var groupID, permID string

			if tt.setupGroup {
				group := &models.Group{
					Name:        "TestGroup",
					Description: "Test group",
					Active:      true,
				}
				err := repo.Create(group)
				require.NoError(t, err)
				groupID = group.ID
			} else if tt.groupID != "" {
				groupID = tt.groupID
			}

			if tt.setupPerm {
				perm := &models.Permission{
					Name:        "TestPermission",
					Resource:    "test_resource",
					Action:      "test_action",
					Description: "Test permission",
					Active:      true,
				}
				err := permRepo.Create(perm)
				require.NoError(t, err)
				permID = perm.ID
			} else if tt.permID != "" {
				permID = tt.permID
			}

			err := repo.AddPermission(groupID, permID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify association
				perms, err := repo.GetGroupPermissions(groupID)
				assert.NoError(t, err)
				assert.Len(t, perms, 1)
				assert.Equal(t, permID, perms[0].ID)
			}
		})
	}
}

func TestGroupRepository_RemovePermission(t *testing.T) {
	tests := []struct {
		name        string
		setupAssoc  bool
		groupID     string
		permID      string
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful remove",
			setupAssoc: true,
			wantErr:    false,
		},
		{
			name:        "empty group ID",
			groupID:     "",
			permID:      "some-perm",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "empty permission ID",
			groupID:     "some-group",
			permID:      "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "association not found",
			groupID:     "group1",
			permID:      "perm1",
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := SetupTestDB(t)
			repo := NewGroupRepository(db)
			permRepo := NewPermissionRepository(db)

			var groupID, permID string

			if tt.setupAssoc {
				group := &models.Group{
					Name:        "TestGroup",
					Description: "Test group",
					Active:      true,
				}
				err := repo.Create(group)
				require.NoError(t, err)
				groupID = group.ID

				perm := &models.Permission{
					Name:        "TestPermission",
					Resource:    "test_resource",
					Action:      "test_action",
					Description: "Test permission",
					Active:      true,
				}
				err = permRepo.Create(perm)
				require.NoError(t, err)
				permID = perm.ID

				err = repo.AddPermission(groupID, permID)
				require.NoError(t, err)
			} else {
				groupID = tt.groupID
				permID = tt.permID
			}

			err := repo.RemovePermission(groupID, permID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify removal
				perms, err := repo.GetGroupPermissions(groupID)
				assert.NoError(t, err)
				assert.Empty(t, perms)
			}
		})
	}
}

func TestGroupRepository_GetGroupPermissions(t *testing.T) {
	tests := []struct {
		name        string
		setupPerms  int
		setupGroup  bool
		groupID     string
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:       "multiple permissions",
			setupGroup: true,
			setupPerms: 3,
			wantCount:  3,
			wantErr:    false,
		},
		{
			name:       "no permissions",
			setupGroup: true,
			setupPerms: 0,
			wantCount:  0,
			wantErr:    false,
		},
		{
			name:        "empty group ID",
			setupGroup:  false,
			groupID:     "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := SetupTestDB(t)
			repo := NewGroupRepository(db)
			permRepo := NewPermissionRepository(db)

			var groupID string
			if tt.setupGroup {
				group := &models.Group{
					Name:        "TestGroup",
					Description: "Test group",
					Active:      true,
				}
				err := repo.Create(group)
				require.NoError(t, err)
				groupID = group.ID

				// Setup permissions
				for i := 0; i < tt.setupPerms; i++ {
					perm := &models.Permission{
						Name:        "Permission" + string(rune(i+'0')),
						Resource:    "resource" + string(rune(i+'0')),
						Action:      "action" + string(rune(i+'0')),
						Description: "Test permission",
						Active:      true,
					}
					err := permRepo.Create(perm)
					require.NoError(t, err)

					err = repo.AddPermission(groupID, perm.ID)
					require.NoError(t, err)
				}
			} else {
				groupID = tt.groupID
			}

			perms, err := repo.GetGroupPermissions(groupID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, perms, tt.wantCount)

				// Verify ordering (by resource, action)
				if len(perms) > 1 {
					for i := 0; i < len(perms)-1; i++ {
						// Resource ordering
						assert.LessOrEqual(t, perms[i].Resource, perms[i+1].Resource)
					}
				}
			}
		})
	}
}

// Integration test for full CRUD lifecycle
func TestGroupRepository_IntegrationFullLifecycle(t *testing.T) {
	db := SetupTestDB(t)
	repo := NewGroupRepository(db)
	permRepo := NewPermissionRepository(db)

	// Create group
	group := &models.Group{
		Name:        "IntegrationGroup",
		Description: "Test group",
		Active:      true,
	}
	err := repo.Create(group)
	require.NoError(t, err)
	assert.NotEmpty(t, group.ID)

	// Get group by ID
	retrieved, err := repo.GetByID(group.ID)
	require.NoError(t, err)
	assert.Equal(t, group.Name, retrieved.Name)

	// Get group by name
	retrieved, err = repo.GetByName(group.Name)
	require.NoError(t, err)
	assert.Equal(t, group.ID, retrieved.ID)

	// Update group
	group.Name = "UpdatedGroup"
	group.Description = "Updated description"
	group.Active = false
	err = repo.Update(group)
	require.NoError(t, err)

	retrieved, err = repo.GetByID(group.ID)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedGroup", retrieved.Name)
	assert.False(t, retrieved.Active)

	// Create permission and add to group
	perm := &models.Permission{
		Name:        "TestPermission",
		Resource:    "test_resource",
		Action:      "test_action",
		Description: "Test permission",
		Active:      true,
	}
	err = permRepo.Create(perm)
	require.NoError(t, err)

	err = repo.AddPermission(group.ID, perm.ID)
	require.NoError(t, err)

	// Verify group has permission
	perms, err := repo.GetGroupPermissions(group.ID)
	require.NoError(t, err)
	assert.Len(t, perms, 1)
	assert.Equal(t, perm.Name, perms[0].Name)

	// Remove permission from group
	err = repo.RemovePermission(group.ID, perm.ID)
	require.NoError(t, err)

	perms, err = repo.GetGroupPermissions(group.ID)
	require.NoError(t, err)
	assert.Empty(t, perms)

	// Delete group
	err = repo.Delete(group.ID)
	require.NoError(t, err)

	retrieved, err = repo.GetByID(group.ID)
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}
