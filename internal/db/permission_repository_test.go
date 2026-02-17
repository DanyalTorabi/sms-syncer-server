package db

import (
	"testing"
	"time"

	"sms-sync-server/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestPermissionRepository(t *testing.T) PermissionRepository {
	db := SetupTestDB(t)
	return NewPermissionRepository(db)
}

func TestPermissionRepository_Create(t *testing.T) {
	tests := []struct {
		name        string
		permission  *models.Permission
		wantErr     bool
		errContains string
	}{
		{
			name: "successful create",
			permission: &models.Permission{
				Name:        "TestPermission",
				Resource:    "test_resource",
				Action:      "test_action",
				Description: "Test description",
				Active:      true,
			},
			wantErr: false,
		},
		{
			name: "create with provided ID",
			permission: &models.Permission{
				ID:          "custom-uuid",
				Name:        "TestPermission2",
				Resource:    "test_resource2",
				Action:      "test_action2",
				Description: "Test description",
				Active:      true,
			},
			wantErr: false,
		},
		{
			name:        "nil permission",
			permission:  nil,
			wantErr:     true,
			errContains: "cannot be nil",
		},
		{
			name: "duplicate name",
			permission: &models.Permission{
				Name:        "TestPermission",
				Resource:    "different_resource",
				Action:      "different_action",
				Description: "Different description",
				Active:      true,
			},
			wantErr:     true,
			errContains: "failed to create permission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestPermissionRepository(t)

			// Create first permission for duplicate test
			if tt.name == "duplicate name" {
				firstPerm := &models.Permission{
					Name:        "TestPermission",
					Resource:    "test_resource",
					Action:      "test_action",
					Description: "Original description",
					Active:      true,
				}
				err := repo.Create(firstPerm)
				require.NoError(t, err)
			}

			err := repo.Create(tt.permission)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, tt.permission.ID)
				assert.NotZero(t, tt.permission.CreatedAt)
			}
		})
	}
}

func TestPermissionRepository_GetByID(t *testing.T) {
	tests := []struct {
		name        string
		setupPerm   *models.Permission
		lookupID    string
		wantPerm    bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful get",
			setupPerm: &models.Permission{
				Name:        "TestPermission",
				Resource:    "test_resource",
				Action:      "test_action",
				Description: "Test description",
				Active:      true,
			},
			wantPerm: true,
			wantErr:  false,
		},
		{
			name:     "permission not found",
			lookupID: "non-existent-id",
			wantPerm: false,
			wantErr:  false,
		},
		{
			name:        "empty ID",
			lookupID:    "",
			wantPerm:    false,
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestPermissionRepository(t)

			var lookupID string
			if tt.setupPerm != nil {
				err := repo.Create(tt.setupPerm)
				require.NoError(t, err)
				lookupID = tt.setupPerm.ID
			} else {
				lookupID = tt.lookupID
			}

			perm, err := repo.GetByID(lookupID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantPerm {
					assert.NotNil(t, perm)
					assert.Equal(t, tt.setupPerm.Name, perm.Name)
					assert.Equal(t, tt.setupPerm.Resource, perm.Resource)
					assert.Equal(t, tt.setupPerm.Action, perm.Action)
				} else {
					assert.Nil(t, perm)
				}
			}
		})
	}
}

func TestPermissionRepository_GetByName(t *testing.T) {
	tests := []struct {
		name        string
		setupPerm   *models.Permission
		permName    string
		wantPerm    bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful get",
			setupPerm: &models.Permission{
				Name:        "TestPermission",
				Resource:    "test_resource",
				Action:      "test_action",
				Description: "Test description",
				Active:      true,
			},
			permName: "TestPermission",
			wantPerm: true,
			wantErr:  false,
		},
		{
			name:     "permission not found",
			permName: "NonExistent",
			wantPerm: false,
			wantErr:  false,
		},
		{
			name:        "empty name",
			permName:    "",
			wantPerm:    false,
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestPermissionRepository(t)

			if tt.setupPerm != nil {
				err := repo.Create(tt.setupPerm)
				require.NoError(t, err)
			}

			perm, err := repo.GetByName(tt.permName)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantPerm {
					assert.NotNil(t, perm)
					assert.Equal(t, tt.setupPerm.Name, perm.Name)
				} else {
					assert.Nil(t, perm)
				}
			}
		})
	}
}

func TestPermissionRepository_Update(t *testing.T) {
	tests := []struct {
		name        string
		setupPerm   *models.Permission
		updatePerm  *models.Permission
		wantErr     bool
		errContains string
	}{
		{
			name: "successful update",
			setupPerm: &models.Permission{
				Name:        "TestPermission",
				Resource:    "test_resource",
				Action:      "test_action",
				Description: "Original description",
				Active:      true,
			},
			updatePerm: &models.Permission{
				Name:        "UpdatedPermission",
				Resource:    "updated_resource",
				Action:      "updated_action",
				Description: "Updated description",
				Active:      false,
			},
			wantErr: false,
		},
		{
			name:        "nil permission",
			updatePerm:  nil,
			wantErr:     true,
			errContains: "cannot be nil",
		},
		{
			name: "empty ID",
			updatePerm: &models.Permission{
				Name: "TestPermission",
			},
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name: "permission not found",
			updatePerm: &models.Permission{
				ID:   "non-existent-id",
				Name: "TestPermission",
			},
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := setupTestPermissionRepository(t)

			if tt.setupPerm != nil {
				err := repo.Create(tt.setupPerm)
				require.NoError(t, err)
				if tt.updatePerm != nil && tt.updatePerm.ID == "" {
					tt.updatePerm.ID = tt.setupPerm.ID
				}
			}

			err := repo.Update(tt.updatePerm)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify update
				perm, err := repo.GetByID(tt.updatePerm.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.updatePerm.Name, perm.Name)
				assert.Equal(t, tt.updatePerm.Resource, perm.Resource)
				assert.Equal(t, tt.updatePerm.Action, perm.Action)
				assert.Equal(t, tt.updatePerm.Description, perm.Description)
				assert.Equal(t, tt.updatePerm.Active, perm.Active)
			}
		})
	}
}

func TestPermissionRepository_Delete(t *testing.T) {
	tests := []struct {
		name        string
		setupPerm   *models.Permission
		deleteID    string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful delete",
			setupPerm: &models.Permission{
				Name:        "TestPermission",
				Resource:    "test_resource",
				Action:      "test_action",
				Description: "Test description",
				Active:      true,
			},
			wantErr: false,
		},
		{
			name:        "permission not found",
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
			repo := setupTestPermissionRepository(t)

			var deleteID string
			if tt.setupPerm != nil {
				err := repo.Create(tt.setupPerm)
				require.NoError(t, err)
				deleteID = tt.setupPerm.ID
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
				perm, err := repo.GetByID(deleteID)
				assert.NoError(t, err)
				assert.Nil(t, perm)
			}
		})
	}
}

func TestPermissionRepository_List(t *testing.T) {
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
			name:       "list all permissions",
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
			repo := setupTestPermissionRepository(t)

			// Setup permissions
			for i := 0; i < tt.setupCount; i++ {
				perm := &models.Permission{
					Name:        "Permission" + string(rune(i+'A')),
					Resource:    "resource" + string(rune(i+'0')),
					Action:      "action" + string(rune(i+'0')),
					Description: "Test permission " + string(rune(i+'0')),
					Active:      true,
				}
				err := repo.Create(perm)
				require.NoError(t, err)
			}

			perms, err := repo.List(tt.limit, tt.offset)

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
						assert.LessOrEqual(t, perms[i].Resource, perms[i+1].Resource)
					}
				}
			}
		})
	}
}

// Integration test for full CRUD lifecycle
func TestPermissionRepository_IntegrationFullLifecycle(t *testing.T) {
	repo := setupTestPermissionRepository(t)

	// Create permission
	perm := &models.Permission{
		Name:        "IntegrationPermission",
		Resource:    "integration_resource",
		Action:      "integration_action",
		Description: "Test permission",
		Active:      true,
	}
	err := repo.Create(perm)
	require.NoError(t, err)
	assert.NotEmpty(t, perm.ID)
	assert.NotZero(t, perm.CreatedAt)

	// Get permission by ID
	retrieved, err := repo.GetByID(perm.ID)
	require.NoError(t, err)
	assert.Equal(t, perm.Name, retrieved.Name)
	assert.Equal(t, perm.Resource, retrieved.Resource)
	assert.Equal(t, perm.Action, retrieved.Action)

	// Get permission by name
	retrieved, err = repo.GetByName(perm.Name)
	require.NoError(t, err)
	assert.Equal(t, perm.ID, retrieved.ID)

	// Update permission
	perm.Name = "UpdatedPermission"
	perm.Resource = "updated_resource"
	perm.Action = "updated_action"
	perm.Description = "Updated description"
	perm.Active = false
	err = repo.Update(perm)
	require.NoError(t, err)

	retrieved, err = repo.GetByID(perm.ID)
	require.NoError(t, err)
	assert.Equal(t, "UpdatedPermission", retrieved.Name)
	assert.Equal(t, "updated_resource", retrieved.Resource)
	assert.Equal(t, "updated_action", retrieved.Action)
	assert.False(t, retrieved.Active)

	// List permissions
	perms, err := repo.List(10, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(perms), 1)

	// Delete permission
	err = repo.Delete(perm.ID)
	require.NoError(t, err)

	retrieved, err = repo.GetByID(perm.ID)
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

// Test SQL injection prevention
func TestPermissionRepository_SQLInjectionPrevention(t *testing.T) {
	repo := setupTestPermissionRepository(t)

	// Attempt SQL injection in name
	perm := &models.Permission{
		Name:        "admin' OR '1'='1",
		Resource:    "test_resource",
		Action:      "test_action",
		Description: "Test description",
		Active:      true,
	}
	err := repo.Create(perm)
	require.NoError(t, err)

	// Should not return any permission when searching for SQL injection pattern
	retrieved, err := repo.GetByName("admin' OR '1'='1")
	require.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, perm.ID, retrieved.ID)

	// Verify that only the permission with exact name match is returned
	retrieved, err = repo.GetByName("admin")
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

// Test pagination with large dataset
func TestPermissionRepository_PaginationLargeDataset(t *testing.T) {
	repo := setupTestPermissionRepository(t)

	// Create 50 permissions
	for i := 0; i < 50; i++ {
		perm := &models.Permission{
			Name:        "Permission" + string(rune(i)),
			Resource:    "resource" + string(rune(i)),
			Action:      "action" + string(rune(i)),
			Description: "Test permission",
			Active:      true,
		}
		err := repo.Create(perm)
		require.NoError(t, err)
		time.Sleep(1 * time.Millisecond) // Ensure different timestamps
	}

	// Test first page
	page1, err := repo.List(10, 0)
	require.NoError(t, err)
	assert.Len(t, page1, 10)

	// Test second page
	page2, err := repo.List(10, 10)
	require.NoError(t, err)
	assert.Len(t, page2, 10)

	// Verify no overlap between pages
	for _, p1 := range page1 {
		for _, p2 := range page2 {
			assert.NotEqual(t, p1.ID, p2.ID)
		}
	}

	// Test last page (partial)
	page5, err := repo.List(10, 40)
	require.NoError(t, err)
	assert.Len(t, page5, 10)

	// Test beyond dataset
	page6, err := repo.List(10, 50)
	require.NoError(t, err)
	assert.Empty(t, page6)
}
