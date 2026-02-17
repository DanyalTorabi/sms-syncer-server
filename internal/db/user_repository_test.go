package db

import (
	"database/sql"
	"testing"
	"time"

	"sms-sync-server/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestUserRepository(t *testing.T) (*sql.DB, UserRepository) {
	db := SetupTestDB(t)
	repo := NewUserRepository(db)
	return db, repo
}

func TestUserRepository_Create(t *testing.T) {
	tests := []struct {
		name        string
		user        *models.User
		wantErr     bool
		errContains string
	}{
		{
			name: "successful create",
			user: &models.User{
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			wantErr: false,
		},
		{
			name: "create with provided ID",
			user: &models.User{
				ID:           "custom-uuid",
				Username:     "testuser2",
				Email:        "test2@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			wantErr: false,
		},
		{
			name:        "nil user",
			user:        nil,
			wantErr:     true,
			errContains: "cannot be nil",
		},
		{
			name: "duplicate username",
			user: &models.User{
				Username:     "testuser",
				Email:        "different@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			wantErr:     true,
			errContains: "failed to create user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, repo := setupTestUserRepository(t)

			// Create first user for duplicate test
			if tt.name == "duplicate username" {
				firstUser := &models.User{
					Username:     "testuser",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Active:       true,
				}
				err := repo.Create(firstUser)
				require.NoError(t, err)
			}

			err := repo.Create(tt.user)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, tt.user.ID)
				assert.NotZero(t, tt.user.CreatedAt)
				assert.NotZero(t, tt.user.UpdatedAt)
				assert.Equal(t, tt.user.CreatedAt, tt.user.UpdatedAt)
			}
		})
	}
}

func TestUserRepository_GetByID(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   *models.User
		lookupID    string
		wantUser    bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful get",
			setupUser: &models.User{
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			wantUser: true,
			wantErr:  false,
		},
		{
			name:     "user not found",
			lookupID: "non-existent-id",
			wantUser: false,
			wantErr:  false,
		},
		{
			name:        "empty ID",
			lookupID:    "",
			wantUser:    false,
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, repo := setupTestUserRepository(t)

			var lookupID string
			if tt.setupUser != nil {
				err := repo.Create(tt.setupUser)
				require.NoError(t, err)
				lookupID = tt.setupUser.ID
			} else {
				lookupID = tt.lookupID
			}

			user, err := repo.GetByID(lookupID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantUser {
					assert.NotNil(t, user)
					assert.Equal(t, tt.setupUser.Username, user.Username)
					assert.Equal(t, tt.setupUser.Email, user.Email)
				} else {
					assert.Nil(t, user)
				}
			}
		})
	}
}

func TestUserRepository_GetByUsername(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   *models.User
		username    string
		wantUser    bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful get",
			setupUser: &models.User{
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			username: "testuser",
			wantUser: true,
			wantErr:  false,
		},
		{
			name:     "user not found",
			username: "nonexistent",
			wantUser: false,
			wantErr:  false,
		},
		{
			name:        "empty username",
			username:    "",
			wantUser:    false,
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, repo := setupTestUserRepository(t)

			if tt.setupUser != nil {
				err := repo.Create(tt.setupUser)
				require.NoError(t, err)
			}

			user, err := repo.GetByUsername(tt.username)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantUser {
					assert.NotNil(t, user)
					assert.Equal(t, tt.setupUser.Username, user.Username)
				} else {
					assert.Nil(t, user)
				}
			}
		})
	}
}

func TestUserRepository_GetByEmail(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   *models.User
		email       string
		wantUser    bool
		wantErr     bool
		errContains string
	}{
		{
			name: "successful get",
			setupUser: &models.User{
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			email:    "test@example.com",
			wantUser: true,
			wantErr:  false,
		},
		{
			name:     "user not found",
			email:    "nonexistent@example.com",
			wantUser: false,
			wantErr:  false,
		},
		{
			name:        "empty email",
			email:       "",
			wantUser:    false,
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, repo := setupTestUserRepository(t)

			if tt.setupUser != nil {
				err := repo.Create(tt.setupUser)
				require.NoError(t, err)
			}

			user, err := repo.GetByEmail(tt.email)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				if tt.wantUser {
					assert.NotNil(t, user)
					assert.Equal(t, tt.setupUser.Email, user.Email)
				} else {
					assert.Nil(t, user)
				}
			}
		})
	}
}

func TestUserRepository_Update(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   *models.User
		updateUser  *models.User
		wantErr     bool
		errContains string
	}{
		{
			name: "successful update",
			setupUser: &models.User{
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			updateUser: &models.User{
				Username:     "updateduser",
				Email:        "updated@example.com",
				PasswordHash: "new_hashed_password",
				Active:       false,
			},
			wantErr: false,
		},
		{
			name:        "nil user",
			updateUser:  nil,
			wantErr:     true,
			errContains: "cannot be nil",
		},
		{
			name: "empty ID",
			updateUser: &models.User{
				Username: "testuser",
			},
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name: "user not found",
			updateUser: &models.User{
				ID:       "non-existent-id",
				Username: "testuser",
			},
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, repo := setupTestUserRepository(t)

			if tt.setupUser != nil {
				err := repo.Create(tt.setupUser)
				require.NoError(t, err)
				if tt.updateUser != nil && tt.updateUser.ID == "" {
					tt.updateUser.ID = tt.setupUser.ID
				}
			}

			originalUpdatedAt := int64(0)
			if tt.updateUser != nil && tt.updateUser.ID != "" {
				user, _ := repo.GetByID(tt.updateUser.ID)
				if user != nil {
					originalUpdatedAt = user.UpdatedAt
				}
			}

			time.Sleep(10 * time.Millisecond) // Ensure updated_at changes

			err := repo.Update(tt.updateUser)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.GreaterOrEqual(t, tt.updateUser.UpdatedAt, originalUpdatedAt)

				// Verify update
				user, err := repo.GetByID(tt.updateUser.ID)
				require.NoError(t, err)
				assert.Equal(t, tt.updateUser.Username, user.Username)
				assert.Equal(t, tt.updateUser.Email, user.Email)
				assert.Equal(t, tt.updateUser.Active, user.Active)
			}
		})
	}
}

func TestUserRepository_Delete(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   *models.User
		deleteID    string
		wantErr     bool
		errContains string
	}{
		{
			name: "successful delete",
			setupUser: &models.User{
				Username:     "testuser",
				Email:        "test@example.com",
				PasswordHash: "hashed_password",
				Active:       true,
			},
			wantErr: false,
		},
		{
			name:        "user not found",
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
			_, repo := setupTestUserRepository(t)

			var deleteID string
			if tt.setupUser != nil {
				err := repo.Create(tt.setupUser)
				require.NoError(t, err)
				deleteID = tt.setupUser.ID
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
				user, err := repo.GetByID(deleteID)
				assert.NoError(t, err)
				assert.Nil(t, user)
			}
		})
	}
}

func TestUserRepository_List(t *testing.T) {
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
			name:       "list all users",
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
			_, repo := setupTestUserRepository(t)

			// Setup users
			for i := 0; i < tt.setupCount; i++ {
				user := &models.User{
					Username:     "testuser" + string(rune(i+'0')),
					Email:        "test" + string(rune(i+'0')) + "@example.com",
					PasswordHash: "hashed_password",
					Active:       true,
				}
				err := repo.Create(user)
				require.NoError(t, err)
				time.Sleep(2 * time.Millisecond) // Ensure different timestamps
			}

			users, err := repo.List(tt.limit, tt.offset)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, users, tt.wantCount)

				// Verify ordering (newest first)
				if len(users) > 1 {
					for i := 0; i < len(users)-1; i++ {
						assert.GreaterOrEqual(t, users[i].CreatedAt, users[i+1].CreatedAt)
					}
				}
			}
		})
	}
}

func TestUserRepository_AddToGroup(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   bool
		setupGroup  bool
		userID      string
		groupID     string
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful add",
			setupUser:  true,
			setupGroup: true,
			wantErr:    false,
		},
		{
			name:        "empty user ID",
			userID:      "",
			groupID:     "some-group",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "empty group ID",
			userID:      "some-user",
			groupID:     "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "user not found",
			setupGroup:  true,
			userID:      "non-existent-user",
			wantErr:     true,
			errContains: "failed to add user to group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, repo := setupTestUserRepository(t)
			groupRepo := NewGroupRepository(db)

			var userID, groupID string

			if tt.setupUser {
				user := &models.User{
					Username:     "testuser",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Active:       true,
				}
				err := repo.Create(user)
				require.NoError(t, err)
				userID = user.ID
			} else {
				userID = tt.userID
			}

			if tt.setupGroup {
				group := &models.Group{
					Name:        "TestGroup",
					Description: "Test group",
					Active:      true,
				}
				err := groupRepo.Create(group)
				require.NoError(t, err)
				groupID = group.ID
			} else {
				groupID = tt.groupID
			}

			err := repo.AddToGroup(userID, groupID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify association
				groups, err := repo.GetUserGroups(userID)
				assert.NoError(t, err)
				assert.Len(t, groups, 1)
				assert.Equal(t, groupID, groups[0].ID)
			}
		})
	}
}

func TestUserRepository_RemoveFromGroup(t *testing.T) {
	tests := []struct {
		name        string
		setupAssoc  bool
		userID      string
		groupID     string
		wantErr     bool
		errContains string
	}{
		{
			name:       "successful remove",
			setupAssoc: true,
			wantErr:    false,
		},
		{
			name:        "empty user ID",
			userID:      "",
			groupID:     "some-group",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "empty group ID",
			userID:      "some-user",
			groupID:     "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "association not found",
			userID:      "user1",
			groupID:     "group1",
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, repo := setupTestUserRepository(t)
			groupRepo := NewGroupRepository(db)

			var userID, groupID string

			if tt.setupAssoc {
				user := &models.User{
					Username:     "testuser",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Active:       true,
				}
				err := repo.Create(user)
				require.NoError(t, err)
				userID = user.ID

				group := &models.Group{
					Name:        "TestGroup",
					Description: "Test group",
					Active:      true,
				}
				err = groupRepo.Create(group)
				require.NoError(t, err)
				groupID = group.ID

				err = repo.AddToGroup(userID, groupID)
				require.NoError(t, err)
			} else {
				userID = tt.userID
				groupID = tt.groupID
			}

			err := repo.RemoveFromGroup(userID, groupID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify removal
				groups, err := repo.GetUserGroups(userID)
				assert.NoError(t, err)
				assert.Empty(t, groups)
			}
		})
	}
}

func TestUserRepository_GetUserGroups(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   bool
		setupGroups int
		userID      string
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:        "multiple groups",
			setupUser:   true,
			setupGroups: 3,
			wantCount:   3,
			wantErr:     false,
		},
		{
			name:        "no groups",
			setupUser:   true,
			setupGroups: 0,
			wantCount:   0,
			wantErr:     false,
		},
		{
			name:        "empty user ID",
			setupUser:   false,
			userID:      "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, repo := setupTestUserRepository(t)
			groupRepo := NewGroupRepository(db)

			var userID string
			if tt.setupUser {
				user := &models.User{
					Username:     "testuser",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Active:       true,
				}
				err := repo.Create(user)
				require.NoError(t, err)
				userID = user.ID

				// Setup groups
				for i := 0; i < tt.setupGroups; i++ {
					group := &models.Group{
						Name:        "Group" + string(rune(i+'0')),
						Description: "Test group",
						Active:      true,
					}
					err := groupRepo.Create(group)
					require.NoError(t, err)

					err = repo.AddToGroup(userID, group.ID)
					require.NoError(t, err)
				}
			} else {
				userID = tt.userID
			}

			groups, err := repo.GetUserGroups(userID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, groups, tt.wantCount)
			}
		})
	}
}

func TestUserRepository_GetUserPermissions(t *testing.T) {
	tests := []struct {
		name             string
		setupUser        bool
		setupPermissions int
		userID           string
		wantCount        int
		wantErr          bool
		errContains      string
	}{
		{
			name:             "multiple permissions through groups",
			setupUser:        true,
			setupPermissions: 3,
			wantCount:        3,
			wantErr:          false,
		},
		{
			name:             "no permissions",
			setupUser:        true,
			setupPermissions: 0,
			wantCount:        0,
			wantErr:          false,
		},
		{
			name:        "empty user ID",
			setupUser:   false,
			userID:      "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, repo := setupTestUserRepository(t)
			groupRepo := NewGroupRepository(db)
			permRepo := NewPermissionRepository(db)

			var userID string
			if tt.setupUser {
				user := &models.User{
					Username:     "testuser",
					Email:        "test@example.com",
					PasswordHash: "hashed_password",
					Active:       true,
				}
				err := repo.Create(user)
				require.NoError(t, err)
				userID = user.ID

				// Create group
				group := &models.Group{
					Name:        "TestGroup",
					Description: "Test group",
					Active:      true,
				}
				err = groupRepo.Create(group)
				require.NoError(t, err)

				// Add user to group
				err = repo.AddToGroup(userID, group.ID)
				require.NoError(t, err)

				// Setup permissions
				for i := 0; i < tt.setupPermissions; i++ {
					perm := &models.Permission{
						Name:        "Permission" + string(rune(i+'0')),
						Resource:    "resource" + string(rune(i+'0')),
						Action:      "action" + string(rune(i+'0')),
						Description: "Test permission",
						Active:      true,
					}
					err := permRepo.Create(perm)
					require.NoError(t, err)

					err = groupRepo.AddPermission(group.ID, perm.ID)
					require.NoError(t, err)
				}
			} else {
				userID = tt.userID
			}

			permissions, err := repo.GetUserPermissions(userID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, permissions, tt.wantCount)
			}
		})
	}
}

// Integration test for full CRUD lifecycle
func TestUserRepository_IntegrationFullLifecycle(t *testing.T) {
	db, repo := setupTestUserRepository(t)
	groupRepo := NewGroupRepository(db)
	permRepo := NewPermissionRepository(db)

	// Create user
	user := &models.User{
		Username:     "integrationuser",
		Email:        "integration@example.com",
		PasswordHash: "hashed_password",
		Active:       true,
	}
	err := repo.Create(user)
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)

	// Get user by ID
	retrieved, err := repo.GetByID(user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Username, retrieved.Username)

	// Get user by username
	retrieved, err = repo.GetByUsername(user.Username)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrieved.ID)

	// Get user by email
	retrieved, err = repo.GetByEmail(user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrieved.ID)

	// Update user
	user.Email = "updated@example.com"
	user.Active = false
	err = repo.Update(user)
	require.NoError(t, err)

	retrieved, err = repo.GetByID(user.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated@example.com", retrieved.Email)
	assert.False(t, retrieved.Active)

	// Create group and add user
	group := &models.Group{
		Name:        "IntegrationGroup",
		Description: "Test group",
		Active:      true,
	}
	err = groupRepo.Create(group)
	require.NoError(t, err)

	err = repo.AddToGroup(user.ID, group.ID)
	require.NoError(t, err)

	groups, err := repo.GetUserGroups(user.ID)
	require.NoError(t, err)
	assert.Len(t, groups, 1)

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

	err = groupRepo.AddPermission(group.ID, perm.ID)
	require.NoError(t, err)

	// Verify user has permission through group
	permissions, err := repo.GetUserPermissions(user.ID)
	require.NoError(t, err)
	assert.Len(t, permissions, 1)
	assert.Equal(t, perm.Name, permissions[0].Name)

	// Remove user from group
	err = repo.RemoveFromGroup(user.ID, group.ID)
	require.NoError(t, err)

	groups, err = repo.GetUserGroups(user.ID)
	require.NoError(t, err)
	assert.Empty(t, groups)

	// Delete user
	err = repo.Delete(user.ID)
	require.NoError(t, err)

	retrieved, err = repo.GetByID(user.ID)
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}

// Test SQL injection prevention
func TestUserRepository_SQLInjectionPrevention(t *testing.T) {
	_, repo := setupTestUserRepository(t)

	// Attempt SQL injection in username
	user := &models.User{
		Username:     "admin' OR '1'='1",
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
		Active:       true,
	}
	err := repo.Create(user)
	require.NoError(t, err)

	// Should not return any user when searching for SQL injection pattern
	retrieved, err := repo.GetByUsername("admin' OR '1'='1")
	require.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, user.ID, retrieved.ID)

	// Verify that only the user with exact username match is returned
	retrieved, err = repo.GetByUsername("admin")
	require.NoError(t, err)
	assert.Nil(t, retrieved)
}
