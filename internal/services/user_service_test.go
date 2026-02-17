package services

import (
	"database/sql"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"sms-sync-server/internal/db"
	"sms-sync-server/internal/models"
)

func setupTestUserService(t *testing.T) (*sql.DB, *UserService) {
	database := db.SetupTestDB(t)
	repo := db.NewUserRepository(database)
	service := NewUserService(repo)
	return database, service
}

func TestUserService_CreateUser(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		email       string
		password    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "successful creation",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			wantErr:  false,
		},
		{
			name:     "successful creation without email",
			username: "testuser2",
			email:    "",
			password: "password123",
			wantErr:  false,
		},
		{
			name:        "username too short",
			username:    "ab",
			email:       "test@example.com",
			password:    "password123",
			wantErr:     true,
			errContains: "3-50 characters",
		},
		{
			name:        "username too long",
			username:    "a_very_long_username_that_exceeds_the_maximum_allowed_length",
			email:       "test@example.com",
			password:    "password123",
			wantErr:     true,
			errContains: "3-50 characters",
		},
		{
			name:        "username with invalid characters",
			username:    "test-user",
			email:       "test@example.com",
			password:    "password123",
			wantErr:     true,
			errContains: "alphanumeric",
		},
		{
			name:        "invalid email format",
			username:    "testuser",
			email:       "invalid-email",
			password:    "password123",
			wantErr:     true,
			errContains: "invalid email",
		},
		{
			name:        "password too short",
			username:    "testuser",
			email:       "test@example.com",
			password:    "short",
			wantErr:     true,
			errContains: "at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, service := setupTestUserService(t)

			user, err := service.CreateUser(tt.username, tt.email, tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.username, user.Username)
				assert.Equal(t, tt.email, user.Email)
				assert.NotEmpty(t, user.ID)
				assert.True(t, user.Active)
				assert.Equal(t, 0, user.FailedLoginAttempts)
				assert.False(t, user.TOTPEnabled)

				// Verify password was hashed
				err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(tt.password))
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserService_CreateUser_DuplicateUsername(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create first user
	_, err := service.CreateUser("testuser", "test1@example.com", "password123")
	require.NoError(t, err)

	// Try to create user with same username
	_, err = service.CreateUser("testuser", "test2@example.com", "password456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "username already exists")
}

func TestUserService_CreateUser_DuplicateEmail(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create first user
	_, err := service.CreateUser("testuser1", "test@example.com", "password123")
	require.NoError(t, err)

	// Try to create user with same email
	_, err = service.CreateUser("testuser2", "test@example.com", "password456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email already exists")
}

func TestUserService_Authenticate(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   bool
		username    string
		password    string
		totpEnabled bool
		totpCode    string
		lockAccount bool
		inactive    bool
		wantErr     bool
		errContains string
	}{
		{
			name:      "successful authentication",
			setupUser: true,
			username:  "testuser",
			password:  "password123",
			wantErr:   false,
		},
		{
			name:        "invalid username",
			setupUser:   false,
			username:    "nonexistent",
			password:    "password123",
			wantErr:     true,
			errContains: "invalid username or password",
		},
		{
			name:        "invalid password",
			setupUser:   true,
			username:    "testuser",
			password:    "wrongpassword",
			wantErr:     true,
			errContains: "invalid username or password",
		},
		{
			name:        "account locked",
			setupUser:   true,
			username:    "testuser",
			password:    "password123",
			lockAccount: true,
			wantErr:     true,
			errContains: "account is locked",
		},
		{
			name:        "inactive account",
			setupUser:   true,
			username:    "testuser",
			password:    "password123",
			inactive:    true,
			wantErr:     true,
			errContains: "inactive",
		},
		{
			name:        "TOTP enabled but no code",
			setupUser:   true,
			username:    "testuser",
			password:    "password123",
			totpEnabled: true,
			totpCode:    "",
			wantErr:     true,
			errContains: "invalid TOTP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database, service := setupTestUserService(t)

			var createdUser *models.User
			if tt.setupUser {
				var err error
				// Always create with "password123", then use tt.password for authentication test
				createdUser, err = service.CreateUser(tt.username, "test@example.com", "password123")
				require.NoError(t, err)

				if tt.lockAccount {
					lockUntil := time.Now().Add(30 * time.Minute).Unix()
					createdUser.LockedUntil = &lockUntil
					repo := db.NewUserRepository(database)
					err = repo.Update(createdUser)
					require.NoError(t, err)
				}

				if tt.inactive {
					err = service.UpdateUser(createdUser.ID, map[string]interface{}{"active": false})
					require.NoError(t, err)
				}

				if tt.totpEnabled {
					secret, err := service.GenerateTOTPSecret(createdUser.ID)
					require.NoError(t, err)
					code, err := totp.GenerateCode(secret, time.Now())
					require.NoError(t, err)
					err = service.EnableTOTP(createdUser.ID, code)
					require.NoError(t, err)
				}
			}

			user, err := service.Authenticate(tt.username, tt.password, tt.totpCode)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, user)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, user)
			if user != nil {
				assert.Equal(t, tt.username, user.Username)
				assert.Equal(t, 0, user.FailedLoginAttempts)
				assert.NotNil(t, user.LastLogin)
				assert.Greater(t, *user.LastLogin, int64(0))
			}
		})
	}
}

func TestUserService_Authenticate_WithValidTOTP(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	// Generate and enable TOTP
	secret, err := service.GenerateTOTPSecret(user.ID)
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	err = service.EnableTOTP(user.ID, code)
	require.NoError(t, err)

	// Generate current TOTP code for authentication
	currentCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	// Authenticate with valid TOTP
	authUser, err := service.Authenticate("testuser", "password123", currentCode)
	assert.NoError(t, err)
	assert.NotNil(t, authUser)
	assert.Equal(t, user.ID, authUser.ID)
}

func TestUserService_AccountLockout(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	// Fail authentication 5 times
	for i := 0; i < MaxFailedLoginAttempts; i++ {
		_, err := service.Authenticate("testuser", "wrongpassword", "")
		assert.Error(t, err)
	}

	// Get user to check lock status
	lockedUser, err := service.GetUser(user.ID)
	require.NoError(t, err)
	assert.Equal(t, MaxFailedLoginAttempts, lockedUser.FailedLoginAttempts)
	assert.NotNil(t, lockedUser.LockedUntil)
	assert.Greater(t, *lockedUser.LockedUntil, time.Now().Unix())

	// Try to authenticate with correct password - should fail due to lock
	_, err = service.Authenticate("testuser", "password123", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
}

func TestUserService_GetUser(t *testing.T) {
	tests := []struct {
		name        string
		setupUser   bool
		userID      string
		wantErr     bool
		errContains string
	}{
		{
			name:      "successful retrieval",
			setupUser: true,
			wantErr:   false,
		},
		{
			name:        "empty user ID",
			setupUser:   false,
			userID:      "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "non-existent user",
			setupUser:   false,
			userID:      "non-existent-id",
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, service := setupTestUserService(t)

			var userID string
			if tt.setupUser {
				user, err := service.CreateUser("testuser", "test@example.com", "password123")
				require.NoError(t, err)
				userID = user.ID
			} else {
				userID = tt.userID
			}

			user, err := service.GetUser(userID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, userID, user.ID)
			}
		})
	}
}

func TestUserService_UpdateUser(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	tests := []struct {
		name        string
		updates     map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name: "update username",
			updates: map[string]interface{}{
				"username": "newusername",
			},
			wantErr: false,
		},
		{
			name: "update email",
			updates: map[string]interface{}{
				"email": "newemail@example.com",
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
			name: "invalid username",
			updates: map[string]interface{}{
				"username": "ab",
			},
			wantErr:     true,
			errContains: "3-50 characters",
		},
		{
			name: "invalid email",
			updates: map[string]interface{}{
				"email": "invalid-email",
			},
			wantErr:     true,
			errContains: "invalid email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.UpdateUser(user.ID, tt.updates)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify update
				updatedUser, err := service.GetUser(user.ID)
				require.NoError(t, err)

				if username, ok := tt.updates["username"].(string); ok {
					assert.Equal(t, username, updatedUser.Username)
				}
				if email, ok := tt.updates["email"].(string); ok {
					assert.Equal(t, email, updatedUser.Email)
				}
				if active, ok := tt.updates["active"].(bool); ok {
					assert.Equal(t, active, updatedUser.Active)
				}
			}
		})
	}
}

func TestUserService_DeleteUser(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	// Delete user
	err = service.DeleteUser(user.ID)
	assert.NoError(t, err)

	// Verify user is deleted
	_, err = service.GetUser(user.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUserService_ListUsers(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create multiple users with unique emails
	for i := 0; i < 5; i++ {
		email := "testuser" + string(rune(i+'0')) + "@example.com"
		_, err := service.CreateUser("testuser"+string(rune(i+'0')), email, "password123")
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
			name:      "list all users",
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
			users, err := service.ListUsers(tt.limit, tt.offset)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, users, tt.wantCount)
			}
		})
	}
}

func TestUserService_ChangePassword(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "oldpassword123")
	require.NoError(t, err)

	tests := []struct {
		name        string
		oldPassword string
		newPassword string
		wantErr     bool
		errContains string
	}{
		{
			name:        "successful password change",
			oldPassword: "oldpassword123",
			newPassword: "newpassword456",
			wantErr:     false,
		},
		{
			name:        "incorrect old password",
			oldPassword: "wrongpassword",
			newPassword: "newpassword456",
			wantErr:     true,
			errContains: "incorrect old password",
		},
		{
			name:        "new password too short",
			oldPassword: "oldpassword123",
			newPassword: "short",
			wantErr:     true,
			errContains: "at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ChangePassword(user.ID, tt.oldPassword, tt.newPassword)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify new password works
				authUser, err := service.Authenticate("testuser", tt.newPassword, "")
				assert.NoError(t, err)
				assert.NotNil(t, authUser)
			}
		})
	}
}

func TestUserService_AssignToGroup(t *testing.T) {
	database, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	// Create group
	groupRepo := db.NewGroupRepository(database)
	group := &models.Group{
		Name:        "TestGroup",
		Description: "Test group",
		Active:      true,
	}
	err = groupRepo.Create(group)
	require.NoError(t, err)

	// Assign user to group
	err = service.AssignToGroup(user.ID, group.ID)
	assert.NoError(t, err)

	// Verify assignment
	userRepo := db.NewUserRepository(database)
	groups, err := userRepo.GetUserGroups(user.ID)
	assert.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.Equal(t, group.ID, groups[0].ID)
}

func TestUserService_RemoveFromGroup(t *testing.T) {
	database, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	// Create group
	groupRepo := db.NewGroupRepository(database)
	group := &models.Group{
		Name:        "TestGroup",
		Description: "Test group",
		Active:      true,
	}
	err = groupRepo.Create(group)
	require.NoError(t, err)

	// Assign user to group
	err = service.AssignToGroup(user.ID, group.ID)
	require.NoError(t, err)

	// Remove user from group
	err = service.RemoveFromGroup(user.ID, group.ID)
	assert.NoError(t, err)

	// Verify removal
	userRepo := db.NewUserRepository(database)
	groups, err := userRepo.GetUserGroups(user.ID)
	assert.NoError(t, err)
	assert.Len(t, groups, 0)
}

func TestUserService_IncrementAndResetFailedLogin(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	// Increment failed login attempts
	for i := 1; i <= 3; i++ {
		err = service.IncrementFailedLogin(user.ID)
		assert.NoError(t, err)

		updatedUser, err := service.GetUser(user.ID)
		require.NoError(t, err)
		assert.Equal(t, i, updatedUser.FailedLoginAttempts)
	}

	// Reset failed login
	err = service.ResetFailedLogin(user.ID)
	assert.NoError(t, err)

	// Verify reset
	updatedUser, err := service.GetUser(user.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, updatedUser.FailedLoginAttempts)
	assert.Nil(t, updatedUser.LockedUntil)
}

func TestUserService_TOTP(t *testing.T) {
	_, service := setupTestUserService(t)

	// Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)

	// Generate TOTP secret
	secret, err := service.GenerateTOTPSecret(user.ID)
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Verify secret is saved
	updatedUser, err := service.GetUser(user.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedUser.TOTPSecret)
	assert.Equal(t, secret, *updatedUser.TOTPSecret)
	assert.False(t, updatedUser.TOTPEnabled)

	// Generate valid TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	// Enable TOTP with valid code
	err = service.EnableTOTP(user.ID, code)
	assert.NoError(t, err)

	// Verify TOTP is enabled
	updatedUser, err = service.GetUser(user.ID)
	require.NoError(t, err)
	assert.True(t, updatedUser.TOTPEnabled)

	// Disable TOTP
	err = service.DisableTOTP(user.ID)
	assert.NoError(t, err)

	// Verify TOTP is disabled and secret cleared
	updatedUser, err = service.GetUser(user.ID)
	require.NoError(t, err)
	assert.False(t, updatedUser.TOTPEnabled)
	assert.Nil(t, updatedUser.TOTPSecret)
}

func TestUserService_IntegrationFullLifecycle(t *testing.T) {
	database, service := setupTestUserService(t)

	// 1. Create user
	user, err := service.CreateUser("testuser", "test@example.com", "password123")
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)

	// 2. Authenticate
	authUser, err := service.Authenticate("testuser", "password123", "")
	require.NoError(t, err)
	assert.Equal(t, user.ID, authUser.ID)

	// 3. Update user
	err = service.UpdateUser(user.ID, map[string]interface{}{
		"email": "updated@example.com",
	})
	require.NoError(t, err)

	updatedUser, err := service.GetUser(user.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated@example.com", updatedUser.Email)

	// 4. Change password
	err = service.ChangePassword(user.ID, "password123", "newpassword456")
	require.NoError(t, err)

	// Verify new password works
	_, err = service.Authenticate("testuser", "newpassword456", "")
	assert.NoError(t, err)

	// 5. Enable TOTP
	secret, err := service.GenerateTOTPSecret(user.ID)
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	err = service.EnableTOTP(user.ID, code)
	require.NoError(t, err)

	// 6. Authenticate with TOTP
	currentCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	_, err = service.Authenticate("testuser", "newpassword456", currentCode)
	assert.NoError(t, err)

	// 7. Assign to group
	groupRepo := db.NewGroupRepository(database)
	group := &models.Group{
		Name:        "TestGroup",
		Description: "Test group",
		Active:      true,
	}
	err = groupRepo.Create(group)
	require.NoError(t, err)

	err = service.AssignToGroup(user.ID, group.ID)
	require.NoError(t, err)

	// 8. List users
	users, err := service.ListUsers(10, 0)
	require.NoError(t, err)
	assert.Len(t, users, 1)

	// 9. Delete user
	err = service.DeleteUser(user.ID)
	require.NoError(t, err)

	_, err = service.GetUser(user.ID)
	assert.Error(t, err)
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid username", "testuser", false},
		{"valid with numbers", "user123", false},
		{"valid with underscore", "test_user", false},
		{"too short", "ab", true},
		{"too long", "a_very_long_username_that_exceeds_the_maximum_length_allowed", true},
		{"with hyphen", "test-user", true},
		{"with space", "test user", true},
		{"with special chars", "test@user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.username)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "test@example.com", false},
		{"valid with subdomain", "test@mail.example.com", false},
		{"empty email", "", false}, // Empty is allowed
		{"missing @", "testexample.com", true},
		{"missing domain", "test@", true},
		{"missing TLD", "test@example", true},
		{"invalid format", "test user@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEmail(tt.email)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid password", "password123", false},
		{"minimum length", "12345678", false},
		{"long password", "a_very_long_password_with_many_characters", false},
		{"too short", "short", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.password)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
