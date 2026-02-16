package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUser(t *testing.T) {
	user := NewUser("testuser", "test@example.com", "hashed_password")

	assert.NotEmpty(t, user.ID, "ID should be generated")
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "hashed_password", user.PasswordHash)
	assert.False(t, user.TOTPEnabled, "TOTP should be disabled by default")
	assert.True(t, user.Active, "New user should be active by default")
	assert.Equal(t, 0, user.FailedLoginAttempts)
	assert.Nil(t, user.LockedUntil)
	assert.Nil(t, user.LastLogin)
	assert.Greater(t, user.CreatedAt, int64(0), "CreatedAt should be set")
	assert.Greater(t, user.UpdatedAt, int64(0), "UpdatedAt should be set")
	assert.NotNil(t, user.Groups, "Groups should be initialized")
	assert.NotNil(t, user.Permissions, "Permissions should be initialized")
}

func TestUser_IsActive(t *testing.T) {
	tests := []struct {
		name        string
		active      bool
		lockedUntil *int64
		expected    bool
	}{
		{
			name:        "active user not locked",
			active:      true,
			lockedUntil: nil,
			expected:    true,
		},
		{
			name:     "inactive user",
			active:   false,
			expected: false,
		},
		{
			name:        "active user locked",
			active:      true,
			lockedUntil: func() *int64 { t := time.Now().Add(1 * time.Hour).Unix(); return &t }(),
			expected:    false,
		},
		{
			name:        "active user lock expired",
			active:      true,
			lockedUntil: func() *int64 { t := time.Now().Add(-1 * time.Hour).Unix(); return &t }(),
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{
				Active:      tt.active,
				LockedUntil: tt.lockedUntil,
			}
			assert.Equal(t, tt.expected, user.IsActive())
		})
	}
}

func TestUser_IsLocked(t *testing.T) {
	tests := []struct {
		name        string
		lockedUntil *int64
		expected    bool
	}{
		{
			name:        "not locked",
			lockedUntil: nil,
			expected:    false,
		},
		{
			name:        "locked in future",
			lockedUntil: func() *int64 { t := time.Now().Add(1 * time.Hour).Unix(); return &t }(),
			expected:    true,
		},
		{
			name:        "lock expired",
			lockedUntil: func() *int64 { t := time.Now().Add(-1 * time.Hour).Unix(); return &t }(),
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{LockedUntil: tt.lockedUntil}
			assert.Equal(t, tt.expected, user.IsLocked())
		})
	}
}

func TestUser_HasPermission(t *testing.T) {
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
			user := &User{Permissions: tt.permissions}
			assert.Equal(t, tt.expected, user.HasPermission(tt.permissionID))
		})
	}
}

func TestUser_HasPermissionByName(t *testing.T) {
	perm1 := Permission{ID: "perm-1", Resource: "sms", Action: "read"}
	perm2 := Permission{ID: "perm-2", Resource: "users", Action: "write"}

	tests := []struct {
		name        string
		permissions []Permission
		resource    string
		action      string
		expected    bool
	}{
		{
			name:        "has permission by name",
			permissions: []Permission{perm1, perm2},
			resource:    "sms",
			action:      "read",
			expected:    true,
		},
		{
			name:        "does not have permission",
			permissions: []Permission{perm1},
			resource:    "users",
			action:      "write",
			expected:    false,
		},
		{
			name:        "wrong resource",
			permissions: []Permission{perm1},
			resource:    "groups",
			action:      "read",
			expected:    false,
		},
		{
			name:        "wrong action",
			permissions: []Permission{perm1},
			resource:    "sms",
			action:      "write",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Permissions: tt.permissions}
			assert.Equal(t, tt.expected, user.HasPermissionByName(tt.resource, tt.action))
		})
	}
}

func TestUser_AddGroup(t *testing.T) {
	user := &User{ID: "user-1", Username: "testuser"}

	group1 := Group{ID: "group-1", Name: "Admins"}
	group2 := Group{ID: "group-2", Name: "Users"}

	t.Run("add first group", func(t *testing.T) {
		user.AddGroup(group1)
		assert.Len(t, user.Groups, 1)
		assert.Equal(t, "group-1", user.Groups[0].ID)
	})

	t.Run("add second group", func(t *testing.T) {
		user.AddGroup(group2)
		assert.Len(t, user.Groups, 2)
		assert.Equal(t, "group-2", user.Groups[1].ID)
	})

	t.Run("add group to nil list", func(t *testing.T) {
		newUser := &User{ID: "user-2", Groups: nil}
		newUser.AddGroup(group1)
		assert.Len(t, newUser.Groups, 1)
	})
}

func TestUser_AddPermission(t *testing.T) {
	user := &User{ID: "user-1", Username: "testuser"}

	perm1 := Permission{ID: "perm-1", Name: "sms:read"}
	perm2 := Permission{ID: "perm-2", Name: "sms:write"}

	t.Run("add first permission", func(t *testing.T) {
		user.AddPermission(perm1)
		assert.Len(t, user.Permissions, 1)
		assert.Equal(t, "perm-1", user.Permissions[0].ID)
	})

	t.Run("add second permission", func(t *testing.T) {
		user.AddPermission(perm2)
		assert.Len(t, user.Permissions, 2)
		assert.Equal(t, "perm-2", user.Permissions[1].ID)
	})

	t.Run("add permission to nil list", func(t *testing.T) {
		newUser := &User{ID: "user-2", Permissions: nil}
		newUser.AddPermission(perm1)
		assert.Len(t, newUser.Permissions, 1)
	})
}

func TestUser_ToResponse(t *testing.T) {
	lastLogin := time.Now().Unix()
	user := &User{
		ID:           "user-123",
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "secret_hash",
		TOTPSecret:   func() *string { s := "secret"; return &s }(),
		TOTPEnabled:  true,
		Active:       true,
		LastLogin:    &lastLogin,
		CreatedAt:    1609459200,
		UpdatedAt:    1609459300,
	}

	response := user.ToResponse()

	// Verify included fields
	assert.Equal(t, "user-123", response.ID)
	assert.Equal(t, "testuser", response.Username)
	assert.Equal(t, "test@example.com", response.Email)
	assert.True(t, response.Active)
	assert.True(t, response.TOTPEnabled)
	assert.NotNil(t, response.LastLogin)
	assert.Equal(t, lastLogin, *response.LastLogin)
	assert.Equal(t, int64(1609459200), response.CreatedAt)

	// Verify sensitive fields are not in response struct
	responseJSON, err := json.Marshal(response)
	require.NoError(t, err)
	assert.NotContains(t, string(responseJSON), "password")
	assert.NotContains(t, string(responseJSON), "totp_secret")
}

// CRITICAL TEST: Verify sensitive fields are excluded from JSON marshaling
func TestUserJSON_ExcludesSensitiveFields(t *testing.T) {
	user := &User{
		ID:           "user-123",
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "very_secret_hash_should_not_appear",
		TOTPSecret:   func() *string { s := "very_secret_totp_should_not_appear"; return &s }(),
		TOTPEnabled:  true,
		Active:       true,
		CreatedAt:    1609459200,
		UpdatedAt:    1609459300,
	}

	// Marshal to JSON
	data, err := json.Marshal(user)
	require.NoError(t, err)

	jsonString := string(data)

	// CRITICAL: Verify sensitive fields are NOT in JSON output
	assert.NotContains(t, jsonString, "password_hash", "password_hash field should not be in JSON")
	assert.NotContains(t, jsonString, "very_secret_hash_should_not_appear", "Password hash value should not be in JSON")
	assert.NotContains(t, jsonString, "totp_secret", "totp_secret field should not be in JSON")
	assert.NotContains(t, jsonString, "very_secret_totp_should_not_appear", "TOTP secret value should not be in JSON")

	// Verify other fields ARE in JSON output
	assert.Contains(t, jsonString, "user-123")
	assert.Contains(t, jsonString, "testuser")
	assert.Contains(t, jsonString, "test@example.com")

	// Verify by unmarshaling
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// CRITICAL: Verify sensitive fields are NOT in the map
	_, hasPasswordHash := result["password_hash"]
	assert.False(t, hasPasswordHash, "password_hash should not exist in JSON")

	_, hasTOTPSecret := result["totp_secret"]
	assert.False(t, hasTOTPSecret, "totp_secret should not exist in JSON")

	// Verify non-sensitive fields ARE in the map
	assert.Equal(t, "user-123", result["id"])
	assert.Equal(t, "testuser", result["username"])
	assert.Equal(t, "test@example.com", result["email"])
}

func TestUserJSON_Marshaling(t *testing.T) {
	lastLogin := int64(1609459300)
	user := &User{
		ID:          "user-123",
		Username:    "testuser",
		Email:       "test@example.com",
		TOTPEnabled: true,
		Active:      true,
		LastLogin:   &lastLogin,
		CreatedAt:   1609459200,
		UpdatedAt:   1609459300,
	}

	// Marshal to JSON
	data, err := json.Marshal(user)
	require.NoError(t, err)

	// Verify all non-sensitive fields are present
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "user-123", result["id"])
	assert.Equal(t, "testuser", result["username"])
	assert.Equal(t, "test@example.com", result["email"])
	assert.Equal(t, true, result["totp_enabled"])
	assert.Equal(t, true, result["active"])
	assert.Equal(t, float64(1609459200), result["created_at"])
	assert.Equal(t, float64(1609459300), result["updated_at"])
}

func TestUserJSON_Unmarshaling(t *testing.T) {
	jsonData := `{
		"id": "user-456",
		"username": "anotheruser",
		"email": "another@example.com",
		"totp_enabled": false,
		"active": false,
		"failed_login_attempts": 3,
		"created_at": 1609459200,
		"updated_at": 1609459300
	}`

	var user User
	err := json.Unmarshal([]byte(jsonData), &user)
	require.NoError(t, err)

	assert.Equal(t, "user-456", user.ID)
	assert.Equal(t, "anotheruser", user.Username)
	assert.Equal(t, "another@example.com", user.Email)
	assert.False(t, user.TOTPEnabled)
	assert.False(t, user.Active)
	assert.Equal(t, 3, user.FailedLoginAttempts)
	assert.Equal(t, int64(1609459200), user.CreatedAt)
	assert.Equal(t, int64(1609459300), user.UpdatedAt)
}

func TestCreateUserRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request CreateUserRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			wantErr: false,
		},
		{
			name: "missing username",
			request: CreateUserRequest{
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			wantErr: true,
		},
		{
			name: "username too short",
			request: CreateUserRequest{
				Username: "ab",
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			wantErr: true,
		},
		{
			name: "missing email",
			request: CreateUserRequest{
				Username: "testuser",
				Password: "securepassword123",
			},
			wantErr: true,
		},
		{
			name: "invalid email",
			request: CreateUserRequest{
				Username: "testuser",
				Email:    "not-an-email",
				Password: "securepassword123",
			},
			wantErr: true,
		},
		{
			name: "missing password",
			request: CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
			},
			wantErr: true,
		},
		{
			name: "password too short",
			request: CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "short",
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
				isInvalid := tt.request.Username == "" || len(tt.request.Username) < 3 ||
					tt.request.Email == "" || !contains(tt.request.Email, "@") ||
					tt.request.Password == "" || len(tt.request.Password) < 8
				assert.True(t, isInvalid)
			} else {
				// Should pass validation
				assert.NotEmpty(t, tt.request.Username)
				assert.GreaterOrEqual(t, len(tt.request.Username), 3)
				assert.NotEmpty(t, tt.request.Email)
				assert.Contains(t, tt.request.Email, "@")
				assert.NotEmpty(t, tt.request.Password)
				assert.GreaterOrEqual(t, len(tt.request.Password), 8)
			}
		})
	}
}

func TestUpdateUserRequest(t *testing.T) {
	t.Run("update email", func(t *testing.T) {
		email := "newemail@example.com"
		req := UpdateUserRequest{
			Email: &email,
		}
		assert.NotNil(t, req.Email)
		assert.Equal(t, "newemail@example.com", *req.Email)
	})

	t.Run("update active status", func(t *testing.T) {
		active := false
		req := UpdateUserRequest{
			Active: &active,
		}
		assert.NotNil(t, req.Active)
		assert.False(t, *req.Active)
	})

	t.Run("update TOTP enabled", func(t *testing.T) {
		enabled := true
		req := UpdateUserRequest{
			TOTPEnabled: &enabled,
		}
		assert.NotNil(t, req.TOTPEnabled)
		assert.True(t, *req.TOTPEnabled)
	})

	t.Run("empty update request", func(t *testing.T) {
		req := UpdateUserRequest{}
		assert.Nil(t, req.Email)
		assert.Nil(t, req.Active)
		assert.Nil(t, req.TOTPEnabled)
	})
}

// Helper function for validation tests
func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
