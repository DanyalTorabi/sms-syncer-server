package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system with authentication and RBAC capabilities
type User struct {
	ID                  string  `json:"id"`                                       // UUID
	Username            string  `json:"username" binding:"required,min=3,max=50"` // Unique username
	Email               string  `json:"email" binding:"required,email"`           // User email
	PasswordHash        string  `json:"-"`                                        // EXCLUDED from JSON - bcrypt hash
	TOTPSecret          *string `json:"-"`                                        // EXCLUDED from JSON - TOTP secret for 2FA
	TOTPEnabled         bool    `json:"totp_enabled"`                             // Whether 2FA is enabled
	Active              bool    `json:"active"`                                   // Whether user account is active
	FailedLoginAttempts int     `json:"failed_login_attempts"`                    // Number of consecutive failed login attempts
	LockedUntil         *int64  `json:"locked_until,omitempty"`                   // Unix timestamp when account lock expires
	LastLogin           *int64  `json:"last_login,omitempty"`                     // Unix timestamp of last successful login
	CreatedAt           int64   `json:"created_at"`                               // Unix timestamp of account creation
	UpdatedAt           int64   `json:"updated_at"`                               // Unix timestamp of last update

	// Relationships (not stored in DB, loaded separately)
	Groups      []Group      `json:"groups,omitempty"`      // Groups this user belongs to
	Permissions []Permission `json:"permissions,omitempty"` // Effective permissions from all groups
}

// CreateUserRequest represents the request body for creating a new user
type CreateUserRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"` // Plain password - will be hashed
}

// UpdateUserRequest represents the request body for updating an existing user
type UpdateUserRequest struct {
	Email       *string `json:"email,omitempty" binding:"omitempty,email"`
	Active      *bool   `json:"active,omitempty"`
	TOTPEnabled *bool   `json:"totp_enabled,omitempty"`
}

// UserResponse represents a safe user representation for API responses
// This excludes all sensitive fields and is safe to send to clients
type UserResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Active      bool   `json:"active"`
	TOTPEnabled bool   `json:"totp_enabled"`
	LastLogin   *int64 `json:"last_login,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

// NewUser creates a new User with generated UUID and timestamps
// The password should already be hashed before calling this function
func NewUser(username, email, passwordHash string) *User {
	now := time.Now().Unix()
	return &User{
		ID:                  uuid.New().String(),
		Username:            username,
		Email:               email,
		PasswordHash:        passwordHash,
		TOTPEnabled:         false,
		Active:              true,
		FailedLoginAttempts: 0,
		CreatedAt:           now,
		UpdatedAt:           now,
		Groups:              []Group{},
		Permissions:         []Permission{},
	}
}

// IsActive returns whether the user account is active and not locked
func (u *User) IsActive() bool {
	if !u.Active {
		return false
	}

	return !u.IsLocked()
}

// IsLocked returns whether the user account is currently locked
// An account is locked if LockedUntil is set and in the future
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}

	now := time.Now().Unix()
	return *u.LockedUntil > now
}

// HasPermission checks if the user has a specific permission (by permission ID)
// This checks all permissions loaded from the user's groups
func (u *User) HasPermission(permissionID string) bool {
	if u.Permissions == nil {
		return false
	}

	for _, perm := range u.Permissions {
		if perm.ID == permissionID {
			return true
		}
	}

	return false
}

// HasPermissionByName checks if the user has a permission by its full name (resource:action)
func (u *User) HasPermissionByName(resource, action string) bool {
	if u.Permissions == nil {
		return false
	}

	for _, perm := range u.Permissions {
		if perm.Resource == resource && perm.Action == action {
			return true
		}
	}

	return false
}

// AddGroup adds a group to the user's group list
// This is a helper method for in-memory operations, not for database updates
func (u *User) AddGroup(group Group) {
	if u.Groups == nil {
		u.Groups = []Group{}
	}
	u.Groups = append(u.Groups, group)
}

// AddPermission adds a permission to the user's permission list
// This is a helper method for in-memory operations, not for database updates
func (u *User) AddPermission(permission Permission) {
	if u.Permissions == nil {
		u.Permissions = []Permission{}
	}
	u.Permissions = append(u.Permissions, permission)
}

// ToResponse converts User to UserResponse, excluding all sensitive fields
// This is safe to send to clients via API responses
func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Active:      u.Active,
		TOTPEnabled: u.TOTPEnabled,
		LastLogin:   u.LastLogin,
		CreatedAt:   u.CreatedAt,
	}
}
