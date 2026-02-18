package handlers

import (
	"sms-sync-server/internal/models"
)

// UserServiceInterface defines the contract for user service operations
// This interface is used for dependency injection and testing
type UserServiceInterface interface {
	CreateUser(username, email, password string) (*models.User, error)
	Authenticate(username, password, totpCode string) (*models.User, error)
	GetUserWithPermissions(userID string) (*models.User, error)
	GetUser(id string) (*models.User, error)
	UpdateUser(id string, updates map[string]interface{}) error
	DeleteUser(id string) error
	ChangePassword(id, oldPassword, newPassword string) error
	AdminSetPassword(id, newPassword string) error
	ListUsers(limit, offset int) ([]*models.User, error)
	AssignToGroup(userID, groupID string) error
	RemoveFromGroup(userID, groupID string) error

	// 2FA/TOTP methods
	GenerateTOTPSecret(userID string) (string, error)
	EnableTOTP(userID, totpCode string) error
	DisableTOTP(userID string) error
}

// GroupServiceInterface defines the contract for group service operations
// This interface is used for dependency injection and testing
type GroupServiceInterface interface {
	CreateGroup(name, description string) (*models.Group, error)
	GetGroup(id string) (*models.Group, error)
	UpdateGroup(id string, updates map[string]interface{}) error
	DeleteGroup(id string) error
	ListGroups(limit, offset int) ([]*models.Group, error)
	AddPermission(groupID, permissionID string) error
	RemovePermission(groupID, permissionID string) error
}

// PermissionServiceInterface defines the contract for permission service operations
// This interface is used for dependency injection and testing
type PermissionServiceInterface interface {
	CreatePermission(name, resource, action, description string) (*models.Permission, error)
	GetPermission(id string) (*models.Permission, error)
	UpdatePermission(id string, updates map[string]interface{}) error
	DeletePermission(id string) error
	ListPermissions(limit, offset int) ([]*models.Permission, error)
}
