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
}
