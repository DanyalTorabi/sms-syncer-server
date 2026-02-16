package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Permission represents a permission in the RBAC system
// Permissions define what actions can be performed on which resources
type Permission struct {
	ID          string `json:"id"`                                    // UUID
	Name        string `json:"name" binding:"required,min=3,max=100"` // Unique permission name
	Resource    string `json:"resource" binding:"required"`           // Resource type (e.g., "sms", "users")
	Action      string `json:"action" binding:"required"`             // Action type (e.g., "read", "write", "delete")
	Description string `json:"description,omitempty"`                 // Optional description
	Active      bool   `json:"active"`                                // Whether permission is active
	CreatedAt   int64  `json:"created_at"`                            // Unix timestamp
}

// CreatePermissionRequest represents the request body for creating a new permission
type CreatePermissionRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=100"`
	Resource    string `json:"resource" binding:"required"`
	Action      string `json:"action" binding:"required"`
	Description string `json:"description,omitempty"`
}

// UpdatePermissionRequest represents the request body for updating an existing permission
type UpdatePermissionRequest struct {
	Description *string `json:"description,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

// NewPermission creates a new Permission with generated UUID and timestamps
func NewPermission(name, resource, action, description string) *Permission {
	now := time.Now().Unix()
	return &Permission{
		ID:          uuid.New().String(),
		Name:        name,
		Resource:    resource,
		Action:      action,
		Description: description,
		Active:      true,
		CreatedAt:   now,
	}
}

// IsActive returns whether the permission is currently active
func (p *Permission) IsActive() bool {
	return p.Active
}

// FullName returns the permission in "resource:action" format
// This is useful for permission checking and display purposes
func (p *Permission) FullName() string {
	return fmt.Sprintf("%s:%s", p.Resource, p.Action)
}
