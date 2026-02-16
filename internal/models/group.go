package models

import (
	"time"

	"github.com/google/uuid"
)

// Group represents a user group in the RBAC system
// Groups contain permissions that can be assigned to multiple users
type Group struct {
	ID          string `json:"id"`                                    // UUID
	Name        string `json:"name" binding:"required,min=3,max=100"` // Unique group name
	Description string `json:"description,omitempty"`                 // Optional description
	Active      bool   `json:"active"`                                // Whether group is active
	CreatedAt   int64  `json:"created_at"`                            // Unix timestamp
	UpdatedAt   int64  `json:"updated_at"`                            // Unix timestamp

	// Relationships (not stored in DB, loaded separately)
	Permissions []Permission `json:"permissions,omitempty"` // Permissions assigned to this group
}

// CreateGroupRequest represents the request body for creating a new group
type CreateGroupRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=100"`
	Description string `json:"description,omitempty"`
}

// UpdateGroupRequest represents the request body for updating an existing group
type UpdateGroupRequest struct {
	Name        *string `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Description *string `json:"description,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

// NewGroup creates a new Group with generated UUID and timestamps
func NewGroup(name, description string) *Group {
	now := time.Now().Unix()
	return &Group{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		Active:      true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Permissions: []Permission{},
	}
}

// IsActive returns whether the group is currently active
func (g *Group) IsActive() bool {
	return g.Active
}

// HasPermission checks if the group has a specific permission by permission ID
func (g *Group) HasPermission(permissionID string) bool {
	if g.Permissions == nil {
		return false
	}

	for _, perm := range g.Permissions {
		if perm.ID == permissionID {
			return true
		}
	}

	return false
}

// AddPermission adds a permission to the group's permission list
// This is a helper method for in-memory operations, not for database updates
func (g *Group) AddPermission(permission Permission) {
	if g.Permissions == nil {
		g.Permissions = []Permission{}
	}
	g.Permissions = append(g.Permissions, permission)
}
