package services

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"sms-sync-server/internal/db"
	"sms-sync-server/internal/models"
)

var (
	// ErrPermissionNotFound indicates permission does not exist
	ErrPermissionNotFound = errors.New("permission not found")

	// ErrPermissionInUse indicates permission is used by groups
	ErrPermissionInUse = errors.New("permission cannot be deleted as it is in use by groups")

	// ErrInvalidPermissionName indicates permission name validation failure
	ErrInvalidPermissionName = errors.New("permission name must follow resource:action format")
)

// PermissionService provides business logic for permission management
type PermissionService struct {
	repo      db.PermissionRepository
	groupRepo db.GroupRepository
}

// NewPermissionService creates a new PermissionService instance
func NewPermissionService(repo db.PermissionRepository, groupRepo db.GroupRepository) *PermissionService {
	return &PermissionService{
		repo:      repo,
		groupRepo: groupRepo,
	}
}

// CreatePermission creates a new permission with validation
func (s *PermissionService) CreatePermission(name, resource, action, description string) (*models.Permission, error) {
	// Validate permission name format (resource:action)
	if err := validatePermissionName(name); err != nil {
		return nil, err
	}

	// Validate resource and action
	if strings.TrimSpace(resource) == "" {
		return nil, errors.New("resource cannot be empty")
	}
	if strings.TrimSpace(action) == "" {
		return nil, errors.New("action cannot be empty")
	}

	// Check if permission name already exists
	existingPerm, err := s.repo.GetByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to check permission name: %w", err)
	}
	if existingPerm != nil {
		return nil, errors.New("permission name already exists")
	}

	// Create permission
	permission := &models.Permission{
		Name:        name,
		Resource:    resource,
		Action:      action,
		Description: description,
		Active:      true,
	}

	if err := s.repo.Create(permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	return permission, nil
}

// GetPermission retrieves a permission by ID
func (s *PermissionService) GetPermission(id string) (*models.Permission, error) {
	if id == "" {
		return nil, errors.New("permission ID cannot be empty")
	}

	permission, err := s.repo.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	if permission == nil {
		return nil, ErrPermissionNotFound
	}

	return permission, nil
}

// UpdatePermission updates permission fields
func (s *PermissionService) UpdatePermission(id string, updates map[string]interface{}) error {
	if id == "" {
		return errors.New("permission ID cannot be empty")
	}

	// Get existing permission
	permission, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get permission: %w", err)
	}
	if permission == nil {
		return ErrPermissionNotFound
	}

	// Validate and apply updates
	if name, ok := updates["name"].(string); ok {
		if err := validatePermissionName(name); err != nil {
			return err
		}
		// Check name uniqueness
		existingPerm, err := s.repo.GetByName(name)
		if err != nil {
			return fmt.Errorf("failed to check permission name: %w", err)
		}
		if existingPerm != nil && existingPerm.ID != id {
			return errors.New("permission name already exists")
		}
		permission.Name = name
	}

	if resource, ok := updates["resource"].(string); ok {
		if strings.TrimSpace(resource) == "" {
			return errors.New("resource cannot be empty")
		}
		permission.Resource = resource
	}

	if action, ok := updates["action"].(string); ok {
		if strings.TrimSpace(action) == "" {
			return errors.New("action cannot be empty")
		}
		permission.Action = action
	}

	if description, ok := updates["description"].(string); ok {
		permission.Description = description
	}

	if active, ok := updates["active"].(bool); ok {
		permission.Active = active
	}

	// Update permission
	if err := s.repo.Update(permission); err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}

	return nil
}

// DeletePermission deletes a permission after checking if it's in use
func (s *PermissionService) DeletePermission(id string) error {
	if id == "" {
		return errors.New("permission ID cannot be empty")
	}

	// Get permission
	permission, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get permission: %w", err)
	}
	if permission == nil {
		return ErrPermissionNotFound
	}

	// Check if permission is used by any groups
	groups, err := s.groupRepo.List(1000, 0) // Get all groups (reasonable limit)
	if err != nil {
		return fmt.Errorf("failed to check permission usage: %w", err)
	}

	for _, group := range groups {
		permissions, err := s.groupRepo.GetGroupPermissions(group.ID)
		if err != nil {
			return fmt.Errorf("failed to get group permissions: %w", err)
		}

		for _, perm := range permissions {
			if perm.ID == id {
				return ErrPermissionInUse
			}
		}
	}

	// Delete permission
	if err := s.repo.Delete(id); err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	return nil
}

// ListPermissions retrieves a paginated list of permissions
func (s *PermissionService) ListPermissions(limit, offset int) ([]*models.Permission, error) {
	if limit < 0 {
		return nil, errors.New("limit cannot be negative")
	}
	if offset < 0 {
		return nil, errors.New("offset cannot be negative")
	}

	permissions, err := s.repo.List(limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}

	return permissions, nil
}

// validatePermissionName validates that permission name follows resource:action format
func validatePermissionName(name string) error {
	if strings.TrimSpace(name) == "" {
		return ErrInvalidPermissionName
	}

	// Check for resource:action format
	validFormat := regexp.MustCompile(`^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$`)
	if !validFormat.MatchString(name) {
		return ErrInvalidPermissionName
	}

	return nil
}
