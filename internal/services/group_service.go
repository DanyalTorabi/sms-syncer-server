package services

import (
	"errors"
	"fmt"
	"strings"

	"sms-sync-server/internal/db"
	"sms-sync-server/internal/models"
)

const (
	// AdminGroupName is the reserved name for the admin group
	AdminGroupName = "admin"
)

var (
	// ErrAdminGroupProtected indicates attempt to delete admin group
	ErrAdminGroupProtected = errors.New("admin group cannot be deleted")

	// ErrGroupNotFound indicates group does not exist
	ErrGroupNotFound = errors.New("group not found")

	// ErrInvalidGroupName indicates group name validation failure
	ErrInvalidGroupName = errors.New("group name must be unique and not empty")
)

// GroupService provides business logic for group management
type GroupService struct {
	repo db.GroupRepository
}

// NewGroupService creates a new GroupService instance
func NewGroupService(repo db.GroupRepository) *GroupService {
	return &GroupService{
		repo: repo,
	}
}

// CreateGroup creates a new group with validation
func (s *GroupService) CreateGroup(name, description string) (*models.Group, error) {
	// Validate name
	if strings.TrimSpace(name) == "" {
		return nil, ErrInvalidGroupName
	}

	// Check if group name already exists
	existingGroup, err := s.repo.GetByName(name)
	if err != nil {
		return nil, fmt.Errorf("failed to check group name: %w", err)
	}
	if existingGroup != nil {
		return nil, errors.New("group name already exists")
	}

	// Create group
	group := &models.Group{
		Name:        name,
		Description: description,
		Active:      true,
	}

	if err := s.repo.Create(group); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	return group, nil
}

// GetGroup retrieves a group by ID
func (s *GroupService) GetGroup(id string) (*models.Group, error) {
	if id == "" {
		return nil, errors.New("group ID cannot be empty")
	}

	group, err := s.repo.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return nil, ErrGroupNotFound
	}

	return group, nil
}

// UpdateGroup updates group fields
func (s *GroupService) UpdateGroup(id string, updates map[string]interface{}) error {
	if id == "" {
		return errors.New("group ID cannot be empty")
	}

	// Get existing group
	group, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return ErrGroupNotFound
	}

	// Validate and apply updates
	if name, ok := updates["name"].(string); ok {
		if strings.TrimSpace(name) == "" {
			return ErrInvalidGroupName
		}
		// Check name uniqueness
		existingGroup, err := s.repo.GetByName(name)
		if err != nil {
			return fmt.Errorf("failed to check group name: %w", err)
		}
		if existingGroup != nil && existingGroup.ID != id {
			return errors.New("group name already exists")
		}
		group.Name = name
	}

	if description, ok := updates["description"].(string); ok {
		group.Description = description
	}

	if active, ok := updates["active"].(bool); ok {
		group.Active = active
	}

	// Update group
	if err := s.repo.Update(group); err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	return nil
}

// DeleteGroup deletes a group with admin protection
func (s *GroupService) DeleteGroup(id string) error {
	if id == "" {
		return errors.New("group ID cannot be empty")
	}

	// Get group to check if it's the admin group
	group, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}
	if group == nil {
		return ErrGroupNotFound
	}

	// Protect admin group from deletion
	if strings.ToLower(group.Name) == AdminGroupName {
		return ErrAdminGroupProtected
	}

	if err := s.repo.Delete(id); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	return nil
}

// ListGroups retrieves a paginated list of groups
func (s *GroupService) ListGroups(limit, offset int) ([]*models.Group, error) {
	if limit < 0 {
		return nil, errors.New("limit cannot be negative")
	}
	if offset < 0 {
		return nil, errors.New("offset cannot be negative")
	}

	groups, err := s.repo.List(limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	return groups, nil
}

// AddPermission adds a permission to a group
func (s *GroupService) AddPermission(groupID, permissionID string) error {
	if groupID == "" {
		return errors.New("group ID cannot be empty")
	}
	if permissionID == "" {
		return errors.New("permission ID cannot be empty")
	}

	if err := s.repo.AddPermission(groupID, permissionID); err != nil {
		return fmt.Errorf("failed to add permission to group: %w", err)
	}

	return nil
}

// RemovePermission removes a permission from a group
func (s *GroupService) RemovePermission(groupID, permissionID string) error {
	if groupID == "" {
		return errors.New("group ID cannot be empty")
	}
	if permissionID == "" {
		return errors.New("permission ID cannot be empty")
	}

	if err := s.repo.RemovePermission(groupID, permissionID); err != nil {
		return fmt.Errorf("failed to remove permission from group: %w", err)
	}

	return nil
}
