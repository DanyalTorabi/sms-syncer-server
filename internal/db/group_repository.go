package db

import (
	"database/sql"
	"fmt"
	"time"

	"sms-sync-server/internal/models"

	"github.com/google/uuid"
)

// GroupRepository defines the interface for group data access
type GroupRepository interface {
	Create(group *models.Group) error
	GetByID(id string) (*models.Group, error)
	GetByName(name string) (*models.Group, error)
	Update(group *models.Group) error
	Delete(id string) error
	List(limit, offset int) ([]*models.Group, error)
	AddPermission(groupID, permissionID string) error
	RemovePermission(groupID, permissionID string) error
	GetGroupPermissions(groupID string) ([]*models.Permission, error)
}

// groupRepository implements GroupRepository interface
type groupRepository struct {
	db *sql.DB
}

// NewGroupRepository creates a new GroupRepository
func NewGroupRepository(db *sql.DB) GroupRepository {
	return &groupRepository{db: db}
}

// Create creates a new group in the database
func (r *groupRepository) Create(group *models.Group) error {
	if group == nil {
		return fmt.Errorf("group cannot be nil")
	}

	// Generate UUID if not provided
	if group.ID == "" {
		group.ID = uuid.New().String()
	}

	now := time.Now().Unix()
	group.CreatedAt = now
	group.UpdatedAt = now

	query := `
		INSERT INTO groups (id, name, description, active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.Exec(query,
		group.ID,
		group.Name,
		group.Description,
		group.Active,
		group.CreatedAt,
		group.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	return nil
}

// GetByID retrieves a group by ID
func (r *groupRepository) GetByID(id string) (*models.Group, error) {
	if id == "" {
		return nil, fmt.Errorf("group ID cannot be empty")
	}

	query := `
		SELECT id, name, description, active, created_at, updated_at
		FROM groups
		WHERE id = ?
	`

	group := &models.Group{}
	err := r.db.QueryRow(query, id).Scan(
		&group.ID,
		&group.Name,
		&group.Description,
		&group.Active,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group by ID: %w", err)
	}

	return group, nil
}

// GetByName retrieves a group by name
func (r *groupRepository) GetByName(name string) (*models.Group, error) {
	if name == "" {
		return nil, fmt.Errorf("group name cannot be empty")
	}

	query := `
		SELECT id, name, description, active, created_at, updated_at
		FROM groups
		WHERE name = ?
	`

	group := &models.Group{}
	err := r.db.QueryRow(query, name).Scan(
		&group.ID,
		&group.Name,
		&group.Description,
		&group.Active,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group by name: %w", err)
	}

	return group, nil
}

// Update updates an existing group
func (r *groupRepository) Update(group *models.Group) error {
	if group == nil {
		return fmt.Errorf("group cannot be nil")
	}
	if group.ID == "" {
		return fmt.Errorf("group ID cannot be empty")
	}

	group.UpdatedAt = time.Now().Unix()

	query := `
		UPDATE groups 
		SET name = ?, description = ?, active = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.Exec(query,
		group.Name,
		group.Description,
		group.Active,
		group.UpdatedAt,
		group.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update group: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("group not found")
	}

	return nil
}

// Delete deletes a group by ID
func (r *groupRepository) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("group ID cannot be empty")
	}

	query := `DELETE FROM groups WHERE id = ?`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("group not found")
	}

	return nil
}

// List retrieves a list of groups with pagination
func (r *groupRepository) List(limit, offset int) ([]*models.Group, error) {
	if limit < 0 {
		return nil, fmt.Errorf("limit cannot be negative")
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset cannot be negative")
	}

	query := `
		SELECT id, name, description, active, created_at, updated_at
		FROM groups
		ORDER BY name
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	var groups []*models.Group
	for rows.Next() {
		group := &models.Group{}
		err := rows.Scan(
			&group.ID,
			&group.Name,
			&group.Description,
			&group.Active,
			&group.CreatedAt,
			&group.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, group)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating groups: %w", err)
	}

	return groups, nil
}

// AddPermission adds a permission to a group
func (r *groupRepository) AddPermission(groupID, permissionID string) error {
	if groupID == "" {
		return fmt.Errorf("group ID cannot be empty")
	}
	if permissionID == "" {
		return fmt.Errorf("permission ID cannot be empty")
	}

	query := `
		INSERT INTO group_permissions (group_id, permission_id, assigned_at)
		VALUES (?, ?, ?)
	`

	_, err := r.db.Exec(query, groupID, permissionID, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to add permission to group: %w", err)
	}

	return nil
}

// RemovePermission removes a permission from a group
func (r *groupRepository) RemovePermission(groupID, permissionID string) error {
	if groupID == "" {
		return fmt.Errorf("group ID cannot be empty")
	}
	if permissionID == "" {
		return fmt.Errorf("permission ID cannot be empty")
	}

	query := `DELETE FROM group_permissions WHERE group_id = ? AND permission_id = ?`

	result, err := r.db.Exec(query, groupID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to remove permission from group: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("group-permission association not found")
	}

	return nil
}

// GetGroupPermissions retrieves all permissions for a group
func (r *groupRepository) GetGroupPermissions(groupID string) ([]*models.Permission, error) {
	if groupID == "" {
		return nil, fmt.Errorf("group ID cannot be empty")
	}

	query := `
		SELECT p.id, p.name, p.resource, p.action, p.description, p.active, p.created_at
		FROM permissions p
		INNER JOIN group_permissions gp ON p.id = gp.permission_id
		WHERE gp.group_id = ?
		ORDER BY p.resource, p.action
	`

	rows, err := r.db.Query(query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		perm := &models.Permission{}
		err := rows.Scan(
			&perm.ID,
			&perm.Name,
			&perm.Resource,
			&perm.Action,
			&perm.Description,
			&perm.Active,
			&perm.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permissions: %w", err)
	}

	return permissions, nil
}
