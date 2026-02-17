package db

import (
	"database/sql"
	"fmt"
	"time"

	"sms-sync-server/internal/models"

	"github.com/google/uuid"
)

// PermissionRepository defines the interface for permission data access
type PermissionRepository interface {
	Create(permission *models.Permission) error
	GetByID(id string) (*models.Permission, error)
	GetByName(name string) (*models.Permission, error)
	Update(permission *models.Permission) error
	Delete(id string) error
	List(limit, offset int) ([]*models.Permission, error)
}

// permissionRepository implements PermissionRepository interface
type permissionRepository struct {
	db *sql.DB
}

// NewPermissionRepository creates a new PermissionRepository
func NewPermissionRepository(db *sql.DB) PermissionRepository {
	return &permissionRepository{db: db}
}

// Create creates a new permission in the database
func (r *permissionRepository) Create(permission *models.Permission) error {
	if permission == nil {
		return fmt.Errorf("permission cannot be nil")
	}

	// Generate UUID if not provided
	if permission.ID == "" {
		permission.ID = uuid.New().String()
	}

	now := time.Now().Unix()
	permission.CreatedAt = now

	query := `
		INSERT INTO permissions (id, name, resource, action, description, active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.Exec(query,
		permission.ID,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.Active,
		permission.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create permission: %w", err)
	}

	return nil
}

// GetByID retrieves a permission by ID
func (r *permissionRepository) GetByID(id string) (*models.Permission, error) {
	if id == "" {
		return nil, fmt.Errorf("permission ID cannot be empty")
	}

	query := `
		SELECT id, name, resource, action, description, active, created_at
		FROM permissions
		WHERE id = ?
	`

	permission := &models.Permission{}
	err := r.db.QueryRow(query, id).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.Active,
		&permission.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission by ID: %w", err)
	}

	return permission, nil
}

// GetByName retrieves a permission by name
func (r *permissionRepository) GetByName(name string) (*models.Permission, error) {
	if name == "" {
		return nil, fmt.Errorf("permission name cannot be empty")
	}

	query := `
		SELECT id, name, resource, action, description, active, created_at
		FROM permissions
		WHERE name = ?
	`

	permission := &models.Permission{}
	err := r.db.QueryRow(query, name).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Resource,
		&permission.Action,
		&permission.Description,
		&permission.Active,
		&permission.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get permission by name: %w", err)
	}

	return permission, nil
}

// Update updates an existing permission
func (r *permissionRepository) Update(permission *models.Permission) error {
	if permission == nil {
		return fmt.Errorf("permission cannot be nil")
	}
	if permission.ID == "" {
		return fmt.Errorf("permission ID cannot be empty")
	}

	query := `
		UPDATE permissions 
		SET name = ?, resource = ?, action = ?, description = ?, active = ?
		WHERE id = ?
	`

	result, err := r.db.Exec(query,
		permission.Name,
		permission.Resource,
		permission.Action,
		permission.Description,
		permission.Active,
		permission.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update permission: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("permission not found")
	}

	return nil
}

// Delete deletes a permission by ID
func (r *permissionRepository) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("permission ID cannot be empty")
	}

	query := `DELETE FROM permissions WHERE id = ?`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("permission not found")
	}

	return nil
}

// List retrieves a list of permissions with pagination
func (r *permissionRepository) List(limit, offset int) ([]*models.Permission, error) {
	if limit < 0 {
		return nil, fmt.Errorf("limit cannot be negative")
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset cannot be negative")
	}

	query := `
		SELECT id, name, resource, action, description, active, created_at
		FROM permissions
		ORDER BY resource, action
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
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
