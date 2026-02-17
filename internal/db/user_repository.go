package db

import (
	"database/sql"
	"fmt"
	"time"

	"sms-sync-server/internal/models"

	"github.com/google/uuid"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	Create(user *models.User) error
	GetByID(id string) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	GetByEmail(email string) (*models.User, error)
	Update(user *models.User) error
	Delete(id string) error
	List(limit, offset int) ([]*models.User, error)
	AddToGroup(userID, groupID string) error
	RemoveFromGroup(userID, groupID string) error
	GetUserGroups(userID string) ([]*models.Group, error)
	GetUserPermissions(userID string) ([]*models.Permission, error)
}

// userRepository implements UserRepository interface
type userRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{db: db}
}

// Create creates a new user in the database
func (r *userRepository) Create(user *models.User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}

	// Generate UUID if not provided
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	now := time.Now().Unix()
	user.CreatedAt = now
	user.UpdatedAt = now

	query := `
		INSERT INTO users (id, username, email, password_hash, totp_secret, totp_enabled, 
			active, failed_login_attempts, locked_until, last_login, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.Exec(query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.TOTPSecret,
		user.TOTPEnabled,
		user.Active,
		user.FailedLoginAttempts,
		user.LockedUntil,
		user.LastLogin,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(id string) (*models.User, error) {
	if id == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	query := `
		SELECT id, username, email, password_hash, totp_secret, totp_enabled,
			active, failed_login_attempts, locked_until, last_login, created_at, updated_at
		FROM users
		WHERE id = ?
	`

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.TOTPSecret,
		&user.TOTPEnabled,
		&user.Active,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return user, nil
}

// GetByUsername retrieves a user by username
func (r *userRepository) GetByUsername(username string) (*models.User, error) {
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	query := `
		SELECT id, username, email, password_hash, totp_secret, totp_enabled,
			active, failed_login_attempts, locked_until, last_login, created_at, updated_at
		FROM users
		WHERE username = ?
	`

	user := &models.User{}
	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.TOTPSecret,
		&user.TOTPEnabled,
		&user.Active,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(email string) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}

	query := `
		SELECT id, username, email, password_hash, totp_secret, totp_enabled,
			active, failed_login_attempts, locked_until, last_login, created_at, updated_at
		FROM users
		WHERE email = ?
	`

	user := &models.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.TOTPSecret,
		&user.TOTPEnabled,
		&user.Active,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.LastLogin,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

// Update updates an existing user
func (r *userRepository) Update(user *models.User) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}
	if user.ID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	user.UpdatedAt = time.Now().Unix()

	query := `
		UPDATE users 
		SET username = ?, email = ?, password_hash = ?, totp_secret = ?, totp_enabled = ?,
			active = ?, failed_login_attempts = ?, locked_until = ?, last_login = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.Exec(query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.TOTPSecret,
		user.TOTPEnabled,
		user.Active,
		user.FailedLoginAttempts,
		user.LockedUntil,
		user.LastLogin,
		user.UpdatedAt,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// Delete deletes a user by ID
func (r *userRepository) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	query := `DELETE FROM users WHERE id = ?`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// List retrieves a list of users with pagination
func (r *userRepository) List(limit, offset int) ([]*models.User, error) {
	if limit < 0 {
		return nil, fmt.Errorf("limit cannot be negative")
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset cannot be negative")
	}

	query := `
		SELECT id, username, email, password_hash, totp_secret, totp_enabled,
			active, failed_login_attempts, locked_until, last_login, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PasswordHash,
			&user.TOTPSecret,
			&user.TOTPEnabled,
			&user.Active,
			&user.FailedLoginAttempts,
			&user.LockedUntil,
			&user.LastLogin,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// AddToGroup adds a user to a group
func (r *userRepository) AddToGroup(userID, groupID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	if groupID == "" {
		return fmt.Errorf("group ID cannot be empty")
	}

	query := `
		INSERT INTO user_groups (user_id, group_id, assigned_at)
		VALUES (?, ?, ?)
	`

	_, err := r.db.Exec(query, userID, groupID, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	return nil
}

// RemoveFromGroup removes a user from a group
func (r *userRepository) RemoveFromGroup(userID, groupID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	if groupID == "" {
		return fmt.Errorf("group ID cannot be empty")
	}

	query := `DELETE FROM user_groups WHERE user_id = ? AND group_id = ?`

	result, err := r.db.Exec(query, userID, groupID)
	if err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user-group association not found")
	}

	return nil
}

// GetUserGroups retrieves all groups for a user
func (r *userRepository) GetUserGroups(userID string) ([]*models.Group, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	query := `
		SELECT g.id, g.name, g.description, g.active, g.created_at, g.updated_at
		FROM groups g
		INNER JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?
		ORDER BY g.name
	`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
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

// GetUserPermissions retrieves all permissions for a user through their groups
func (r *userRepository) GetUserPermissions(userID string) ([]*models.Permission, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	query := `
		SELECT DISTINCT p.id, p.name, p.resource, p.action, p.description, p.active, p.created_at
		FROM permissions p
		INNER JOIN group_permissions gp ON p.id = gp.permission_id
		INNER JOIN user_groups ug ON gp.group_id = ug.group_id
		WHERE ug.user_id = ?
		ORDER BY p.resource, p.action
	`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
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
