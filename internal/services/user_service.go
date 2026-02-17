package services

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/db"
	"sms-sync-server/internal/models"
	"sms-sync-server/pkg/utils"

	"github.com/pquerna/otp/totp"
)

const (
	// BcryptCost is the cost parameter for bcrypt password hashing
	BcryptCost = 12

	// MaxFailedLoginAttempts is the number of failed attempts before account lockout
	MaxFailedLoginAttempts = 5

	// LockoutDuration is the duration of account lockout after max failed attempts
	LockoutDuration = 30 * time.Minute

	// MinPasswordLength is the minimum length for passwords
	MinPasswordLength = 8

	// MinUsernameLength is the minimum length for usernames
	MinUsernameLength = 3

	// MaxUsernameLength is the maximum length for usernames
	MaxUsernameLength = 50
)

var (
	// ErrInvalidCredentials indicates authentication failure
	ErrInvalidCredentials = errors.New("invalid username or password")

	// ErrAccountLocked indicates the account is temporarily locked
	ErrAccountLocked = errors.New("account is locked due to too many failed login attempts")

	// ErrInvalidTOTP indicates TOTP code validation failure
	ErrInvalidTOTP = errors.New("invalid TOTP code")

	// ErrUserNotFound indicates user does not exist
	ErrUserNotFound = errors.New("user not found")

	// ErrInvalidUsername indicates username validation failure
	ErrInvalidUsername = errors.New("username must be 3-50 characters and contain only alphanumeric characters and underscores")

	// ErrInvalidEmail indicates email validation failure
	ErrInvalidEmail = errors.New("invalid email format")

	// ErrInvalidPassword indicates password validation failure
	ErrInvalidPassword = errors.New("password must be at least 8 characters")

	// ErrIncorrectOldPassword indicates old password verification failed
	ErrIncorrectOldPassword = errors.New("incorrect old password")
)

// UserService provides business logic for user management
type UserService struct {
	repo          db.UserRepository
	encryptionKey string
}

// NewUserService creates a new UserService instance
func NewUserService(repo db.UserRepository) *UserService {
	return &UserService{
		repo:          repo,
		encryptionKey: "",
	}
}

// NewUserServiceWithEncryption creates a new UserService instance with encryption for TOTP secrets
func NewUserServiceWithEncryption(repo db.UserRepository, cfg *config.Config) *UserService {
	return &UserService{
		repo:          repo,
		encryptionKey: cfg.Security.TOTPEncryptionKey,
	}
}

// CreateUser creates a new user with hashed password and validation
func (s *UserService) CreateUser(username, email, password string) (*models.User, error) {
	// Validate inputs
	if err := validateUsername(username); err != nil {
		return nil, err
	}

	if email != "" {
		if err := validateEmail(email); err != nil {
			return nil, err
		}
	}

	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// Check if username already exists
	existingUser, err := s.repo.GetByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("failed to check username: %w", err)
	}
	if existingUser != nil {
		return nil, errors.New("username already exists")
	}

	// Check if email already exists (if provided)
	if email != "" {
		existingUser, err = s.repo.GetByEmail(email)
		if err != nil {
			return nil, fmt.Errorf("failed to check email: %w", err)
		}
		if existingUser != nil {
			return nil, errors.New("email already exists")
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		Username:            username,
		Email:               email,
		PasswordHash:        string(hashedPassword),
		Active:              true,
		FailedLoginAttempts: 0,
		TOTPEnabled:         false,
	}

	if err := s.repo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// Authenticate verifies username/password and optional TOTP code
func (s *UserService) Authenticate(username, password, totpCode string) (*models.User, error) {
	// Get user by username
	user, err := s.repo.GetByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}

	// Check if account is locked
	if user.LockedUntil != nil && *user.LockedUntil > 0 {
		lockTime := time.Unix(*user.LockedUntil, 0)
		if time.Now().Before(lockTime) {
			return nil, ErrAccountLocked
		}
		// Lock expired, reset failed attempts
		if err := s.ResetFailedLogin(user.ID); err != nil {
			return nil, fmt.Errorf("failed to reset failed login: %w", err)
		}
		// Reload user after reset
		user, err = s.repo.GetByID(user.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to reload user: %w", err)
		}
		if user == nil {
			return nil, ErrUserNotFound
		}
	}

	// Check if user is active
	if !user.Active {
		return nil, errors.New("user account is inactive")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Increment failed login attempts
		if incrementErr := s.IncrementFailedLogin(user.ID); incrementErr != nil {
			return nil, fmt.Errorf("authentication failed and failed to increment counter: %w", incrementErr)
		}
		return nil, ErrInvalidCredentials
	}

	// Verify TOTP if enabled
	if user.TOTPEnabled {
		if totpCode == "" {
			return nil, ErrInvalidTOTP
		}
		if user.TOTPSecret == nil {
			return nil, ErrInvalidTOTP
		}

		// Decrypt secret if encryption is enabled
		secret := *user.TOTPSecret
		if s.encryptionKey != "" {
			decryptedSecret, err := utils.DecryptTOTPSecret(secret, s.encryptionKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
			}
			secret = decryptedSecret
		}

		if !totp.Validate(totpCode, secret) {
			// Increment failed login attempts for invalid TOTP too
			if incrementErr := s.IncrementFailedLogin(user.ID); incrementErr != nil {
				return nil, fmt.Errorf("TOTP validation failed and failed to increment counter: %w", incrementErr)
			}
			return nil, ErrInvalidTOTP
		}
	}

	// Authentication successful - reset failed attempts and update last login
	if err := s.ResetFailedLogin(user.ID); err != nil {
		return nil, fmt.Errorf("failed to reset failed login: %w", err)
	}

	if err := s.UpdateLastLogin(user.ID); err != nil {
		return nil, fmt.Errorf("failed to update last login: %w", err)
	}

	// Reload user to get updated fields
	user, err = s.repo.GetByID(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload user: %w", err)
	}

	return user, nil
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(id string) (*models.User, error) {
	if id == "" {
		return nil, errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetUserWithPermissions retrieves a user by ID with their effective permissions
func (s *UserService) GetUserWithPermissions(id string) (*models.User, error) {
	if id == "" {
		return nil, errors.New("user ID cannot be empty")
	}

	// Get user
	user, err := s.repo.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Get user permissions from all their groups
	permissions, err := s.repo.GetUserPermissions(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Convert []*models.Permission to []models.Permission
	user.Permissions = make([]models.Permission, len(permissions))
	for i, perm := range permissions {
		user.Permissions[i] = *perm
	}

	return user, nil
}

// UpdateUser updates user fields
func (s *UserService) UpdateUser(id string, updates map[string]interface{}) error {
	if id == "" {
		return errors.New("user ID cannot be empty")
	}

	// Get existing user
	user, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Validate updates
	if username, ok := updates["username"].(string); ok {
		if err := validateUsername(username); err != nil {
			return err
		}
		// Check username uniqueness
		existingUser, err := s.repo.GetByUsername(username)
		if err != nil {
			return fmt.Errorf("failed to check username: %w", err)
		}
		if existingUser != nil && existingUser.ID != id {
			return errors.New("username already exists")
		}
		user.Username = username
	}

	if email, ok := updates["email"].(string); ok {
		if email != "" {
			if err := validateEmail(email); err != nil {
				return err
			}
			// Check email uniqueness
			existingUser, err := s.repo.GetByEmail(email)
			if err != nil {
				return fmt.Errorf("failed to check email: %w", err)
			}
			if existingUser != nil && existingUser.ID != id {
				return errors.New("email already exists")
			}
		}
		user.Email = email
	}

	if active, ok := updates["active"].(bool); ok {
		user.Active = active
	}

	if totpEnabled, ok := updates["totp_enabled"].(bool); ok {
		user.TOTPEnabled = totpEnabled
	}

	if totpSecret, ok := updates["totp_secret"].(string); ok {
		user.TOTPSecret = &totpSecret
	}

	// Update user
	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// DeleteUser deletes a user by ID
func (s *UserService) DeleteUser(id string) error {
	if id == "" {
		return errors.New("user ID cannot be empty")
	}

	if err := s.repo.Delete(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// ListUsers retrieves a paginated list of users
func (s *UserService) ListUsers(limit, offset int) ([]*models.User, error) {
	if limit < 0 {
		return nil, errors.New("limit cannot be negative")
	}
	if offset < 0 {
		return nil, errors.New("offset cannot be negative")
	}

	users, err := s.repo.List(limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return users, nil
}

// ChangePassword changes a user's password after verifying the old password
func (s *UserService) ChangePassword(id, oldPassword, newPassword string) error {
	if id == "" {
		return errors.New("user ID cannot be empty")
	}

	// Validate new password
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	// Get user
	user, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrIncorrectOldPassword
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), BcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// AdminSetPassword allows an admin to set a user's password without knowing the old password
// This should only be called by admin endpoints with proper permission checks
func (s *UserService) AdminSetPassword(id, newPassword string) error {
	if id == "" {
		return errors.New("user ID cannot be empty")
	}

	// Validate new password
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	// Get user
	user, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), BcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// AssignToGroup assigns a user to a group
func (s *UserService) AssignToGroup(userID, groupID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if groupID == "" {
		return errors.New("group ID cannot be empty")
	}

	if err := s.repo.AddToGroup(userID, groupID); err != nil {
		return fmt.Errorf("failed to assign user to group: %w", err)
	}

	return nil
}

// RemoveFromGroup removes a user from a group
func (s *UserService) RemoveFromGroup(userID, groupID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if groupID == "" {
		return errors.New("group ID cannot be empty")
	}

	if err := s.repo.RemoveFromGroup(userID, groupID); err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	return nil
}

// IncrementFailedLogin increments failed login attempts and locks account if needed
func (s *UserService) IncrementFailedLogin(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.FailedLoginAttempts++

	// Lock account if max attempts reached
	if user.FailedLoginAttempts >= MaxFailedLoginAttempts {
		lockUntil := time.Now().Add(LockoutDuration).Unix()
		user.LockedUntil = &lockUntil
	}

	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to update failed login attempts: %w", err)
	}

	return nil
}

// ResetFailedLogin resets failed login attempts and unlocks account
func (s *UserService) ResetFailedLogin(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.FailedLoginAttempts = 0
	user.LockedUntil = nil

	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to reset failed login: %w", err)
	}

	return nil
}

// UpdateLastLogin updates the last login timestamp
func (s *UserService) UpdateLastLogin(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	lastLogin := time.Now().Unix()
	user.LastLogin = &lastLogin

	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// validateUsername validates username format and length
func validateUsername(username string) error {
	if len(username) < MinUsernameLength || len(username) > MaxUsernameLength {
		return ErrInvalidUsername
	}

	// Only allow alphanumeric characters and underscores
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validUsername.MatchString(username) {
		return ErrInvalidUsername
	}

	return nil
}

// validateEmail validates email format
func validateEmail(email string) error {
	if email == "" {
		return nil // Empty email is allowed
	}

	// Simple email validation regex
	validEmail := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !validEmail.MatchString(email) {
		return ErrInvalidEmail
	}

	return nil
}

// validatePassword validates password length
func validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return ErrInvalidPassword
	}

	return nil
}

// GenerateTOTPSecret generates a new TOTP secret for a user
func (s *UserService) GenerateTOTPSecret(userID string) (string, error) {
	if userID == "" {
		return "", errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		return "", fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return "", ErrUserNotFound
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SMS Syncer",
		AccountName: user.Username,
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secret := key.Secret()

	// Encrypt secret if encryption key is configured
	var storedSecret string
	if s.encryptionKey != "" {
		encryptedSecret, err := utils.EncryptTOTPSecret(secret, s.encryptionKey)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt TOTP secret: %w", err)
		}
		storedSecret = encryptedSecret
	} else {
		storedSecret = secret
	}

	user.TOTPSecret = &storedSecret
	if err := s.repo.Update(user); err != nil {
		return "", fmt.Errorf("failed to update TOTP secret: %w", err)
	}

	// Return the unencrypted secret for QR code generation
	return secret, nil
}

// EnableTOTP enables TOTP for a user after validating the code
func (s *UserService) EnableTOTP(userID, totpCode string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if totpCode == "" {
		return errors.New("TOTP code cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	if user.TOTPSecret == nil || *user.TOTPSecret == "" {
		return errors.New("TOTP secret not generated")
	}

	// Decrypt secret if encryption is enabled
	secret := *user.TOTPSecret
	if s.encryptionKey != "" {
		decryptedSecret, err := utils.DecryptTOTPSecret(secret, s.encryptionKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
		}
		secret = decryptedSecret
	}

	// Validate TOTP code
	if !totp.Validate(totpCode, secret) {
		return ErrInvalidTOTP
	}

	// Enable TOTP
	user.TOTPEnabled = true
	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	return nil
}

// DisableTOTP disables TOTP for a user
func (s *UserService) DisableTOTP(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Disable TOTP and clear secret
	user.TOTPEnabled = false
	user.TOTPSecret = nil
	if err := s.repo.Update(user); err != nil {
		return fmt.Errorf("failed to disable TOTP: %w", err)
	}

	return nil
}
