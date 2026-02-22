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
	"sms-sync-server/pkg/logger"
	"sms-sync-server/pkg/utils"

	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
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
		logger.Error("Database error during authentication",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		logger.Warn("Authentication failed - user not found",
			zap.String("username", username),
			zap.String("event_type", "invalid_credentials"),
		)
		return nil, ErrInvalidCredentials
	}

	// Check and handle account lock
	originalUser := user
	user, err = s.checkAccountLock(user)
	if err != nil {
		logger.Warn("Authentication failed - account locked",
			zap.String("user_id", originalUser.ID),
			zap.String("username", originalUser.Username),
			zap.String("event_type", "account_locked"),
		)
		return nil, err
	}

	// Check if user is active
	if !user.Active {
		logger.Warn("Authentication failed - account inactive",
			zap.String("user_id", user.ID),
			zap.String("username", user.Username),
			zap.String("event_type", "inactive_account"),
		)
		return nil, errors.New("user account is inactive")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		if incrementErr := s.IncrementFailedLogin(user.ID); incrementErr != nil {
			logger.Error("Failed to increment failed login counter",
				zap.String("user_id", user.ID),
				zap.Error(incrementErr),
			)
			return nil, fmt.Errorf("authentication failed and failed to increment counter: %w", incrementErr)
		}
		logger.Warn("Authentication failed - invalid password",
			zap.String("user_id", user.ID),
			zap.String("username", user.Username),
			zap.String("event_type", "failed_login"),
		)
		return nil, ErrInvalidCredentials
	}

	// Verify TOTP if enabled
	if err := s.verifyTOTP(user, totpCode); err != nil {
		logger.Warn("Authentication failed - TOTP validation failed",
			zap.String("user_id", user.ID),
			zap.String("username", user.Username),
			zap.String("event_type", "failed_totp_validation"),
			zap.Error(err),
		)
		return nil, err
	}

	// Authentication successful - reset failed attempts and update last login
	if err := s.ResetFailedLogin(user.ID); err != nil {
		logger.Error("Failed to reset failed login counter after successful auth",
			zap.String("user_id", user.ID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to reset failed login: %w", err)
	}

	if err := s.UpdateLastLogin(user.ID); err != nil {
		logger.Error("Failed to update last login timestamp",
			zap.String("user_id", user.ID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to update last login: %w", err)
	}

	// Reload user to get updated fields
	user, err = s.repo.GetByID(user.ID)
	if err != nil {
		logger.Error("Failed to reload user after successful authentication",
			zap.String("user_id", user.ID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to reload user: %w", err)
	}

	logger.Info("User authenticated successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.Username),
		zap.String("event_type", "successful_login"),
	)

	return user, nil
}

// checkAccountLock checks if user account is locked and handles lock expiry
func (s *UserService) checkAccountLock(user *models.User) (*models.User, error) {
	if user.LockedUntil == nil || *user.LockedUntil == 0 {
		return user, nil
	}

	lockTime := time.Unix(*user.LockedUntil, 0)
	if time.Now().Before(lockTime) {
		return nil, ErrAccountLocked
	}

	// Lock expired, reset failed attempts
	if err := s.ResetFailedLogin(user.ID); err != nil {
		return nil, fmt.Errorf("failed to reset failed login: %w", err)
	}

	// Reload user after reset
	reloadedUser, err := s.repo.GetByID(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload user: %w", err)
	}
	if reloadedUser == nil {
		return nil, ErrUserNotFound
	}

	return reloadedUser, nil
}

// verifyTOTP validates TOTP code if 2FA is enabled
func (s *UserService) verifyTOTP(user *models.User, totpCode string) error {
	if !user.TOTPEnabled {
		return nil
	}

	if totpCode == "" {
		return ErrInvalidTOTP
	}

	if user.TOTPSecret == nil {
		return ErrInvalidTOTP
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

	if !totp.Validate(totpCode, secret) {
		if incrementErr := s.IncrementFailedLogin(user.ID); incrementErr != nil {
			return fmt.Errorf("TOTP validation failed and failed to increment counter: %w", incrementErr)
		}
		return ErrInvalidTOTP
	}

	return nil
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

	// Get user details before deletion for logging
	user, err := s.repo.GetByID(id)
	if err != nil {
		logger.Error("Failed to retrieve user for deletion",
			zap.String("user_id", id),
			zap.Error(err),
		)
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := s.repo.Delete(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warn("Delete user failed - user not found",
				zap.String("user_id", id),
				zap.String("event_type", "user_not_found"),
			)
			return ErrUserNotFound
		}
		logger.Error("Failed to delete user from database",
			zap.String("user_id", id),
			zap.String("username", user.Username),
			zap.String("event_type", "user_deletion_failed"),
			zap.Error(err),
		)
		return fmt.Errorf("failed to delete user: %w", err)
	}

	logger.Info("User deleted successfully",
		zap.String("user_id", id),
		zap.String("username", user.Username),
		zap.String("event_type", "user_deletion"),
	)

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
		logger.Warn("Password change failed - invalid password format",
			zap.String("user_id", id),
			zap.String("event_type", "weak_password"),
			zap.Error(err),
		)
		return err
	}

	// Get user
	user, err := s.repo.GetByID(id)
	if err != nil {
		logger.Error("Failed to retrieve user for password change",
			zap.String("user_id", id),
			zap.Error(err),
		)
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		logger.Warn("Password change failed - user not found",
			zap.String("user_id", id),
			zap.String("event_type", "user_not_found"),
		)
		return ErrUserNotFound
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		logger.Warn("Password change failed - incorrect old password",
			zap.String("user_id", id),
			zap.String("username", user.Username),
			zap.String("event_type", "password_verification_failed"),
		)
		return ErrIncorrectOldPassword
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), BcryptCost)
	if err != nil {
		logger.Error("Failed to hash new password",
			zap.String("user_id", id),
			zap.Error(err),
		)
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hashedPassword)
	if err := s.repo.Update(user); err != nil {
		logger.Error("Failed to update password in database",
			zap.String("user_id", id),
			zap.Error(err),
		)
		return fmt.Errorf("failed to update password: %w", err)
	}

	logger.Info("Password changed successfully",
		zap.String("user_id", id),
		zap.String("username", user.Username),
		zap.String("event_type", "password_change"),
	)

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
		logger.Error("Failed to assign user to group",
			zap.String("user_id", userID),
			zap.String("group_id", groupID),
			zap.String("event_type", "group_assignment_failed"),
			zap.Error(err),
		)
		return fmt.Errorf("failed to assign user to group: %w", err)
	}

	logger.Info("User assigned to group",
		zap.String("user_id", userID),
		zap.String("group_id", groupID),
		zap.String("event_type", "group_assignment"),
	)

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
		logger.Error("Failed to remove user from group",
			zap.String("user_id", userID),
			zap.String("group_id", groupID),
			zap.String("event_type", "group_removal_failed"),
			zap.Error(err),
		)
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	logger.Info("User removed from group",
		zap.String("user_id", userID),
		zap.String("group_id", groupID),
		zap.String("event_type", "group_removal"),
	)

	return nil
}

// IncrementFailedLogin increments failed login attempts and locks account if needed
func (s *UserService) IncrementFailedLogin(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		logger.Error("Failed to get user for incrementing failed login counter",
			zap.String("user_id", userID),
			zap.Error(err),
		)
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
		logger.Warn("User account locked due to excessive failed login attempts",
			zap.String("user_id", userID),
			zap.String("username", user.Username),
			zap.Int("failed_attempts", user.FailedLoginAttempts),
			zap.Duration("lockout_duration", LockoutDuration),
			zap.String("event_type", "account_lockout"),
		)
	} else {
		logger.Debug("Failed login attempt recorded",
			zap.String("user_id", userID),
			zap.String("username", user.Username),
			zap.Int("failed_attempts", user.FailedLoginAttempts),
			zap.Int("max_attempts", MaxFailedLoginAttempts),
		)
	}

	if err := s.repo.Update(user); err != nil {
		logger.Error("Failed to update failed login attempts in database",
			zap.String("user_id", userID),
			zap.Error(err),
		)
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
		logger.Error("Failed to get user for enabling TOTP",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		logger.Warn("Enable 2FA failed - user not found",
			zap.String("user_id", userID),
			zap.String("event_type", "user_not_found"),
		)
		return ErrUserNotFound
	}

	if user.TOTPSecret == nil || *user.TOTPSecret == "" {
		logger.Warn("Enable 2FA failed - TOTP secret not generated",
			zap.String("user_id", userID),
			zap.String("username", user.Username),
			zap.String("event_type", "totp_secret_missing"),
		)
		return errors.New("TOTP secret not generated")
	}

	// Decrypt secret if encryption is enabled
	secret := *user.TOTPSecret
	if s.encryptionKey != "" {
		decryptedSecret, err := utils.DecryptTOTPSecret(secret, s.encryptionKey)
		if err != nil {
			logger.Error("Failed to decrypt TOTP secret for enablement",
				zap.String("user_id", userID),
				zap.Error(err),
			)
			return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
		}
		secret = decryptedSecret
	}

	// Validate TOTP code
	if !totp.Validate(totpCode, secret) {
		logger.Warn("Enable 2FA failed - invalid TOTP code",
			zap.String("user_id", userID),
			zap.String("username", user.Username),
			zap.String("event_type", "invalid_totp_code"),
		)
		return ErrInvalidTOTP
	}

	// Enable TOTP
	user.TOTPEnabled = true
	if err := s.repo.Update(user); err != nil {
		logger.Error("Failed to enable TOTP in database",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	logger.Info("2FA enabled successfully",
		zap.String("user_id", userID),
		zap.String("username", user.Username),
		zap.String("event_type", "2fa_enabled"),
	)

	return nil
}

// DisableTOTP disables TOTP for a user
func (s *UserService) DisableTOTP(userID string) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}

	user, err := s.repo.GetByID(userID)
	if err != nil {
		logger.Error("Failed to get user for disabling TOTP",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		logger.Warn("Disable 2FA failed - user not found",
			zap.String("user_id", userID),
			zap.String("event_type", "user_not_found"),
		)
		return ErrUserNotFound
	}

	// Disable TOTP and clear secret
	user.TOTPEnabled = false
	user.TOTPSecret = nil
	if err := s.repo.Update(user); err != nil {
		logger.Error("Failed to disable TOTP in database",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to disable TOTP: %w", err)
	}

	logger.Info("2FA disabled successfully",
		zap.String("user_id", userID),
		zap.String("username", user.Username),
		zap.String("event_type", "2fa_disabled"),
	)

	return nil
}
