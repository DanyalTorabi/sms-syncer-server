package handlers

import (
	"net/http"

	"sms-sync-server/internal/models"
	"sms-sync-server/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// UserHandler handles user management requests
type UserHandler struct {
	userService UserServiceInterface
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService UserServiceInterface) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// Register handles user registration (POST /api/users)
// Creates a new user account with username, email, and password
// Validates password strength and checks for duplicate usernames/emails
func (h *UserHandler) Register(c *gin.Context) {
	logger.Info("User registration endpoint called")

	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid registration request", zap.Error(err))
		// Check if it's a validation error for required fields
		if req.Username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
			return
		}
		if req.Email == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
			return
		}
		if req.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate required fields (redundant check, but explicit)
	if req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}

	if req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	if req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
		return
	}

	// Create user (service handles password hashing and validation)
	user, err := h.userService.CreateUser(req.Username, req.Email, req.Password)
	if err != nil {
		logger.Warn("User registration failed",
			zap.String("username", req.Username),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info("User registered successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.Username),
	)

	// Return user response (excludes sensitive fields)
	c.JSON(http.StatusCreated, gin.H{
		"id":         user.ID,
		"username":   user.Username,
		"email":      user.Email,
		"active":     user.Active,
		"created_at": user.CreatedAt,
	})
}

// ChangePassword handles self-service password change (POST /api/users/:id/password)
// Requires the user's current password for verification
// Users can only change their own password unless they have admin permissions
func (h *UserHandler) ChangePassword(c *gin.Context) {
	logger.Info("Password change endpoint called")

	// Extract user ID from route parameter
	targetUserID := c.Param("id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Extract authenticated user ID from JWT context
	authenticatedUserID, exists := c.Get("userID")
	if !exists {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Users can only change their own password (admin check would go here in #80)
	if targetUserID != authenticatedUserID {
		logger.Warn("Attempted to change another user's password",
			zap.String("authenticated_user", authenticatedUserID.(string)),
			zap.String("target_user", targetUserID),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot change another user's password"})
		return
	}

	// Parse request body
	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid password change request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Change password (service verifies old password and validates new password)
	err := h.userService.ChangePassword(targetUserID, req.OldPassword, req.NewPassword)
	if err != nil {
		logger.Warn("Password change failed",
			zap.String("user_id", targetUserID),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Info("Password changed successfully",
		zap.String("user_id", targetUserID),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Password changed successfully",
	})
}

// AdminResetPassword handles admin password reset (POST /api/admin/users/:id/password/reset)
// Allows admin to reset any user's password without knowing the old password
// TODO: Add admin permission check when middleware #80 is implemented
func (h *UserHandler) AdminResetPassword(c *gin.Context) {
	logger.Info("Admin password reset endpoint called")

	// Extract user ID from route parameter
	targetUserID := c.Param("id")
	if targetUserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Extract authenticated user ID from JWT context (for logging)
	authenticatedUserID, exists := c.Get("userID")
	if !exists {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// TODO: Check if authenticated user has admin permission (ticket #80)
	// For now, this endpoint should only be mounted on admin routes with middleware

	// Parse request body
	var req models.AdminResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid password reset request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate new password meets requirements
	if len(req.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	// Get target user to ensure they exist
	user, err := h.userService.GetUser(targetUserID)
	if err != nil {
		logger.Warn("Failed to find user for password reset",
			zap.String("target_user_id", targetUserID),
			zap.Error(err),
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Use empty string for old password to bypass verification (admin reset)
	// The service layer should handle this as an admin reset
	err = h.userService.AdminSetPassword(targetUserID, req.NewPassword)
	if err != nil {
		logger.Error("Admin password reset failed",
			zap.String("admin_user_id", authenticatedUserID.(string)),
			zap.String("target_user_id", targetUserID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	logger.Info("Admin password reset successful",
		zap.String("admin_user_id", authenticatedUserID.(string)),
		zap.String("target_user_id", targetUserID),
		zap.String("target_username", user.Username),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successfully",
	})
}
