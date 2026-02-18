package handlers

import (
	"net/http"
	"strconv"

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

// ListUsers handles listing users with pagination (GET /api/users)
// Requires users:read permission or returns filtered results
// Query params: limit (default 50), offset (default 0), include_inactive (default false)
func (h *UserHandler) ListUsers(c *gin.Context) {
	logger.Info("List users endpoint called")

	// Parse pagination parameters
	limit := 50 // Default limit
	offset := 0 // Default offset

	if limitParam := c.Query("limit"); limitParam != "" {
		l, err := strconv.Atoi(limitParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid limit parameter"})
			return
		}
		if l > 0 && l <= 100 {
			limit = l
		}
	}

	if offsetParam := c.Query("offset"); offsetParam != "" {
		o, err := strconv.Atoi(offsetParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid offset parameter"})
			return
		}
		if o >= 0 {
			offset = o
		}
	}

	// Check include_inactive parameter
	includeInactive := c.Query("include_inactive") == "true"

	// Get users from service
	users, err := h.userService.ListUsers(limit, offset)
	if err != nil {
		logger.Error("Failed to list users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	// Filter inactive users unless explicitly requested
	var filteredUsers []*models.User
	if includeInactive {
		filteredUsers = users
	} else {
		for _, user := range users {
			if user.Active {
				filteredUsers = append(filteredUsers, user)
			}
		}
	}

	// Convert to safe response format
	responses := make([]*models.UserResponse, len(filteredUsers))
	for i, user := range filteredUsers {
		responses[i] = user.ToResponse()
	}

	logger.Info("Users listed successfully",
		zap.Int("count", len(responses)),
		zap.Int("limit", limit),
		zap.Int("offset", offset),
	)

	c.JSON(http.StatusOK, gin.H{
		"users": responses,
		"count": len(responses),
	})
}

// GetUserByID handles retrieving a single user (GET /api/users/:id)
// Requires users:read permission OR user viewing themselves
// Returns user with groups and permissions expanded
func (h *UserHandler) GetUserByID(c *gin.Context) {
	logger.Info("Get user by ID endpoint called")

	// Extract user ID from route parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Extract authenticated user ID from JWT context
	authenticatedUserID, exists := c.Get("user_id")
	if !exists {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Check if user is viewing themselves
	isSelf := userID == authenticatedUserID.(string)

	// Permission check is handled by middleware

	// Get user with permissions
	user, err := h.userService.GetUserWithPermissions(userID)
	if err != nil {
		logger.Warn("Failed to get user",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		// Check if it's a "not found" error
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		}
		return
	}

	logger.Info("User retrieved successfully",
		zap.String("user_id", userID),
		zap.Bool("is_self", isSelf),
	)

	// Return detailed response with groups and permissions
	c.JSON(http.StatusOK, user.ToDetailResponse())
}

// validateUpdatePermissions checks if user has permission to update the target user
// Permission check is now handled by middleware, this just validates the request
func (h *UserHandler) validateUpdatePermissions(c *gin.Context, userID string, authenticatedUserID string, isSelf bool) bool {
	// Middleware already verified permission, just return true
	return true
}

// validateAdminProtection checks if the update would deactivate the admin user
func (h *UserHandler) validateAdminProtection(c *gin.Context, userID string, req *models.UpdateUserRequest, isSelf bool) (*models.User, bool) {
	if isSelf {
		return nil, true
	}

	// For admin updates, verify user exists and check admin protection
	user, err := h.userService.GetUser(userID)
	if err != nil {
		logger.Warn("Failed to find user for update",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		}
		return nil, false
	}

	// Protect admin user from deactivation
	if req.Active != nil && user.Username == "admin" && !*req.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot deactivate the admin user"})
		return nil, false
	}

	return user, true
}

// buildUpdateMap builds the updates map based on permissions
func buildUpdateMap(req *models.UpdateUserRequest, isSelf bool) map[string]interface{} {
	updates := make(map[string]interface{})

	if isSelf {
		// Self-update: Can only change email
		if req.Email != nil {
			updates["email"] = *req.Email
		}
	} else {
		// Admin update: Can change email, active status
		if req.Active != nil {
			updates["active"] = *req.Active
		}
		if req.Email != nil {
			updates["email"] = *req.Email
		}
	}

	return updates
}

// UpdateUserByID handles updating a user (PUT /api/users/:id)
// Self-update: Can only change email
// Admin update (users:write): Can change username, email, active status
func (h *UserHandler) UpdateUserByID(c *gin.Context) {
	logger.Info("Update user endpoint called")

	// Extract user ID from route parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Extract authenticated user ID from JWT context
	authenticatedUserID, exists := c.Get("user_id")
	if !exists {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	isSelf := userID == authenticatedUserID.(string)

	// Check permissions
	if !h.validateUpdatePermissions(c, userID, authenticatedUserID.(string), isSelf) {
		return
	}

	// Parse request body
	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid update request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Check early for self trying to change active status
	if isSelf && req.Active != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot change active status for own account"})
		return
	}

	// Validate admin protection for non-self updates
	if _, ok := h.validateAdminProtection(c, userID, &req, isSelf); !ok {
		return
	}

	// Build updates map
	updates := buildUpdateMap(&req, isSelf)
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid fields to update"})
		return
	}

	// Perform update
	err := h.userService.UpdateUser(userID, updates)
	if err != nil {
		logger.Error("Failed to update user",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	logger.Info("User updated successfully",
		zap.String("user_id", userID),
		zap.Bool("is_self", isSelf),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
	})
}

// DeleteUserByID handles soft-deleting a user (DELETE /api/users/:id)
// Requires users:write permission
// Sets active=false instead of hard delete
func (h *UserHandler) DeleteUserByID(c *gin.Context) {
	logger.Info("Delete user endpoint called")

	// Permission check handled by middleware

	// Extract user ID from route parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Get user to check if it's admin
	user, err := h.userService.GetUser(userID)
	if err != nil {
		logger.Warn("Failed to find user for deletion",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		}
		return
	}

	// Protect admin user from deletion
	if user.Username == "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete admin user"})
		return
	}

	// Soft delete: Set active=false
	updates := map[string]interface{}{
		"active": false,
	}

	err = h.userService.UpdateUser(userID, updates)
	if err != nil {
		logger.Error("Failed to delete user",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	logger.Info("User deleted successfully (soft delete)",
		zap.String("user_id", userID),
		zap.String("username", user.Username),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

// AssignUserToGroup handles assigning a user to a group (POST /api/users/:id/groups)
// Requires users:write permission
func (h *UserHandler) AssignUserToGroup(c *gin.Context) {
	logger.Info("Assign user to group endpoint called")

	// Permission check handled by middleware

	// Extract user ID from route parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Parse request body
	var req models.AssignGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid assign group request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Assign user to group
	err := h.userService.AssignToGroup(userID, req.GroupID)
	if err != nil {
		logger.Error("Failed to assign user to group",
			zap.String("user_id", userID),
			zap.String("group_id", req.GroupID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign user to group"})
		return
	}

	logger.Info("User assigned to group successfully",
		zap.String("user_id", userID),
		zap.String("group_id", req.GroupID),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "User assigned to group successfully",
	})
}

// RemoveUserFromGroup handles removing a user from a group (DELETE /api/users/:id/groups/:groupId)
// Requires users:write permission
// Cannot remove admin user from admin group
func (h *UserHandler) RemoveUserFromGroup(c *gin.Context) {
	logger.Info("Remove user from group endpoint called")

	// Permission check handled by middleware

	// Extract user ID and group ID from route parameters
	userID := c.Param("id")
	groupID := c.Param("groupId")

	if userID == "" || groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID and Group ID are required"})
		return
	}

	// Get user to check if it's admin
	user, err := h.userService.GetUser(userID)
	if err != nil {
		logger.Warn("Failed to find user",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Protect admin user from being removed from admin group
	// This requires checking if the group is the admin group
	// For now, we'll do a simple check - in a real system, you'd query the group name
	if user.Username == "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot remove admin user from admin group"})
		return
	}

	// Remove user from group
	err = h.userService.RemoveFromGroup(userID, groupID)
	if err != nil {
		logger.Error("Failed to remove user from group",
			zap.String("user_id", userID),
			zap.String("group_id", groupID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from group"})
		return
	}

	logger.Info("User removed from group successfully",
		zap.String("user_id", userID),
		zap.String("group_id", groupID),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "User removed from group successfully",
	})
}

// ListUserGroups handles listing groups for a user (GET /api/users/:id/groups)
// Requires users:read permission or self-access
func (h *UserHandler) ListUserGroups(c *gin.Context) {
	logger.Info("List user groups endpoint called")

	// Extract user ID from route parameter
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Extract authenticated user ID from JWT context
	_, exists := c.Get("user_id")
	if !exists {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Permission check handled by middleware

	// Get user with groups
	user, err := h.userService.GetUserWithPermissions(userID)
	if err != nil {
		logger.Warn("Failed to get user groups",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list user groups"})
		}
		return
	}

	logger.Info("User groups retrieved successfully",
		zap.String("user_id", userID),
		zap.Int("group_count", len(user.Groups)),
	)

	c.JSON(http.StatusOK, gin.H{
		"groups": user.Groups,
	})
}
