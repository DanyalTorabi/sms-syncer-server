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
