package handlers

import (
	"net/http"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/services"
	"sms-sync-server/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type LoginRequest struct {
	Username string `json:"username"`
	// #nosec G117 - Input struct for receiving credentials, not exposing secrets
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"` // Optional 2FA code
}

// Claims represents the JWT claims structure with user ID and permission UUIDs
type Claims struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Permissions []string `json:"permissions"` // Array of permission UUIDs
	jwt.RegisteredClaims
}

// AuthHandler handles authentication-related requests
type AuthHandler struct {
	config      *config.Config
	userService UserServiceInterface
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(cfg *config.Config, userService UserServiceInterface) *AuthHandler {
	return &AuthHandler{
		config:      cfg,
		userService: userService,
	}
}

// Login handles user authentication and returns a JWT token
// Authenticates with username/password and optional TOTP code
// Returns JWT token with 1-hour expiry containing user ID and permission UUIDs
func (h *AuthHandler) Login(c *gin.Context) {
	logger.Info("Auth login endpoint called")
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error("Failed to parse login request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" {
		logger.Error("Missing username or password")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	// Authenticate user with password and optional TOTP
	user, err := h.userService.Authenticate(req.Username, req.Password, req.TOTPCode)
	if err != nil {
		logger.Warn("Authentication failed",
			zap.String("username", req.Username),
			zap.Error(err),
		)
		// Return generic error message for security
		if err == services.ErrAccountLocked {
			c.JSON(http.StatusForbidden, gin.H{"error": "Account is locked due to too many failed login attempts"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		}
		return
	}

	// Load user's permissions
	userWithPermissions, err := h.userService.GetUserWithPermissions(user.ID)
	if err != nil {
		logger.Error("Failed to load user permissions",
			zap.String("user_id", user.ID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Extract permission UUIDs
	permissionIDs := make([]string, len(userWithPermissions.Permissions))
	for i, perm := range userWithPermissions.Permissions {
		permissionIDs[i] = perm.ID
	}

	// Create JWT token with proper claims
	claims := Claims{
		UserID:      user.ID,
		Username:    user.Username,
		Permissions: permissionIDs,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(h.config.JWT.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token
	tokenString, err := token.SignedString([]byte(h.config.JWT.Secret))
	if err != nil {
		logger.Error("Failed to sign token",
			zap.String("user_id", user.ID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	logger.Info("User authenticated successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.Username),
		zap.Int("permission_count", len(permissionIDs)),
	)

	c.JSON(http.StatusOK, gin.H{
		"token":    tokenString,
		"user_id":  user.ID,
		"username": user.Username,
	})
}
