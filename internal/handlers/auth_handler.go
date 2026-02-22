package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/services"
	"sms-sync-server/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	qrcode "github.com/skip2/go-qrcode"
	"go.uber.org/zap"
)

type LoginRequest struct {
	Username string `json:"username"`
	// #nosec G117 - Input struct for receiving credentials, not exposing secrets
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"` // Optional 2FA code
}

// Claims represents the JWT claims structure with user ID and permission names
type Claims struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Permissions []string `json:"permissions"` // Array of permission names (e.g. users:read)
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
// Returns JWT token with 1-hour expiry containing user ID and permission names
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

	// Extract permission names for middleware permission checks
	permissionNames := make([]string, len(userWithPermissions.Permissions))
	for i, perm := range userWithPermissions.Permissions {
		permissionNames[i] = perm.Name
	}

	// Create JWT token with proper claims
	claims := Claims{
		UserID:      user.ID,
		Username:    user.Username,
		Permissions: permissionNames,
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
		zap.Int("permission_count", len(permissionNames)),
	)

	c.JSON(http.StatusOK, gin.H{
		"token":    tokenString,
		"user_id":  user.ID,
		"username": user.Username,
	})
}

// Generate2FASecret generates a new TOTP secret for the authenticated user
// Returns the secret and a QR code as base64-encoded PNG
func (h *AuthHandler) Generate2FASecret(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Generate TOTP secret
	secret, err := h.userService.GenerateTOTPSecret(userID)
	if err != nil {
		logger.Error("Failed to generate TOTP secret",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate 2FA secret"})
		return
	}

	// Get user details for QR code
	user, err := h.userService.GetUser(userID)
	if err != nil {
		logger.Error("Failed to get user details",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate 2FA secret"})
		return
	}

	// Generate QR code URI
	qrURI := fmt.Sprintf("otpauth://totp/SMS%%20Syncer:%s?secret=%s&issuer=SMS%%20Syncer",
		user.Username, secret)

	// Generate QR code as PNG
	qrCodeBytes, err := qrcode.Encode(qrURI, qrcode.Medium, 256)
	if err != nil {
		logger.Error("Failed to generate QR code",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	// Encode QR code as base64
	qrCodeBase64 := base64.StdEncoding.EncodeToString(qrCodeBytes)

	logger.Info("2FA secret generated successfully",
		zap.String("user_id", userID),
		zap.String("username", user.Username),
	)

	c.JSON(http.StatusOK, gin.H{
		"secret":  secret,
		"qr_code": qrCodeBase64,
		"qr_uri":  qrURI,
	})
}

// Enable2FARequest represents the request body for enabling 2FA
type Enable2FARequest struct {
	TOTPCode string `json:"totp_code" binding:"required"`
}

// Enable2FA enables 2FA for the authenticated user after validating the TOTP code
func (h *AuthHandler) Enable2FA(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req Enable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error("Failed to parse enable 2FA request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOTP code is required"})
		return
	}

	// Enable TOTP
	if err := h.userService.EnableTOTP(userID, req.TOTPCode); err != nil {
		logger.Warn("Failed to enable 2FA",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		if err == services.ErrInvalidTOTP {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid TOTP code"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable 2FA"})
		}
		return
	}

	logger.Info("2FA enabled successfully",
		zap.String("user_id", userID),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA enabled successfully",
	})
}

// Disable2FA disables 2FA for the authenticated user
func (h *AuthHandler) Disable2FA(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		logger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Disable TOTP
	if err := h.userService.DisableTOTP(userID); err != nil {
		logger.Error("Failed to disable 2FA",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable 2FA"})
		return
	}

	logger.Info("2FA disabled successfully",
		zap.String("user_id", userID),
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA disabled successfully",
	})
}
