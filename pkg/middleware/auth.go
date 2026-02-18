package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sms-sync-server/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims
type Claims struct {
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// AuthMiddleware creates a middleware for JWT authentication
func AuthMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Test case: "missing token"
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Test case: "invalid token"
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWT.Secret), nil
		})

		// Test case: "expired token"
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Test case: "missing user ID"
		if claims.UserID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Check for missing expiration claim
		if claims.ExpiresAt == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Test case: "valid token"
		c.Set("userID", claims.UserID)
		c.Set("permissions", claims.Permissions)
		c.Next()
	}
}

// GenerateToken generates a new JWT token
func GenerateToken(userID string, cfg *config.Config) (string, error) {
	if userID == "" {
		return "", errors.New("user ID is required")
	}
	if cfg == nil {
		return "", errors.New("config is required")
	}
	if cfg.JWT.Secret == "" {
		return "", errors.New("JWT secret is required")
	}

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.JWT.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.JWT.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return tokenString, nil
}

// GenerateTokenWithPermissions generates a new JWT token with permissions
func GenerateTokenWithPermissions(userID string, permissions []string, cfg *config.Config) (string, error) {
	if userID == "" {
		return "", errors.New("user ID is required")
	}
	if cfg == nil {
		return "", errors.New("config is required")
	}
	if cfg.JWT.Secret == "" {
		return "", errors.New("JWT secret is required")
	}

	claims := &Claims{
		UserID:      userID,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.JWT.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.JWT.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return tokenString, nil
}

// RequirePermission creates middleware that requires a specific permission
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "No permissions found"})
			c.Abort()
			return
		}

		permList, ok := permissions.([]string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid permissions format"})
			c.Abort()
			return
		}

		if !hasPermission(permList, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission creates middleware that requires at least one of the specified permissions
func RequireAnyPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userPerms, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "No permissions found"})
			c.Abort()
			return
		}

		permList, ok := userPerms.([]string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid permissions format"})
			c.Abort()
			return
		}

		if !hasAnyPermission(permList, permissions...) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAllPermissions creates middleware that requires all specified permissions
func RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userPerms, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "No permissions found"})
			c.Abort()
			return
		}

		permList, ok := userPerms.([]string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid permissions format"})
			c.Abort()
			return
		}

		if !hasAllPermissions(permList, permissions...) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// IsSelfOrHasPermission creates middleware that allows access if user is accessing their own resource
// or has the specified permission
func IsSelfOrHasPermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get authenticated user ID
		authUserID, _ := c.Get("userID")
		authUserIDStr, _ := authUserID.(string)

		// Get resource user ID from path parameter
		resourceUserID := c.Param("id")

		// Allow if accessing own resource
		if authUserIDStr == resourceUserID {
			c.Next()
			return
		}

		// Otherwise, require the specified permission
		permissions, exists := c.Get("permissions")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		permList, ok := permissions.([]string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid permissions format"})
			c.Abort()
			return
		}

		if !hasPermission(permList, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// hasPermission checks if a specific permission exists in the list
func hasPermission(permissions []string, required string) bool {
	for _, p := range permissions {
		if p == required {
			return true
		}
	}
	return false
}

// hasAnyPermission checks if at least one of the required permissions exists
func hasAnyPermission(permissions []string, required ...string) bool {
	for _, req := range required {
		if hasPermission(permissions, req) {
			return true
		}
	}
	return false
}

// hasAllPermissions checks if all required permissions exist
func hasAllPermissions(permissions []string, required ...string) bool {
	for _, req := range required {
		if !hasPermission(permissions, req) {
			return false
		}
	}
	return true
}
