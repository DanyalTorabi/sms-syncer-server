package handlers

import (
	"net/http"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthHandler handles authentication-related requests
type AuthHandler struct {
	config *config.Config
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(cfg *config.Config) *AuthHandler {
	return &AuthHandler{config: cfg}
}

// Login handles user authentication and returns a JWT token
func (h *AuthHandler) Login(c *gin.Context) {
	logger.Info("Auth login endpoint called")
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Error("Failed to parse login request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" {
		logger.Error("Missing username or password")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	// TODO: Replace with actual user authentication
	if req.Username == "testuser" && req.Password == "testpass" {
		// Create the JWT token
		token := jwt.New(jwt.SigningMethodHS256)

		// Set claims
		claims := token.Claims.(jwt.MapClaims)
		claims["user_id"] = req.Username
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

		// Generate encoded token
		tokenString, err := token.SignedString([]byte(h.config.JWT.Secret))
		if err != nil {
			logger.Error("Failed to generate token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		// logger.Info("JWT token generated successfully for user: " + req.Username + ", token: " + tokenString)
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
		return
	}

	logger.Error("Invalid credentials")
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}
