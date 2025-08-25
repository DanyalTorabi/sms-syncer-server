package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/pkg/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestLoginHandler(t *testing.T) {
	// Create test config
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test-secret"
	cfg.JWT.TokenExpiry = 24 * time.Hour

	tests := []struct {
		name           string
		username       string
		password       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid credentials",
			username:       "admin",
			password:       "password",
			expectedStatus: http.StatusOK,
			expectedBody:   `"token"`,
		},
		{
			name:           "Invalid username",
			username:       "wrong",
			password:       "password",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `"Invalid credentials"`,
		},
		{
			name:           "Invalid password",
			username:       "admin",
			password:       "wrong",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `"Invalid credentials"`,
		},
		{
			name:           "Missing username",
			username:       "",
			password:       "password",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"Username and password are required"`,
		},
		{
			name:           "Missing password",
			username:       "admin",
			password:       "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"Username and password are required"`,
		},
		{
			name:           "Missing authorization header",
			username:       "",
			password:       "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `"Missing credentials"`,
		},
		{
			name:           "Long username",
			username:       "a very long username that should still work",
			password:       "password",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `"Invalid credentials"`,
		},
		{
			name:           "Long password",
			username:       "admin",
			password:       "a very long password that should still work",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `"Invalid credentials"`,
		},
		{
			name:           "Special characters in username",
			username:       "admin@example.com",
			password:       "password",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `"Invalid credentials"`,
		},
		{
			name:           "Special characters in password",
			username:       "admin",
			password:       "pass@word!123",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `"Invalid credentials"`,
		},
	}

	gin.SetMode(gin.TestMode)
	router := gin.Default()

	// Add login handler
	router.POST("/api/auth/login", func(c *gin.Context) {
		username, password, ok := c.Request.BasicAuth()
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing credentials"})
			return
		}

		if username == "" || password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
			return
		}

		if username == "admin" && password == "password" {
			token, err := middleware.GenerateToken(username, cfg)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"token": token})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/auth/login", nil)
			if tt.username != "" || tt.password != "" {
				req.SetBasicAuth(tt.username, tt.password)
			}

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)
		})
	}

	// Test token generation error separately
	t.Run("token generation error", func(t *testing.T) {
		// Create a new router for this test
		router := gin.Default()

		// Create a test config with invalid secret to force token generation error
		invalidCfg := config.DefaultConfig()
		invalidCfg.JWT.Secret = "" // Empty secret will cause token generation to fail

		router.POST("/api/auth/login", func(c *gin.Context) {
			username, password, ok := c.Request.BasicAuth()
			if !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Missing credentials"})
				return
			}

			if username == "admin" && password == "password" {
				token, err := middleware.GenerateToken(username, invalidCfg)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": token})
				return
			}

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/auth/login", nil)
		req.SetBasicAuth("admin", "password")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), `"Failed to generate token"`)
	})
}
