package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sms-sync-server/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	return r
}

func TestAuthMiddleware(t *testing.T) {
	// Create test config
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test_secret"
	cfg.JWT.TokenExpiry = time.Hour * 24

	// Generate valid and expired tokens
	validToken := generateValidToken(cfg)
	expiredToken := generateExpiredToken(cfg)

	// Setup test cases
	testCases := []struct {
		name           string
		token          string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "missing token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Authorization header is required",
		},
		{
			name:           "invalid token",
			token:          "invalid",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Invalid token",
		},
		{
			name:           "expired token",
			token:          "Bearer " + expiredToken,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Token has expired",
		},
		{
			name:           "valid token",
			token:          "Bearer " + validToken,
			expectedStatus: http.StatusOK,
			expectedError:  "",
		},
	}

	// Create test router
	router := gin.New()
	router.Use(AuthMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test request
			req, _ := http.NewRequest("GET", "/test", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", tc.token)
			}

			// Create test response recorder
			w := httptest.NewRecorder()

			// Perform request
			router.ServeHTTP(w, req)

			// Check response
			assert.Equal(t, tc.expectedStatus, w.Code)
			if tc.expectedError != "" {
				assert.Contains(t, w.Body.String(), tc.expectedError)
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	// Create test config
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test-secret"
	cfg.JWT.TokenExpiry = 24 * time.Hour

	// Test cases
	testCases := []struct {
		name          string
		userID        string
		cfg           *config.Config
		expectedError string
	}{
		{
			name:          "empty user ID",
			userID:        "",
			cfg:           cfg,
			expectedError: "user ID is required",
		},
		{
			name:          "nil config",
			userID:        "test_user",
			cfg:           nil,
			expectedError: "config is required",
		},
		{
			name:          "empty secret",
			userID:        "test_user",
			cfg:           &config.Config{},
			expectedError: "JWT secret is required",
		},
		{
			name:          "valid token",
			userID:        "test_user",
			cfg:           cfg,
			expectedError: "",
		},
		{
			name:   "token signing error",
			userID: "test_user",
			cfg: &config.Config{
				JWT: struct {
					Secret      string        `json:"secret"`
					TokenExpiry time.Duration `json:"token_expiry"`
				}{},
			},
			expectedError: "JWT secret is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := GenerateToken(tc.userID, tc.cfg)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)

				// Verify token
				parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
					return []byte(cfg.JWT.Secret), nil
				})
				assert.NoError(t, err)
				assert.True(t, parsedToken.Valid)

				claims, ok := parsedToken.Claims.(*Claims)
				assert.True(t, ok)
				assert.Equal(t, tc.userID, claims.UserID)
			}
		})
	}
}

func generateValidToken(cfg *config.Config) string {
	token, _ := GenerateToken("test-user", cfg)
	return token
}

func generateExpiredToken(cfg *config.Config) string {
	claims := &Claims{
		UserID: "test-user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(cfg.JWT.Secret))
	return tokenString
}

func generateTokenWithInvalidSigningMethod(cfg *config.Config) string {
	claims := &Claims{
		UserID: "test-user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenString, _ := token.SignedString(privateKey)
	return tokenString
}

func generateTokenWithFutureNBF(cfg *config.Config) string {
	claims := &Claims{
		UserID: "test-user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(cfg.JWT.Secret))
	return tokenString
}

func generateTokenWithoutUserID(cfg *config.Config) string {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(cfg.JWT.Secret))
	return tokenString
}

func generateTokenWithInvalidClaims(cfg *config.Config) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"invalid": "claims",
	})
	tokenString, _ := token.SignedString([]byte(cfg.JWT.Secret))
	return tokenString
}

func generateTestToken(userID string, exp time.Time) string {
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test_secret"
	cfg.JWT.TokenExpiry = time.Until(exp)
	token, _ := GenerateToken(userID, cfg)
	return token
}

func generateInvalidClaimsToken() string {
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test_secret"
	return generateTokenWithInvalidClaims(cfg)
}

func generateTokenWithoutExp() string {
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test_secret"
	claims := &Claims{
		UserID: "test-user",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(cfg.JWT.Secret))
	return tokenString
}

func generateTokenWithInvalidExp() string {
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test_secret"
	claims := &Claims{
		UserID: "test-user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(cfg.JWT.Secret))
	return tokenString
}

// Test GenerateTokenWithPermissions
func TestGenerateTokenWithPermissions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.JWT.Secret = "test_secret"
	cfg.JWT.TokenExpiry = time.Hour

	tests := []struct {
		name        string
		userID      string
		permissions []string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid token with permissions",
			userID:      "user-123",
			permissions: []string{"users:read", "users:write"},
			wantErr:     false,
		},
		{
			name:        "valid token with empty permissions",
			userID:      "user-123",
			permissions: []string{},
			wantErr:     false,
		},
		{
			name:        "valid token with nil permissions",
			userID:      "user-123",
			permissions: nil,
			wantErr:     false,
		},
		{
			name:        "missing user ID",
			userID:      "",
			permissions: []string{"users:read"},
			wantErr:     true,
			errContains: "user ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateTokenWithPermissions(tt.userID, tt.permissions, cfg)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)

				// Verify token can be parsed and contains permissions
				parsed, parseErr := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
					return []byte(cfg.JWT.Secret), nil
				})
				assert.NoError(t, parseErr)
				assert.True(t, parsed.Valid)

				claims, ok := parsed.Claims.(*Claims)
				assert.True(t, ok)
				assert.Equal(t, tt.userID, claims.UserID)
				// nil and empty slice are equivalent for permissions
				if tt.permissions == nil {
					assert.Nil(t, claims.Permissions)
				} else if len(tt.permissions) == 0 {
					// Accept either nil or empty slice
					assert.True(t, claims.Permissions == nil || len(claims.Permissions) == 0)
				} else {
					assert.Equal(t, tt.permissions, claims.Permissions)
				}
			}
		})
	}
}

// Test RequirePermission middleware
func TestRequirePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		permissions    []string
		required       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "has required permission",
			permissions:    []string{"users:read", "users:write"},
			required:       "users:read",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "does not have required permission",
			permissions:    []string{"users:read"},
			required:       "users:write",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
		{
			name:           "empty permissions list",
			permissions:    []string{},
			required:       "users:read",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				c.Next()
			}, RequirePermission(tt.required), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

// Test RequireAnyPermission middleware
func TestRequireAnyPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		permissions    []string
		required       []string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "has one of required permissions",
			permissions:    []string{"users:read", "groups:read"},
			required:       []string{"users:read", "users:write"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "has all required permissions",
			permissions:    []string{"users:read", "users:write"},
			required:       []string{"users:read", "users:write"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "does not have any required permission",
			permissions:    []string{"groups:read"},
			required:       []string{"users:read", "users:write"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
		{
			name:           "empty permissions list",
			permissions:    []string{},
			required:       []string{"users:read"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				c.Next()
			}, RequireAnyPermission(tt.required...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

// Test RequireAllPermissions middleware
func TestRequireAllPermissions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		permissions    []string
		required       []string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "has all required permissions",
			permissions:    []string{"users:read", "users:write", "groups:read"},
			required:       []string{"users:read", "users:write"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing one required permission",
			permissions:    []string{"users:read"},
			required:       []string{"users:read", "users:write"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
		{
			name:           "missing all required permissions",
			permissions:    []string{"groups:read"},
			required:       []string{"users:read", "users:write"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
		{
			name:           "empty permissions list",
			permissions:    []string{},
			required:       []string{"users:read"},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test", func(c *gin.Context) {
				c.Set("permissions", tt.permissions)
				c.Next()
			}, RequireAllPermissions(tt.required...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

// Test IsSelfOrHasPermission middleware
func TestIsSelfOrHasPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		authUserID     string
		resourceUserID string
		permissions    []string
		required       string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "accessing own resource",
			authUserID:     "user-123",
			resourceUserID: "user-123",
			permissions:    []string{},
			required:       "users:write",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "accessing other's resource with permission",
			authUserID:     "user-123",
			resourceUserID: "user-456",
			permissions:    []string{"users:write"},
			required:       "users:write",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "accessing other's resource without permission",
			authUserID:     "user-123",
			resourceUserID: "user-456",
			permissions:    []string{"users:read"},
			required:       "users:write",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
		{
			name:           "accessing other's resource with empty permissions",
			authUserID:     "user-123",
			resourceUserID: "user-456",
			permissions:    []string{},
			required:       "users:write",
			expectedStatus: http.StatusForbidden,
			expectedError:  "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/users/:id", func(c *gin.Context) {
				c.Set("userID", tt.authUserID)
				c.Set("permissions", tt.permissions)
				c.Next()
			}, IsSelfOrHasPermission(tt.required), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/users/"+tt.resourceUserID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
		})
	}
}

// Test helper functions
func TestHasPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		required    string
		expected    bool
	}{
		{
			name:        "has permission",
			permissions: []string{"users:read", "users:write"},
			required:    "users:read",
			expected:    true,
		},
		{
			name:        "does not have permission",
			permissions: []string{"users:read"},
			required:    "users:write",
			expected:    false,
		},
		{
			name:        "empty permissions",
			permissions: []string{},
			required:    "users:read",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasPermission(tt.permissions, tt.required)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasAnyPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		required    []string
		expected    bool
	}{
		{
			name:        "has one permission",
			permissions: []string{"users:read"},
			required:    []string{"users:read", "users:write"},
			expected:    true,
		},
		{
			name:        "has multiple permissions",
			permissions: []string{"users:read", "users:write"},
			required:    []string{"users:read", "groups:read"},
			expected:    true,
		},
		{
			name:        "does not have any",
			permissions: []string{"groups:read"},
			required:    []string{"users:read", "users:write"},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAnyPermission(tt.permissions, tt.required...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasAllPermissions(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		required    []string
		expected    bool
	}{
		{
			name:        "has all permissions",
			permissions: []string{"users:read", "users:write", "groups:read"},
			required:    []string{"users:read", "users:write"},
			expected:    true,
		},
		{
			name:        "missing one permission",
			permissions: []string{"users:read"},
			required:    []string{"users:read", "users:write"},
			expected:    false,
		},
		{
			name:        "empty required",
			permissions: []string{"users:read"},
			required:    []string{},
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAllPermissions(tt.permissions, tt.required...)
			assert.Equal(t, tt.expected, result)
		})
	}
}
