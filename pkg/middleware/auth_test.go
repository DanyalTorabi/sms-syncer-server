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
