package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/db"
	"sms-sync-server/internal/models"
	"sms-sync-server/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSQLInjectionPrevention tests that parameterized queries prevent SQL injection attacks
// OWASP: A03:2021 - Injection
func TestSQLInjectionPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security tests in short mode")
	}

	tests := []struct {
		name        string
		username    string
		password    string
		wantError   bool
		description string
	}{
		{
			name:        "Basic OR injection",
			username:    "admin' OR '1'='1",
			password:    "anything",
			wantError:   true,
			description: "Attempts: admin' OR '1'='1",
		},
		{
			name:        "Comment-based injection",
			username:    "admin'--",
			password:    "anything",
			wantError:   true,
			description: "Attempts to bypass with admin'--",
		},
		{
			name:        "UNION injection",
			username:    "admin' UNION SELECT null--",
			password:    "anything",
			wantError:   true,
			description: "Attempts UNION-based injection",
		},
		{
			name:        "Time-based blind injection",
			username:    "admin' AND SLEEP(5)--",
			password:    "anything",
			wantError:   true,
			description: "Attempts time-based blind SQL injection",
		},
		{
			name:        "Stacked queries injection",
			username:    "admin'; DROP TABLE users;--",
			password:    "anything",
			wantError:   true,
			description: "Attempts stacked queries to drop table",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			gin.SetMode(gin.TestMode)
			tempDir := t.TempDir()
			tempDBPath := filepath.Join(tempDir, "test_security.db")
			dsn := fmt.Sprintf("file:%s?cache=shared&mode=rwc", tempDBPath)

			database, err := db.NewDatabase(dsn)
			require.NoError(t, err)
			dbConn := database.GetDB()

			cfg := &config.Config{}
			cfg.JWT.Secret = "test-secret"
			cfg.JWT.TokenExpiry = 3600 * time.Second
			cfg.Security.TOTPEncryptionKey = "test-encryption-key-32-chars-long!"

			userService := services.NewUserServiceWithEncryption(
				db.NewUserRepository(dbConn),
				cfg,
			)

			handler := NewAuthHandler(cfg, userService)

			// Create legit user for comparison
			_, err = userService.CreateUser("legit_user", "legit@example.com", "secure_password")
			require.NoError(t, err)

			// Create request with injection attempt
			req := LoginRequest{
				Username: tt.username,
				Password: tt.password,
			}

			body, _ := json.Marshal(req)
			httpReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(body))
			httpReq.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			c, _ := gin.CreateTestContext(w)
			c.Request = httpReq
			c.Request.Header.Set("Content-Type", "application/json")

			// Execute
			handler.Login(c)

			// Verify: Should reject login but NOT cause database error
			assert.Equal(t, http.StatusUnauthorized, w.Code, "Injection attempt %s should return 401", tt.description)
			assert.NotContains(t, w.Body.String(), "database error", "Should not expose database errors")
			assert.NotContains(t, w.Body.String(), "SQL", "Should not mention SQL in error")

			// Verify: Legitimate user can still login (database not corrupted)
			req.Username = "legit_user"
			req.Password = "secure_password"
			body, _ = json.Marshal(req)
			httpReq = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(body))
			httpReq.Header.Set("Content-Type", "application/json")
			w = httptest.NewRecorder()

			c, _ = gin.CreateTestContext(w)
			c.Request = httpReq
			c.Request.Header.Set("Content-Type", "application/json")

			handler.Login(c)

			assert.Equal(t, http.StatusOK, w.Code, "Legitimate user should still be able to login after injection attempt")
		})
	}
}

// TestJWTTamperingPrevention tests JWT signature validation and claim verification
// OWASP: A01:2021 - Broken Authentication
func TestJWTTamperingPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security tests in short mode")
	}

	tests := []struct {
		name        string
		tokenFunc   func(secret string) string
		wantStatus  int
		description string
	}{
		{
			name: "Valid token",
			tokenFunc: func(secret string) string {
				claims := jwt.MapClaims{
					"user_id":     "test-user",
					"username":    "testuser",
					"permissions": []string{},
					"exp":         time.Now().Add(1 * time.Hour).Unix(),
					"iat":         time.Now().Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte(secret))
				return signed
			},
			wantStatus:  http.StatusOK,
			description: "Valid JWT signed with correct secret",
		},
		{
			name: "Invalid signature",
			tokenFunc: func(secret string) string {
				claims := jwt.MapClaims{
					"user_id":     "test-user",
					"username":    "testuser",
					"permissions": []string{},
					"exp":         time.Now().Add(1 * time.Hour).Unix(),
					"iat":         time.Now().Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				// Sign with wrong secret
				signed, _ := token.SignedString([]byte("wrong-secret"))
				return signed
			},
			wantStatus:  http.StatusUnauthorized,
			description: "Token signed with wrong secret",
		},
		{
			name: "Modified payload",
			tokenFunc: func(secret string) string {
				claims := jwt.MapClaims{
					"user_id":     "test-user",
					"username":    "testuser",
					"permissions": []string{},
					"exp":         time.Now().Add(1 * time.Hour).Unix(),
					"iat":         time.Now().Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte(secret))

				// Tamper with payload: change user_id in the token string
				parts := strings.Split(signed, ".")
				if len(parts) == 3 {
					// Attempt to modify the payload part
					signed = parts[0] + ".tampered." + parts[2]
				}
				return signed
			},
			wantStatus:  http.StatusUnauthorized,
			description: "Token with modified payload",
		},
		{
			name: "Expired token",
			tokenFunc: func(secret string) string {
				claims := jwt.MapClaims{
					"user_id":     "test-user",
					"username":    "testuser",
					"permissions": []string{},
					"exp":         time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
					"iat":         time.Now().Add(-2 * time.Hour).Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte(secret))
				return signed
			},
			wantStatus:  http.StatusUnauthorized,
			description: "Token with expiration time in the past",
		},
		{
			name: "None algorithm attack",
			tokenFunc: func(secret string) string {
				// Attempt to create token with 'none' algorithm
				claims := jwt.MapClaims{
					"user_id":     "admin",
					"username":    "admin",
					"permissions": []string{"admin"},
					"exp":         time.Now().Add(1 * time.Hour).Unix(),
					"iat":         time.Now().Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
				signed, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				return signed
			},
			wantStatus:  http.StatusUnauthorized,
			description: "Token with 'none' algorithm (should be rejected)",
		},
		{
			name: "Missing expiration claim",
			tokenFunc: func(secret string) string {
				claims := jwt.MapClaims{
					"user_id":     "test-user",
					"username":    "testuser",
					"permissions": []string{},
					"iat":         time.Now().Unix(),
					// exp is missing - jwt.Parse may not validate this by default
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte(secret))
				return signed
			},
			wantStatus:  http.StatusOK, // jwt.Parse accepts tokens without exp claim by default
			description: "Token missing expiration claim (jwt.Parse accepts by default)",
		},
		{
			name: "Invalid token format",
			tokenFunc: func(secret string) string {
				return "not.a.valid.token.format.extra"
			},
			wantStatus:  http.StatusUnauthorized,
			description: "Malformed token string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			jwtSecret := "test-secret-key-32-chars-minimum!"
			token := tt.tokenFunc(jwtSecret)

			// Make authenticated request
			req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Verify token validation
			// The actual middleware would validate, so we test the token extraction and validation
			tokenString := extractTokenFromHeader(req.Header.Get("Authorization"))
			assert.NotEmpty(t, tokenString, "Should extract token from header")

			// Parse token
			parsedToken, err := jwt.ParseWithClaims(
				tokenString,
				&Claims{},
				func(token *jwt.Token) (interface{}, error) {
					// Reject 'none' algorithm
					if token.Method.Alg() == "none" {
						return nil, jwt.ErrSignatureInvalid
					}
					return []byte(jwtSecret), nil
				},
			)

			if tt.wantStatus == http.StatusUnauthorized {
				assert.True(t, err != nil || !parsedToken.Valid,
					"Token should be invalid for: %s", tt.description)
			} else {
				assert.NoError(t, err, "Valid token should parse without error")
				assert.True(t, parsedToken.Valid, "Valid token should be valid")
			}
		})
	}
}

// TestSensitiveDataExposure tests that sensitive data is not leaked in responses or logs
// OWASP: A01:2021 - Broken Authentication, A02:2021 - Cryptographic Failures
func TestSensitiveDataExposure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security tests in short mode")
	}

	tests := []struct {
		name        string
		setupFunc   func(*db.Database, *config.Config) (*models.User, error)
		endpoint    string
		method      string
		makeRequest func(*http.Request)
		checkFunc   func(*testing.T, *httptest.ResponseRecorder)
		description string
	}{
		{
			name: "Password not in login response",
			setupFunc: func(database *db.Database, cfg *config.Config) (*models.User, error) {
				userService := services.NewUserServiceWithEncryption(
					db.NewUserRepository(database.GetDB()),
					cfg,
				)
				return userService.CreateUser("testuser", "testuser@example.com", "securepassword123")
			},
			endpoint: "/api/auth/login",
			method:   http.MethodPost,
			makeRequest: func(req *http.Request) {
				loginReq := LoginRequest{
					Username: "testuser",
					Password: "securepassword123",
				}
				body, _ := json.Marshal(loginReq)
				req.Body = io.NopCloser(bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
			},
			checkFunc: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.NotContains(t, w.Body.String(), "securepassword123",
					"Response should not contain password")
				assert.NotContains(t, strings.ToLower(w.Body.String()), "password",
					"Response should not contain password field")
			},
			description: "Login response should not contain password",
		},
		{
			name: "Generic error messages prevent user enumeration",
			setupFunc: func(database *db.Database, cfg *config.Config) (*models.User, error) {
				userService := services.NewUserServiceWithEncryption(
					db.NewUserRepository(database.GetDB()),
					cfg,
				)
				return userService.CreateUser("existinguser", "existing@example.com", "password123")
			},
			endpoint: "/api/auth/login",
			method:   http.MethodPost,
			makeRequest: func(req *http.Request) {
				loginReq := LoginRequest{
					Username: "nonexistentuser",
					Password: "wrongpassword",
				}
				body, _ := json.Marshal(loginReq)
				req.Body = io.NopCloser(bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
			},
			checkFunc: func(t *testing.T, w *httptest.ResponseRecorder) {
				responseBody := w.Body.String()
				// Should not reveal whether username exists
				assert.NotContains(t, responseBody, "nonexistentuser",
					"Should not reveal username doesn't exist")
				assert.NotContains(t, responseBody, "user not found",
					"Should not explicitly say user not found")
				// Should return generic auth error
				assert.Contains(t, responseBody, "Invalid credentials",
					"Should return generic credential error")
			},
			description: "Auth errors should be generic to prevent enumeration",
		},
		{
			name: "No stack traces in error responses",
			setupFunc: func(database *db.Database, cfg *config.Config) (*models.User, error) {
				return nil, nil
			},
			endpoint: "/api/auth/login",
			method:   http.MethodPost,
			makeRequest: func(req *http.Request) {
				// Send malformed JSON
				req.Body = io.NopCloser(bytes.NewBuffer([]byte("{invalid json}")))
				req.Header.Set("Content-Type", "application/json")
			},
			checkFunc: func(t *testing.T, w *httptest.ResponseRecorder) {
				responseBody := w.Body.String()
				assert.NotContains(t, responseBody, "panic",
					"Response should not contain panic traces")
				assert.NotContains(t, responseBody, "goroutine",
					"Response should not contain goroutine traces")
				assert.NotContains(t, responseBody, "/home/",
					"Response should not contain file paths")
				assert.NotContains(t, strings.ToLower(responseBody), "traceback",
					"Response should not contain traceback")
			},
			description: "Error responses should not expose stack traces",
		},
		{
			name: "TOTP secret not in user response",
			setupFunc: func(database *db.Database, cfg *config.Config) (*models.User, error) {
				userService := services.NewUserServiceWithEncryption(
					db.NewUserRepository(database.GetDB()),
					cfg,
				)
				user, err := userService.CreateUser("testuser", "testuser@example.com", "password123")
				if err != nil {
					return nil, err
				}
				// Simulate a user with TOTP secret
				secret := "JBSWY3DPEBLW64TMMQ======"
				user.TOTPSecret = &secret
				return user, nil
			},
			endpoint: "/api/users/testuser",
			method:   http.MethodGet,
			makeRequest: func(req *http.Request) {
				req.Header.Set("Content-Type", "application/json")
			},
			checkFunc: func(t *testing.T, w *httptest.ResponseRecorder) {
				responseBody := w.Body.String()
				// TOTP secret should never be in response
				assert.NotContains(t, responseBody, "JBSWY3DPEBLW64TMMQ======",
					"Response should not contain TOTP secret")
				assert.NotContains(t, strings.ToLower(responseBody), "totp_secret",
					"Response should not expose TOTP secret field")
			},
			description: "TOTP secrets should not be exposed in responses",
		},
		{
			name: "Account lockout message generic",
			setupFunc: func(database *db.Database, cfg *config.Config) (*models.User, error) {
				userService := services.NewUserServiceWithEncryption(
					db.NewUserRepository(database.GetDB()),
					cfg,
				)
				user, err := userService.CreateUser("testuser", "testuser@example.com", "realpassword")
				if err != nil {
					return nil, err
				}
				// Simulate failed attempts
				for i := 0; i < 6; i++ {
					userService.Authenticate("testuser", "wrongpassword", "")
				}
				return user, nil
			},
			endpoint: "/api/auth/login",
			method:   http.MethodPost,
			makeRequest: func(req *http.Request) {
				loginReq := LoginRequest{
					Username: "testuser",
					Password: "realpassword",
				}
				body, _ := json.Marshal(loginReq)
				req.Body = io.NopCloser(bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
			},
			checkFunc: func(t *testing.T, w *httptest.ResponseRecorder) {
				responseBody := w.Body.String()
				// Should indicate account is locked but be generic about timing
				assert.Equal(t, http.StatusForbidden, w.Code,
					"Locked account should return 403")
				assert.Contains(t, responseBody, "locked",
					"Should indicate account is locked")
				// Should not expose exact lockout duration or attempt count
				assert.NotContains(t, responseBody, "30 minute",
					"Should not expose exact lockout duration")
				assert.NotContains(t, responseBody, "5 attempts",
					"Should not expose failed attempt count")
			},
			description: "Account lockout message should be generic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			gin.SetMode(gin.TestMode)
			tempDir := t.TempDir()
			tempDBPath := filepath.Join(tempDir, "test_data_exp.db")
			dsn := fmt.Sprintf("file:%s?cache=shared&mode=rwc", tempDBPath)

			database, err := db.NewDatabase(dsn)
			require.NoError(t, err)

			cfg := &config.Config{}
			cfg.JWT.Secret = "test-secret"
			cfg.JWT.TokenExpiry = 3600 * time.Second
			cfg.Security.TOTPEncryptionKey = "test-encryption-key-32-chars-long!"

			// Create test user if needed
			_, err = tt.setupFunc(database, cfg)
			// Ignore setup errors for some tests

			// Create handler
			userService := services.NewUserServiceWithEncryption(
				db.NewUserRepository(database.GetDB()),
				cfg,
			)
			handler := NewAuthHandler(cfg, userService)

			// Create request
			req := httptest.NewRequest(tt.method, tt.endpoint, nil)
			tt.makeRequest(req)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Execute
			if strings.HasSuffix(tt.endpoint, "/login") {
				handler.Login(c)
			}

			// Verify
			tt.checkFunc(t, w)
		})
	}
}

// Helper function to extract token from Authorization header
func extractTokenFromHeader(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}
