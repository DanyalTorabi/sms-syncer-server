package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/db"
	"sms-sync-server/internal/services"
	"sms-sync-server/pkg/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSMSMessage represents the SMS message structure for testing
type TestSMSMessage struct {
	SMSId          int64  `json:"smsId"`
	PhoneNumber    string `json:"phoneNumber"`
	Body           string `json:"body"`
	EventType      string `json:"eventType"`
	SMSTimestamp   int64  `json:"smsTimestamp"`
	EventTimestamp int64  `json:"eventTimestamp"`
	ThreadId       int64  `json:"threadId,omitempty"`
	DateSent       int64  `json:"dateSent,omitempty"`
	Person         string `json:"person,omitempty"`
}

// IntegrationTestSuite holds the test environment
type IntegrationTestSuite struct {
	router     *gin.Engine
	database   *db.Database
	config     *config.Config
	tempDBPath string
}

// setupIntegrationTest initializes the test environment
func setupIntegrationTest(t *testing.T) *IntegrationTestSuite {
	// Create temporary database file
	tempDir := t.TempDir()
	tempDBPath := filepath.Join(tempDir, "test_integration.db")

	// Create test config
	cfg := &config.Config{}
	cfg.Server.Port = 8080
	cfg.Server.Host = "localhost"
	cfg.Database.DSN = fmt.Sprintf("file:%s?cache=shared&mode=rwc", tempDBPath)
	cfg.JWT.Secret = "test-secret-key-integration"
	cfg.JWT.TokenExpiry = 24 * time.Hour
	cfg.Logging.Level = "info"
	cfg.Logging.Path = "test.log"

	// Initialize database
	database, err := db.NewDatabase(cfg.Database.DSN)
	require.NoError(t, err, "Failed to initialize test database")

	// Initialize services
	smsService := services.NewSMSService(database)
	authHandler := NewAuthHandler(cfg)

	// Setup router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Auth endpoints
	auth := router.Group("/api/auth")
	{
		auth.POST("/login", authHandler.Login)
	}

	// SMS endpoints (protected)
	sms := router.Group("/api/sms")
	sms.Use(middleware.AuthMiddleware(cfg))
	{
		sms.POST("/add", func(c *gin.Context) {
			var msg db.SMSMessage
			if err := c.ShouldBindJSON(&msg); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
				return
			}

			// Extract userID from JWT token context
			userID, exists := c.Get("userID")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
				return
			}

			// Set the userID on the message
			msg.UserID = userID.(string)

			// Validate and save message
			if err := smsService.AddMessage(&msg); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"status": "success"})
		})

		sms.GET("/get", func(c *gin.Context) {
			// Extract userID from JWT token context
			userID, exists := c.Get("userID")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
				return
			}

			limit := 100
			offset := 0

			messages, err := smsService.GetMessages(userID.(string), limit, offset)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get messages"})
				return
			}

			c.JSON(http.StatusOK, messages)
		})
	}

	return &IntegrationTestSuite{
		router:     router,
		database:   database,
		config:     cfg,
		tempDBPath: tempDBPath,
	}
}

// cleanup removes temporary files
func (suite *IntegrationTestSuite) cleanup() {
	if suite.tempDBPath != "" {
		os.Remove(suite.tempDBPath)
	}
}

func TestFullIntegrationWorkflow(t *testing.T) {
	suite := setupIntegrationTest(t)
	defer suite.cleanup()

	// Test data
	testUsername := "testuser"
	testPassword := "testpass"
	testSMSMessage := TestSMSMessage{
		SMSId:          12345,
		PhoneNumber:    "+1234567890",
		Body:           "Integration test message",
		EventType:      "RECEIVED",
		SMSTimestamp:   time.Now().UnixMilli(),
		EventTimestamp: time.Now().UnixMilli(),
		ThreadId:       1,
		DateSent:       time.Now().UnixMilli(),
		Person:         "Test Person",
	}

	// Step 1: Test Health Endpoint
	t.Run("Health Check", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "ok", response["status"])
	})

	// Step 2: Test Login and Get JWT Token
	var jwtToken string
	t.Run("Login and Get JWT Token", func(t *testing.T) {
		loginData := map[string]string{
			"username": testUsername,
			"password": testPassword,
		}

		loginJSON, err := json.Marshal(loginData)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(loginJSON))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		token, exists := response["token"]
		require.True(t, exists, "Token should be present in response")
		jwtToken = token.(string)
		assert.NotEmpty(t, jwtToken, "JWT token should not be empty")
		t.Logf("JWT Token received: %s", jwtToken)
	})

	// Step 3: Test Adding SMS Message with JWT Authentication
	t.Run("Add SMS Message with JWT", func(t *testing.T) {
		smsJSON, err := json.Marshal(testSMSMessage)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(smsJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "success", response["status"])
	})

	// Step 4: Test Retrieving SMS Messages
	var retrievedMessages []*db.SMSMessage
	t.Run("Get SMS Messages with JWT", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/sms/get", nil)
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		err := json.Unmarshal(w.Body.Bytes(), &retrievedMessages)
		require.NoError(t, err)
		assert.Len(t, retrievedMessages, 1, "Should have exactly one message")

		// Verify the message content
		msg := retrievedMessages[0]
		assert.Equal(t, testUsername, msg.UserID)
		assert.Equal(t, testSMSMessage.PhoneNumber, msg.PhoneNumber)
		assert.Equal(t, testSMSMessage.Body, msg.Body)
		assert.Equal(t, testSMSMessage.EventType, msg.EventType)
		assert.Equal(t, testSMSMessage.SMSTimestamp, msg.SmsTimestamp)
		if msg.ThreadID != nil {
			assert.Equal(t, testSMSMessage.ThreadId, *msg.ThreadID)
		}
		if msg.Person != nil {
			assert.Equal(t, testSMSMessage.Person, *msg.Person)
		}
	})

	// Step 5: Verify Database State Directly
	t.Run("Verify Database State", func(t *testing.T) {
		// Query database directly to ensure data integrity
		messages, err := suite.database.GetMessages(testUsername, 100, 0)
		require.NoError(t, err)
		assert.Len(t, messages, 1, "Database should contain exactly one message")

		dbMsg := messages[0]
		assert.Equal(t, testUsername, dbMsg.UserID)
		assert.Equal(t, testSMSMessage.PhoneNumber, dbMsg.PhoneNumber)
		assert.Equal(t, testSMSMessage.Body, dbMsg.Body)
		assert.Equal(t, testSMSMessage.EventType, dbMsg.EventType)
		assert.Equal(t, testSMSMessage.SMSTimestamp, dbMsg.SmsTimestamp)
		assert.Equal(t, testSMSMessage.EventTimestamp, dbMsg.EventTimestamp)

		// Verify the message stored in DB matches what we sent
		assert.Equal(t, retrievedMessages[0].ID, dbMsg.ID, "API response should match database")
		assert.Equal(t, retrievedMessages[0].UserID, dbMsg.UserID, "UserID should match")
		assert.Equal(t, retrievedMessages[0].PhoneNumber, dbMsg.PhoneNumber, "Phone number should match")
		assert.Equal(t, retrievedMessages[0].Body, dbMsg.Body, "Message body should match")
	})
}

func TestAuthenticationFailures(t *testing.T) {
	suite := setupIntegrationTest(t)
	defer suite.cleanup()

	t.Run("Invalid Login Credentials", func(t *testing.T) {
		loginData := map[string]string{
			"username": "wronguser",
			"password": "wrongpass",
		}

		loginJSON, err := json.Marshal(loginData)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(loginJSON))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Access SMS Endpoint Without Token", func(t *testing.T) {
		smsMessage := TestSMSMessage{
			PhoneNumber:    "+1234567890",
			Body:           "Unauthorized test",
			EventType:      "RECEIVED",
			SMSTimestamp:   time.Now().UnixMilli(),
			EventTimestamp: time.Now().UnixMilli(),
		}

		smsJSON, err := json.Marshal(smsMessage)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(smsJSON))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Access SMS Endpoint With Invalid Token", func(t *testing.T) {
		smsMessage := TestSMSMessage{
			PhoneNumber:    "+1234567890",
			Body:           "Invalid token test",
			EventType:      "RECEIVED",
			SMSTimestamp:   time.Now().UnixMilli(),
			EventTimestamp: time.Now().UnixMilli(),
		}

		smsJSON, err := json.Marshal(smsMessage)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(smsJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer invalid-token-here")
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestMultipleUsersIsolation(t *testing.T) {
	suite := setupIntegrationTest(t)
	defer suite.cleanup()

	// This test would require multiple users in the system
	// For now, we'll test with the same user but verify data isolation concepts

	testUsername := "testuser"
	testPassword := "testpass"

	// Login and get token
	loginData := map[string]string{
		"username": testUsername,
		"password": testPassword,
	}

	loginJSON, err := json.Marshal(loginData)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	jwtToken := response["token"].(string)

	// Add multiple messages
	messages := []TestSMSMessage{
		{
			SMSId:          1,
			PhoneNumber:    "+1111111111",
			Body:           "Message 1",
			EventType:      "RECEIVED",
			SMSTimestamp:   time.Now().UnixMilli(),
			EventTimestamp: time.Now().UnixMilli(),
		},
		{
			SMSId:          2,
			PhoneNumber:    "+2222222222",
			Body:           "Message 2",
			EventType:      "SENT",
			SMSTimestamp:   time.Now().UnixMilli(),
			EventTimestamp: time.Now().UnixMilli(),
		},
	}

	for i, msg := range messages {
		t.Run(fmt.Sprintf("Add Message %d", i+1), func(t *testing.T) {
			smsJSON, err := json.Marshal(msg)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(smsJSON))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+jwtToken)
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}

	// Verify all messages are retrieved for the user
	t.Run("Verify All Messages Retrieved", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/sms/get", nil)
		req.Header.Set("Authorization", "Bearer "+jwtToken)
		w := httptest.NewRecorder()
		suite.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var retrievedMessages []*db.SMSMessage
		err := json.Unmarshal(w.Body.Bytes(), &retrievedMessages)
		require.NoError(t, err)
		assert.Len(t, retrievedMessages, len(messages))

		// Verify all messages belong to the correct user
		for _, msg := range retrievedMessages {
			assert.Equal(t, testUsername, msg.UserID)
		}
	})
}

func TestDataValidation(t *testing.T) {
	suite := setupIntegrationTest(t)
	defer suite.cleanup()

	// Get JWT token first
	loginData := map[string]string{
		"username": "testuser",
		"password": "testpass",
	}

	loginJSON, err := json.Marshal(loginData)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	jwtToken := response["token"].(string)

	// Test invalid message scenarios
	invalidMessages := []struct {
		name    string
		message TestSMSMessage
	}{
		{
			name: "Missing Phone Number",
			message: TestSMSMessage{
				Body:           "Test message",
				EventType:      "RECEIVED",
				SMSTimestamp:   time.Now().UnixMilli(),
				EventTimestamp: time.Now().UnixMilli(),
			},
		},
		{
			name: "Missing Body",
			message: TestSMSMessage{
				PhoneNumber:    "+1234567890",
				EventType:      "RECEIVED",
				SMSTimestamp:   time.Now().UnixMilli(),
				EventTimestamp: time.Now().UnixMilli(),
			},
		},
		{
			name: "Missing Event Type",
			message: TestSMSMessage{
				PhoneNumber:    "+1234567890",
				Body:           "Test message",
				SMSTimestamp:   time.Now().UnixMilli(),
				EventTimestamp: time.Now().UnixMilli(),
			},
		},
	}

	for _, tc := range invalidMessages {
		t.Run(tc.name, func(t *testing.T) {
			smsJSON, err := json.Marshal(tc.message)
			require.NoError(t, err)

			req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(smsJSON))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+jwtToken)
			w := httptest.NewRecorder()
			suite.router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}
