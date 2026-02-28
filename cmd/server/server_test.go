package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/db"
	"sms-sync-server/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDatabase is a mock implementation of DatabaseInterface
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) AddMessage(msg *db.SMSMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func (m *MockDatabase) GetMessages(userID string, limit, offset int) ([]*db.SMSMessage, error) {
	args := m.Called(userID, limit, offset)
	return args.Get(0).([]*db.SMSMessage), args.Error(1)
}

func (m *MockDatabase) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestSetupServer(t *testing.T) {
	// Test with valid configuration
	cfg := config.DefaultConfig()
	cfg.Server.Port = 8080
	cfg.Database.DSN = "file:test.db?mode=memory&cache=shared"

	srv, err := SetupServer(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, srv)
	assert.Equal(t, ":8080", srv.Addr)
	srv.Close()

	// Test with invalid database configuration
	cfg.Database.DSN = "invalid://dsn"
	srv, err = SetupServer(cfg)
	assert.Error(t, err)
	assert.Nil(t, srv)

	// Test with empty configuration
	srv, err = SetupServer(nil)
	assert.Error(t, err)
	assert.Nil(t, srv)

	// Test with invalid port
	cfg = config.DefaultConfig()
	cfg.Server.Port = -1
	srv, err = SetupServer(cfg)
	assert.Error(t, err)
	assert.Nil(t, srv)

	// Test with TLS enabled but invalid cert/key files
	cfg = config.DefaultConfig()
	cfg.Server.Port = 8080
	cfg.Database.DSN = "file:test-tls.db?mode=memory&cache=shared"
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.CertFile = "invalid-cert.pem"
	cfg.Server.TLS.KeyFile = "invalid-key.pem"
	srv, err = SetupServer(cfg)
	assert.Error(t, err)
	assert.Nil(t, srv)
}

func TestHandleHealthCheck(t *testing.T) {
	// Setup test
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/health", handleHealthCheck)

	// Create test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ok", response["status"])
	assert.NotEmpty(t, response["time"])
}

func TestHandleAddSMS(t *testing.T) {
	// Setup test
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create mock database and service
	mockDB := new(MockDatabase)
	smsService := services.NewSMSService(mockDB)

	// Setup test data
	testMsg := db.SMSMessage{
		PhoneNumber:    "1234567890",
		Body:           "Test message",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	// Setup route with middleware to set user ID
	router.POST("/api/sms/add", func(c *gin.Context) {
		c.Set("userID", "test-user")
		handleAddSMS(c, smsService)
	})

	// Setup request
	body, _ := json.Marshal(testMsg)
	req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Setup mock expectations
	mockDB.On("AddMessage", mock.AnythingOfType("*db.SMSMessage")).Return(nil)

	// Serve the request
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusNoContent, w.Code)
	mockDB.AssertExpectations(t)
}

func TestHandleAddSMS_InvalidRequest(t *testing.T) {
	// Setup test
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create mock database and service
	mockDB := new(MockDatabase)
	smsService := services.NewSMSService(mockDB)

	// Setup route with middleware to set user ID
	router.POST("/api/sms/add", func(c *gin.Context) {
		c.Set("user_id", "test-user")
		handleAddSMS(c, smsService)
	})

	// Setup invalid request
	req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Serve the request
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleAddSMS_ServiceError(t *testing.T) {
	// Setup test
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Create mock database and service
	mockDB := new(MockDatabase)
	smsService := services.NewSMSService(mockDB)

	// Setup test data
	testMsg := db.SMSMessage{
		PhoneNumber:    "1234567890",
		Body:           "Test message",
		EventType:      "RECEIVED",
		SmsTimestamp:   time.Now().Unix(),
		EventTimestamp: time.Now().Unix(),
	}

	// Setup route with middleware to set user ID
	router.POST("/api/sms/add", func(c *gin.Context) {
		c.Set("userID", "test-user")
		handleAddSMS(c, smsService)
	})

	// Setup request
	body, _ := json.Marshal(testMsg)
	req := httptest.NewRequest("POST", "/api/sms/add", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Setup mock to return error
	mockDB.On("AddMessage", mock.AnythingOfType("*db.SMSMessage")).Return(assert.AnError)

	// Serve the request
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockDB.AssertExpectations(t)
}

func TestSetupRoutes(t *testing.T) {
	// Setup test
	gin.SetMode(gin.TestMode)
	router := gin.New()
	cfg := config.DefaultConfig()

	// Create mock database and service
	mockDB := new(MockDatabase)
	smsService := services.NewSMSService(mockDB)

	// Test with valid configuration
	setupRoutes(router, cfg, smsService, nil, nil, nil)

	// Verify routes are registered
	routes := router.Routes()
	assert.NotEmpty(t, routes)

	// Verify health check route
	healthCheckFound := false
	for _, route := range routes {
		if route.Path == "/health" && route.Method == "GET" {
			healthCheckFound = true
		}
	}
	assert.True(t, healthCheckFound)

	// Verify SMS add route
	smsAddFound := false
	for _, route := range routes {
		if route.Path == "/api/sms/add" && route.Method == "POST" {
			smsAddFound = true
		}
	}
	assert.True(t, smsAddFound)

	// Test with nil router
	assert.Panics(t, func() {
		setupRoutes(nil, cfg, smsService, nil, nil, nil)
	})

	// Test with nil service
	assert.Panics(t, func() {
		setupRoutes(router, cfg, nil, nil, nil, nil)
	})

	// Test with nil config
	assert.Panics(t, func() {
		setupRoutes(router, nil, smsService, nil, nil, nil)
	})
}

func TestStartServer(t *testing.T) {
	// Create a test server
	srv := &http.Server{
		Addr:    ":0", // Use port 0 to let the OS assign a random port
		Handler: gin.New(),
	}

	// Start the server in a goroutine
	go func() {
		err := StartServer(srv)
		assert.NoError(t, err)
	}()

	// Wait a bit for the server to start
	time.Sleep(100 * time.Millisecond)

	// Send interrupt signal to trigger shutdown
	p, err := os.FindProcess(os.Getpid())
	assert.NoError(t, err)
	err = p.Signal(syscall.SIGINT)
	assert.NoError(t, err)

	// Wait for server to shut down
	time.Sleep(100 * time.Millisecond)
}

func TestStartServerWithContext(t *testing.T) {
	// Create a test server
	srv := &http.Server{
		Addr:    ":0", // Use port 0 to let the OS assign a random port
		Handler: gin.New(),
	}

	// Create a context with cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		err := StartServerWithContext(ctx, srv)
		errChan <- err
	}()

	// Wait a bit for the server to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context to trigger shutdown
	cancel()

	// Wait for server to shut down and check error
	select {
	case err := <-errChan:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Server didn't shut down within timeout")
	}
}
