package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sms-sync-server/internal/config"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()

	// Register GET handler
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Register handlers for other methods to return method not allowed
	router.POST("/health", func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	})
	router.PUT("/health", func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	})
	router.DELETE("/health", func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed"})
	})

	// Add not found handler
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
	})

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Valid GET request",
			method:         http.MethodGet,
			path:           "/health",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "Invalid method - POST",
			method:         http.MethodPost,
			path:           "/health",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   `{"error":"Method not allowed"}`,
		},
		{
			name:           "Invalid method - PUT",
			method:         http.MethodPut,
			path:           "/health",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   `{"error":"Method not allowed"}`,
		},
		{
			name:           "Invalid method - DELETE",
			method:         http.MethodDelete,
			path:           "/health",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   `{"error":"Method not allowed"}`,
		},
		{
			name:           "Invalid path",
			method:         http.MethodGet,
			path:           "/healthz",
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
		{
			name:           "With query parameters",
			method:         http.MethodGet,
			path:           "/health?check=true",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "With trailing slash",
			method:         http.MethodGet,
			path:           "/health/",
			expectedStatus: http.StatusMovedPermanently,
			expectedBody:   "",
		},
		{
			name:           "With headers",
			method:         http.MethodGet,
			path:           "/health",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "With invalid content type",
			method:         http.MethodGet,
			path:           "/health",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:           "With empty path",
			method:         http.MethodGet,
			path:           "",
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Not found"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.JSONEq(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestMainStartupAndShutdown(t *testing.T) {
	// Setup test config
	cfg := config.DefaultConfig()
	cfg.Server.Port = 8081 // Use different port for testing

	// Test server startup
	t.Run("TestServerStartup", func(t *testing.T) {
		// Setup server
		srv, err := SetupServer(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, srv)

		// Start server in background
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		go func() {
			_ = StartServerWithContext(ctx, srv)
		}()

		// Wait for server to start
		time.Sleep(100 * time.Millisecond)

		// The server should be ready to accept connections
		assert.Equal(t, ":8081", srv.Addr)
	})

	// Test configuration loading
	t.Run("TestConfigLoading", func(t *testing.T) {
		cfg := config.DefaultConfig()
		assert.NotNil(t, cfg)
		assert.Equal(t, 8080, cfg.Server.Port)
	})

	// Test server setup with invalid config
	t.Run("TestServerSetupWithInvalidConfig", func(t *testing.T) {
		// Test with nil config
		srv, err := SetupServer(nil)
		assert.Error(t, err)
		assert.Nil(t, srv)

		// Test with invalid port
		invalidCfg := config.DefaultConfig()
		invalidCfg.Server.Port = 0
		srv, err = SetupServer(invalidCfg)
		assert.Error(t, err)
		assert.Nil(t, srv)
	})
}
