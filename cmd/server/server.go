package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sms-sync-server/internal/config"
	"sms-sync-server/internal/db"
	"sms-sync-server/internal/handlers"
	"sms-sync-server/internal/services"
	"sms-sync-server/pkg/logger"
	"sms-sync-server/pkg/middleware"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SetupServer initializes and returns a configured HTTP server
func SetupServer(cfg *config.Config) (*http.Server, error) {
	if cfg == nil {
		return nil, errors.New("configuration is required")
	}

	if cfg.Server.Port <= 0 {
		return nil, errors.New("invalid server port")
	}

	// Initialize database
	database, err := db.NewDatabase(cfg.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Seed database if enabled
	if cfg.Seed.Enable {
		if err := database.SeedDatabase(cfg.Seed.AdminPassword); err != nil {
			return nil, fmt.Errorf("failed to seed database: %w", err)
		}
	}

	// Initialize repositories
	userRepo := db.NewUserRepository(database.GetDB())
	groupRepo := db.NewGroupRepository(database.GetDB())
	permissionRepo := db.NewPermissionRepository(database.GetDB())

	// Initialize services
	userService := services.NewUserService(userRepo)
	groupService := services.NewGroupService(groupRepo)
	permissionService := services.NewPermissionService(permissionRepo, groupRepo)
	smsService := services.NewSMSService(database)

	// Initialize router
	router := gin.Default()

	// Setup routes
	setupRoutes(router, cfg, smsService, userService, groupService, permissionService)

	// Create server with security timeouts
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:           router,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return srv, nil
}

// setupRoutes configures all the HTTP routes
func setupRoutes(
	router *gin.Engine,
	cfg *config.Config,
	smsService *services.SMSService,
	userService *services.UserService,
	groupService *services.GroupService,
	permissionService *services.PermissionService,
) {
	// Initialize handlers
	authHandler := handlers.NewAuthHandler(cfg, userService)
	userHandler := handlers.NewUserHandler(userService)

	// Basic health check endpoint (public)
	router.GET("/health", handleHealthCheck)

	// Auth endpoints (public)
	authGroup := router.Group("/api/auth")
	{
		authGroup.POST("/login", authHandler.Login)
	}

	// User registration endpoint (public)
	usersGroup := router.Group("/api/users")
	{
		usersGroup.POST("", userHandler.Register)
	}

	// Protected routes group
	protected := router.Group("/api")
	protected.Use(middleware.AuthMiddleware(cfg))

	// SMS endpoint (protected)
	protected.POST("/sms/add", func(c *gin.Context) {
		handleAddSMS(c, smsService)
	})
}

// handleHealthCheck handles the health check endpoint
func handleHealthCheck(c *gin.Context) {
	logger.Info("Health check endpoint called")
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"time":    time.Now().UTC(),
		"version": version,
		"service": "sms-sync-server",
	})
}

// handleAddSMS handles the SMS add endpoint
func handleAddSMS(c *gin.Context, smsService *services.SMSService) {
	logger.Info("SMS add endpoint called")

	// Extract and log the JWT token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && len(authHeader) > 7 { // "Bearer " is 7 characters
		jwtToken := authHeader[7:] // Remove "Bearer " prefix
		logger.Info("Received JWT token in Add SMS API", zap.String("token", jwtToken))
	}

	userID := c.GetString("userID") // Fixed: changed from "user_id" to "userID"
	logger.Info("Received SMS request", zap.String("user_id", userID))

	var msg db.SMSMessage
	if err := c.ShouldBindJSON(&msg); err != nil {
		logger.Warn("Invalid SMS request",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	msg.UserID = userID // Set the userID from JWT token on the message
	if msg.EventTimestamp == 0 {
		msg.EventTimestamp = time.Now().Unix()
	}

	logger.Info("Received SMS",
		zap.String("user_id", userID),
		zap.String("phoneNumber", msg.PhoneNumber),
	)

	if err := smsService.AddMessage(&msg); err != nil {
		logger.Error("Failed to save SMS",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.Info("SMS saved successfully",
		zap.String("user_id", userID),
		zap.String("phoneNumber", msg.PhoneNumber),
	)
	c.Status(http.StatusNoContent)
}

// StartServer starts the HTTP server and handles graceful shutdown
func StartServer(srv *http.Server) error {
	// Start server in a goroutine
	go func() {
		logger.Info("Starting server", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server error", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Create a timeout context for shutdown
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	return nil
}

// StartServerWithContext starts the HTTP server with a context for shutdown control
func StartServerWithContext(ctx context.Context, srv *http.Server) error {
	// Start server in a goroutine
	go func() {
		logger.Info("Starting server", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server error", zap.Error(err))
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	logger.Info("Shutting down server...")

	// Create a timeout context for shutdown
	ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()

	if err := srv.Shutdown(ctxShutdown); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	return nil
}
