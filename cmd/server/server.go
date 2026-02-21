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
	userService := services.NewUserServiceWithEncryption(userRepo, cfg)
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
	groupHandler := handlers.NewGroupHandler(groupService)
	permissionHandler := handlers.NewPermissionHandler(permissionService)

	// Basic health check endpoint (public)
	router.GET("/health", handleHealthCheck)

	// Auth endpoints (public)
	authGroup := router.Group("/api/auth")
	{
		authGroup.POST("/login", authHandler.Login)
	}

	// Protected auth endpoints (2FA management)
	protectedAuth := router.Group("/api/auth")
	protectedAuth.Use(middleware.AuthMiddleware(cfg))
	{
		protectedAuth.POST("/2fa/generate", authHandler.Generate2FASecret)
		protectedAuth.POST("/2fa/enable", authHandler.Enable2FA)
		protectedAuth.POST("/2fa/disable", authHandler.Disable2FA)
	}

	// User registration endpoint (public)
	usersGroup := router.Group("/api/users")
	{
		usersGroup.POST("", userHandler.Register)
	}

	// Protected routes group
	protected := router.Group("/api")
	protected.Use(middleware.AuthMiddleware(cfg))

	// User management endpoints (protected)
	protectedUsers := protected.Group("/users")
	{
		// List users (GET /api/users) - requires users:read permission
		protectedUsers.GET("", middleware.RequirePermission("users:read"), userHandler.ListUsers)

		// Get user by ID (GET /api/users/:id) - self-access or users:read permission
		protectedUsers.GET("/:id", middleware.IsSelfOrHasPermission("users:read"), userHandler.GetUserByID)

		// Update user (PUT /api/users/:id) - self-access or users:write permission
		protectedUsers.PUT("/:id", middleware.IsSelfOrHasPermission("users:write"), userHandler.UpdateUserByID)

		// Delete user - soft delete (DELETE /api/users/:id) - self-access or users:delete permission
		protectedUsers.DELETE("/:id", middleware.IsSelfOrHasPermission("users:delete"), userHandler.DeleteUserByID)

		// Self-service password change - authenticated users can change their own password
		protectedUsers.POST("/:id/password", userHandler.ChangePassword)

		// User-group assignment - requires both users:write and groups:manage permissions
		protectedUsers.POST("/:id/groups", middleware.RequireAllPermissions("users:write", "groups:manage"), userHandler.AssignUserToGroup)
		protectedUsers.DELETE("/:id/groups/:groupId", middleware.RequireAllPermissions("users:write", "groups:manage"), userHandler.RemoveUserFromGroup)

		// Get user's groups - self-access or users:read permission
		protectedUsers.GET("/:id/groups", middleware.IsSelfOrHasPermission("users:read"), userHandler.ListUserGroups)
	}

	// Admin routes (protected)
	adminGroup := protected.Group("/admin")
	{
		// Admin password reset - requires users:write permission
		adminGroup.POST("/users/:id/password/reset", middleware.RequirePermission("users:write"), userHandler.AdminResetPassword)
	}

	// Group management endpoints (protected) - all require groups:manage permission
	protectedGroups := protected.Group("/groups")
	protectedGroups.Use(middleware.RequirePermission("groups:manage"))
	{
		// Create group (POST /api/groups)
		protectedGroups.POST("", groupHandler.CreateGroup)

		// List groups with pagination (GET /api/groups)
		protectedGroups.GET("", groupHandler.ListGroups)

		// Get group by ID (GET /api/groups/:id)
		protectedGroups.GET("/:id", groupHandler.GetGroupByID)

		// Update group (PUT /api/groups/:id)
		protectedGroups.PUT("/:id", groupHandler.UpdateGroup)

		// Delete group (DELETE /api/groups/:id)
		protectedGroups.DELETE("/:id", groupHandler.DeleteGroup)

		// Add permission to group (POST /api/groups/:id/permissions)
		protectedGroups.POST("/:id/permissions", groupHandler.AddPermissionToGroup)

		// Remove permission from group (DELETE /api/groups/:id/permissions/:permissionId)
		protectedGroups.DELETE("/:id/permissions/:permissionId", groupHandler.RemovePermissionFromGroup)
	}

	// Permission management endpoints (protected) - all require permissions:manage permission
	protectedPerms := protected.Group("/permissions")
	protectedPerms.Use(middleware.RequirePermission("permissions:manage"))
	{
		// Create permission (POST /api/permissions)
		protectedPerms.POST("", permissionHandler.CreatePermission)

		// List permissions with pagination (GET /api/permissions)
		protectedPerms.GET("", permissionHandler.ListPermissions)

		// Get permission by ID (GET /api/permissions/:id)
		protectedPerms.GET("/:id", permissionHandler.GetPermissionByID)

		// Update permission (PUT /api/permissions/:id)
		protectedPerms.PUT("/:id", permissionHandler.UpdatePermission)

		// Delete permission (DELETE /api/permissions/:id)
		protectedPerms.DELETE("/:id", permissionHandler.DeletePermission)
	}

	// SMS endpoint (protected) - requires sms:write permission
	protected.POST("/sms/add", middleware.RequirePermission("sms:write"), func(c *gin.Context) {
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
