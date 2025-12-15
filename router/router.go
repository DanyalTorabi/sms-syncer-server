package router

import (
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"sms-sync-server/internal/db"
	"sms-sync-server/pkg/logger"
	"sms-sync-server/pkg/middleware"

	"github.com/gin-gonic/gin"
)

// Database defines the interface that the router needs for database operations
type Database interface {
	AddMessage(msg *db.SMSMessage) error
	GetMessages(userID string, limit, offset int) ([]*db.SMSMessage, error)
}

type Router struct {
	engine   *gin.Engine
	database Database
}

func NewRouter(database Database) *Router {
	if database == nil {
		panic("database cannot be nil")
	}

	r := &Router{
		engine:   gin.Default(),
		database: database,
	}

	// Configure routes

	// Apply global middleware
	r.engine.Use(middleware.RequestIDMiddleware())
	r.engine.Use(middleware.SecurityHeadersMiddleware())
	r.engine.Use(middleware.CORSMiddleware())
	r.engine.Use(middleware.AuditLogMiddleware())
	r.engine.Use(middleware.RequestSizeLimitMiddleware(1024 * 1024)) // 1MB limit

	r.engine.GET("/health", r.handleHealth)
	r.engine.NoRoute(r.handleNotFound)

	smsGroup := r.engine.Group("/api/sms")
	{
		// Register specific method handlers first
		smsGroup.POST("/add", r.handleAddMessage)
		smsGroup.GET("/get", r.handleGetMessages)

		// Then register method not allowed handlers for all other methods
		smsGroup.Handle(http.MethodGet, "/add", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodPut, "/add", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodDelete, "/add", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodPatch, "/add", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodHead, "/add", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodOptions, "/add", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodConnect, "/add", r.handleMethodNotAllowed)

		smsGroup.Handle(http.MethodPost, "/get", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodPut, "/get", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodDelete, "/get", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodPatch, "/get", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodHead, "/get", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodOptions, "/get", r.handleMethodNotAllowed)
		smsGroup.Handle(http.MethodConnect, "/get", r.handleMethodNotAllowed)
	}

	return r
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.engine.ServeHTTP(w, req)
}

func (r *Router) handleHealth(c *gin.Context) {
	logger.Info("Health check endpoint called")
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (r *Router) handleNotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
}

func (r *Router) handleMethodNotAllowed(c *gin.Context) {
	c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
}

func (r *Router) validateMessage(msg *db.SMSMessage) error {
	if msg.UserID == "" {
		return gin.Error{Err: errors.New("user ID is required"), Type: gin.ErrorTypeBind}
	}

	if msg.PhoneNumber == "" {
		return gin.Error{Err: errors.New("phone number is required"), Type: gin.ErrorTypeBind}
	}

	// Basic phone number validation (E.164-ish or at least 10 digits)
	// Allowing + and digits, min 10 chars, max 15 usually for E.164
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{9,14}$`)
	if !phoneRegex.MatchString(msg.PhoneNumber) {
		return gin.Error{Err: errors.New("invalid phone number format"), Type: gin.ErrorTypeBind}
	}

	if msg.Body == "" || strings.TrimSpace(msg.Body) == "" {
		return gin.Error{Err: errors.New("message body is required"), Type: gin.ErrorTypeBind}
	}

	// Message size limit (e.g., 2048 characters)
	if len(msg.Body) > 2048 {
		return gin.Error{Err: errors.New("message body too large"), Type: gin.ErrorTypeBind}
	}

	if msg.EventType == "" {
		return gin.Error{Err: errors.New("event type is required"), Type: gin.ErrorTypeBind}
	}

	if msg.SmsTimestamp == 0 {
		return gin.Error{Err: errors.New("sms timestamp is required"), Type: gin.ErrorTypeBind}
	}

	return nil
}

func (r *Router) handleAddMessage(c *gin.Context) {
	logger.Info("SMS add message endpoint called")
	// Check content type
	if c.ContentType() != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "unsupported media type"})
		return
	}

	var msg db.SMSMessage
	if err := c.ShouldBindJSON(&msg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := r.validateMessage(&msg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := r.database.AddMessage(&msg); err != nil {
		log.Printf("Failed to add message: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save message"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func (r *Router) handleGetMessages(c *gin.Context) {
	logger.Info("SMS get messages endpoint called")
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user ID is required"})
		return
	}

	limit := 100
	offset := 0

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err != nil || l <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit value"})
			return
		} else {
			limit = l
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err != nil || o < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid offset value"})
			return
		} else {
			offset = o
		}
	}

	messages, err := r.database.GetMessages(userID, limit, offset)
	if err != nil {
		log.Printf("Failed to get messages: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get messages"})
		return
	}

	c.JSON(http.StatusOK, messages)
}
