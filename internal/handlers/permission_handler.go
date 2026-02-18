package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"sms-sync-server/internal/models"
	"sms-sync-server/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// PermissionHandler handles permission management requests
type PermissionHandler struct {
	permissionService PermissionServiceInterface
}

// NewPermissionHandler creates a new permission handler
func NewPermissionHandler(permissionService PermissionServiceInterface) *PermissionHandler {
	return &PermissionHandler{
		permissionService: permissionService,
	}
}

// CreatePermission handles creating a new permission (POST /api/permissions)
// Requires permissions:write permission
func (h *PermissionHandler) CreatePermission(c *gin.Context) {
	logger.Info("Create permission endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "permissions:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Parse request
	var req models.CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid create permission request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Create permission
	permission, err := h.permissionService.CreatePermission(req.Name, req.Resource, req.Action, req.Description)
	if err != nil {
		logger.Error("Failed to create permission",
			zap.String("name", req.Name),
			zap.Error(err),
		)
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "must match") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}

	logger.Info("Permission created successfully", zap.String("permission_id", permission.ID))
	c.JSON(http.StatusCreated, permission)
}

// ListPermissions handles listing all permissions with pagination (GET /api/permissions)
// Requires permissions:read permission
func (h *PermissionHandler) ListPermissions(c *gin.Context) {
	logger.Info("List permissions endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "permissions:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Parse pagination parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// Validate pagination
	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	// Get permissions
	perms, err := h.permissionService.ListPermissions(limit, offset)
	if err != nil {
		logger.Error("Failed to list permissions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list permissions"})
		return
	}

	logger.Info("Permissions retrieved successfully", zap.Int("count", len(perms)))
	c.JSON(http.StatusOK, gin.H{
		"permissions": perms,
		"limit":       limit,
		"offset":      offset,
	})
}

// GetPermissionByID handles retrieving a permission by ID (GET /api/permissions/:id)
// Requires permissions:read permission
func (h *PermissionHandler) GetPermissionByID(c *gin.Context) {
	logger.Info("Get permission by ID endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "permissions:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Get permission ID from path
	permissionID := c.Param("id")
	if permissionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Permission ID is required"})
		return
	}

	// Get permission
	permission, err := h.permissionService.GetPermission(permissionID)
	if err != nil {
		logger.Warn("Failed to retrieve permission",
			zap.String("permission_id", permissionID),
			zap.Error(err),
		)
		if err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve permission"})
		}
		return
	}

	logger.Info("Permission retrieved successfully", zap.String("permission_id", permissionID))
	c.JSON(http.StatusOK, permission)
}

// UpdatePermission handles updating a permission (PUT /api/permissions/:id)
// Requires permissions:write permission
// Can only update description and active status (not name, resource, or action)
func (h *PermissionHandler) UpdatePermission(c *gin.Context) {
	logger.Info("Update permission endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "permissions:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Get permission ID from path
	permissionID := c.Param("id")
	if permissionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Permission ID is required"})
		return
	}

	// Parse request
	var req models.UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid update permission request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Build updates map (only description and active allowed)
	updates := make(map[string]interface{})
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Active != nil {
		updates["active"] = *req.Active
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid fields to update"})
		return
	}

	// Update permission
	err := h.permissionService.UpdatePermission(permissionID, updates)
	if err != nil {
		logger.Error("Failed to update permission",
			zap.String("permission_id", permissionID),
			zap.Error(err),
		)
		if err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update permission"})
		}
		return
	}

	logger.Info("Permission updated successfully", zap.String("permission_id", permissionID))
	c.JSON(http.StatusOK, gin.H{"message": "Permission updated successfully"})
}

// DeletePermission handles deleting a permission (DELETE /api/permissions/:id)
// Requires permissions:write permission
// Only allows deletion if permission is not assigned to any groups
func (h *PermissionHandler) DeletePermission(c *gin.Context) {
	logger.Info("Delete permission endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "permissions:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Get permission ID from path
	permissionID := c.Param("id")
	if permissionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Permission ID is required"})
		return
	}

	// Delete permission (service layer checks if in use)
	err := h.permissionService.DeletePermission(permissionID)
	if err != nil {
		logger.Error("Failed to delete permission",
			zap.String("permission_id", permissionID),
			zap.Error(err),
		)
		if err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Permission not found"})
		} else if strings.Contains(err.Error(), "in use") || strings.Contains(err.Error(), "assigned to") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete permission"})
		}
		return
	}

	logger.Info("Permission deleted successfully", zap.String("permission_id", permissionID))
	c.JSON(http.StatusNoContent, nil)
}
