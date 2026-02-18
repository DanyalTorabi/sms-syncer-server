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

// GroupHandler handles group management requests
type GroupHandler struct {
	groupService GroupServiceInterface
}

// NewGroupHandler creates a new group handler
func NewGroupHandler(groupService GroupServiceInterface) *GroupHandler {
	return &GroupHandler{
		groupService: groupService,
	}
}

// CreateGroup handles creating a new group (POST /api/groups)
// Requires groups:write permission
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	logger.Info("Create group endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "groups:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Parse request
	var req models.CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid create group request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Create group
	group, err := h.groupService.CreateGroup(req.Name, req.Description)
	if err != nil {
		logger.Error("Failed to create group",
			zap.String("name", req.Name),
			zap.Error(err),
		)
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}

	logger.Info("Group created successfully", zap.String("group_id", group.ID))
	c.JSON(http.StatusCreated, group)
}

// ListGroups handles listing all groups with pagination (GET /api/groups)
// Requires groups:read permission
func (h *GroupHandler) ListGroups(c *gin.Context) {
	logger.Info("List groups endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "groups:read") {
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

	// Get groups
	groups, err := h.groupService.ListGroups(limit, offset)
	if err != nil {
		logger.Error("Failed to list groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list groups"})
		return
	}

	logger.Info("Groups retrieved successfully", zap.Int("count", len(groups)))
	c.JSON(http.StatusOK, gin.H{
		"groups": groups,
		"limit":  limit,
		"offset": offset,
	})
}

// GetGroupByID handles retrieving a group by ID (GET /api/groups/:id)
// Requires groups:read permission
func (h *GroupHandler) GetGroupByID(c *gin.Context) {
	logger.Info("Get group by ID endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "groups:read") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Get group ID from path
	groupID := c.Param("id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group ID is required"})
		return
	}

	// Get group
	group, err := h.groupService.GetGroup(groupID)
	if err != nil {
		logger.Warn("Failed to retrieve group",
			zap.String("group_id", groupID),
			zap.Error(err),
		)
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve group"})
		}
		return
	}

	logger.Info("Group retrieved successfully", zap.String("group_id", groupID))
	c.JSON(http.StatusOK, group)
}

// UpdateGroup handles updating a group (PUT /api/groups/:id)
// Requires groups:write permission
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	logger.Info("Update group endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "groups:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Get group ID from path
	groupID := c.Param("id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group ID is required"})
		return
	}

	// Parse request
	var req models.UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Warn("Invalid update group request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Build updates map
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
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

	// Update group
	err := h.groupService.UpdateGroup(groupID, updates)
	if err != nil {
		logger.Error("Failed to update group",
			zap.String("group_id", groupID),
			zap.Error(err),
		)
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		} else if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update group"})
		}
		return
	}

	logger.Info("Group updated successfully", zap.String("group_id", groupID))
	c.JSON(http.StatusOK, gin.H{"message": "Group updated successfully"})
}

// DeleteGroup handles deleting a group (DELETE /api/groups/:id)
// Requires groups:write permission
// Protects the admin group from deletion
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	logger.Info("Delete group endpoint called")

	// Check permissions
	permissions, _ := c.Get("permissions")
	permList, _ := permissions.([]string)
	if !hasPermission(permList, "groups:write") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Get group ID from path
	groupID := c.Param("id")
	if groupID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group ID is required"})
		return
	}

	// Delete group (service layer handles admin protection)
	err := h.groupService.DeleteGroup(groupID)
	if err != nil {
		logger.Error("Failed to delete group",
			zap.String("group_id", groupID),
			zap.Error(err),
		)
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		} else if strings.Contains(err.Error(), "admin group") || strings.Contains(err.Error(), "cannot be deleted") {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete group"})
		}
		return
	}

	logger.Info("Group deleted successfully", zap.String("group_id", groupID))
	c.JSON(http.StatusNoContent, nil)
}
