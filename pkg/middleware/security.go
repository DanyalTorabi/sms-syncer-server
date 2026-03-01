package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sms-sync-server/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SecurityHeadersMiddleware adds security-related headers to the response
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	}
}

// HTTPSRedirectMiddleware redirects non-HTTPS requests to HTTPS.
func HTTPSRedirectMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if requestIsHTTPS(c.Request) {
			c.Next()
			return
		}

		targetURL := "https://" + c.Request.Host + c.Request.URL.RequestURI()
		c.Redirect(http.StatusPermanentRedirect, targetURL)
		c.Abort()
	}
}

func requestIsHTTPS(req *http.Request) bool {
	if req.TLS != nil {
		return true
	}

	forwardedProto := req.Header.Get("X-Forwarded-Proto")
	return strings.EqualFold(forwardedProto, "https")
}

// Default CORS configuration
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware adds a unique ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-ID")
		if rid == "" {
			rid = generateRequestID()
		}
		c.Set("RequestID", rid)
		c.Header("X-Request-ID", rid)
		c.Next()
	}
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp if random fails (unlikely)
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// RequestSizeLimitMiddleware limits the size of the request body
func RequestSizeLimitMiddleware(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// AuditLogMiddleware logs request details for security auditing
func AuditLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		rid, _ := c.Get("RequestID")
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		latency := time.Since(start)

		if raw != "" {
			path = path + "?" + raw
		}

		logger.Info("Audit Log",
			zap.String("request_id", fmt.Sprintf("%v", rid)),
			zap.String("client_ip", clientIP),
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Duration("latency", latency),
		)
	}
}
