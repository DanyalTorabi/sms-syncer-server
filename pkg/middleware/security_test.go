package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHTTPSRedirectMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("redirects non-https request", func(t *testing.T) {
		router := gin.New()
		router.Use(HTTPSRedirectMiddleware())
		router.GET("/health", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusPermanentRedirect, w.Code)
		assert.Equal(t, "https://example.com/health", w.Header().Get("Location"))
	})

	t.Run("allows request when forwarded proto is https", func(t *testing.T) {
		router := gin.New()
		router.Use(HTTPSRedirectMiddleware())
		router.GET("/health", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
