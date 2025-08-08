package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

func TestMiddlewareProxyHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{}

	newCtx := func(headers map[string]string) (*gin.Context, *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		c.Request = req
		return c, rec
	}

	t.Run("valid headers pass", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			"X-Forwarded-Server": "traefik@docker",
			"X-Forwarded-For":    "203.0.113.10, 10.0.0.1",
			"X-Forwarded-Port":   "443",
			"X-Forwarded-Proto":  "https",
			"X-Forwarded-Host":   "example.com",
		})

		s.MiddlewareProxyHeaders(c)
		assert.False(t, c.IsAborted())
	})

	t.Run("missing header aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			"X-Forwarded-Server": "traefik@docker",
			"X-Forwarded-For":    "203.0.113.10",
			"X-Forwarded-Port":   "443",
			"X-Forwarded-Proto":  "https",
			// Missing X-Forwarded-Host
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid proto aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			"X-Forwarded-Server": "traefik@docker",
			"X-Forwarded-For":    "203.0.113.10",
			"X-Forwarded-Port":   "443",
			"X-Forwarded-Proto":  "ftp", // invalid
			"X-Forwarded-Host":   "example.com",
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid host aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			"X-Forwarded-Server": "traefik@docker",
			"X-Forwarded-For":    "203.0.113.10",
			"X-Forwarded-Port":   "443",
			"X-Forwarded-Proto":  "https",
			"X-Forwarded-Host":   "bad host!", // invalid format
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid address aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			"X-Forwarded-Server": "traefik@docker",
			"X-Forwarded-For":    "not-an-ip",
			"X-Forwarded-Port":   "443",
			"X-Forwarded-Proto":  "https",
			"X-Forwarded-Host":   "example.com",
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid port aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			"X-Forwarded-Server": "traefik@docker",
			"X-Forwarded-For":    "203.0.113.10",
			"X-Forwarded-Port":   "eighty",
			"X-Forwarded-Proto":  "https",
			"X-Forwarded-Host":   "example.com",
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})
}

func TestMiddlewareRequestId(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{}
	conf := config.Get()

	newCtx := func(headers map[string]string) (*gin.Context, *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		c.Request = req
		return c, rec
	}

	prevTrusted := conf.Server.TrustedRequestIdHeader
	t.Cleanup(func() {
		conf.Server.TrustedRequestIdHeader = prevTrusted
	})

	t.Run("uses trusted header if present", func(t *testing.T) {
		conf.Server.TrustedRequestIdHeader = "X-Request-Id"
		c, rec := newCtx(map[string]string{
			"X-Request-Id": "custom-id-123",
		})

		s.MiddlewareRequestId(c)

		// Should echo the same ID and set it in context
		assert.Equal(t, "custom-id-123", rec.Header().Get("x-request-id"))
		assert.Equal(t, "custom-id-123", c.GetString(requestIDContextKey))
	})

	t.Run("generates UUID if trusted header missing", func(t *testing.T) {
		conf.Server.TrustedRequestIdHeader = "X-Request-Id"
		c, rec := newCtx(nil)

		s.MiddlewareRequestId(c)

		v := rec.Header().Get("x-request-id")
		require.NotEmpty(t, v)
		_, err := uuid.Parse(v)
		require.NoError(t, err, "generated request id should be a valid uuid")
		assert.Equal(t, v, c.GetString(requestIDContextKey))
	})

	t.Run("generates UUID if no trusted header configured", func(t *testing.T) {
		conf.Server.TrustedRequestIdHeader = ""
		c, rec := newCtx(nil)

		s.MiddlewareRequestId(c)

		v := rec.Header().Get("x-request-id")
		require.NotEmpty(t, v)
		_, err := uuid.Parse(v)
		require.NoError(t, err)
		assert.Equal(t, v, c.GetString(requestIDContextKey))
	})
}
