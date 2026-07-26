package server

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
			headerXForwardedServer: "traefik@docker",
			headerXForwardedFor:    "203.0.113.10, 10.0.0.1",
			headerXForwardedPort:   "443",
			headerXForwardedProto:  "https",
			headerXForwardedHost:   "example.com",
		})

		s.MiddlewareProxyHeaders(c)
		assert.False(t, c.IsAborted())
	})

	t.Run("missing header aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			headerXForwardedServer: "traefik@docker",
			headerXForwardedFor:    "203.0.113.10",
			headerXForwardedPort:   "443",
			headerXForwardedProto:  "https",
			// Missing X-Forwarded-Host
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid proto aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			headerXForwardedServer: "traefik@docker",
			headerXForwardedFor:    "203.0.113.10",
			headerXForwardedPort:   "443",
			headerXForwardedProto:  "ftp", // invalid
			headerXForwardedHost:   "example.com",
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid host aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			headerXForwardedServer: "traefik@docker",
			headerXForwardedFor:    "203.0.113.10",
			headerXForwardedPort:   "443",
			headerXForwardedProto:  "https",
			headerXForwardedHost:   "bad host!", // invalid format
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid address aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			headerXForwardedServer: "traefik@docker",
			headerXForwardedFor:    "not-an-ip",
			headerXForwardedPort:   "443",
			headerXForwardedProto:  "https",
			headerXForwardedHost:   "example.com",
		})

		s.MiddlewareProxyHeaders(c)
		assert.True(t, c.IsAborted())
	})

	t.Run("invalid port aborts", func(t *testing.T) {
		c, _ := newCtx(map[string]string{
			headerXForwardedServer: "traefik@docker",
			headerXForwardedFor:    "203.0.113.10",
			headerXForwardedPort:   "eighty",
			headerXForwardedProto:  "https",
			headerXForwardedHost:   "example.com",
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

		// The middleware stores the request ID in the request state, which the router attaches before it runs
		s.MiddlewareAddRequestState(c)

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
		assert.Equal(t, "custom-id-123", getRequestState(c).requestID)
	})

	t.Run("generates UUID if trusted header missing", func(t *testing.T) {
		conf.Server.TrustedRequestIdHeader = "X-Request-Id"
		c, rec := newCtx(nil)

		s.MiddlewareRequestId(c)

		v := rec.Header().Get("x-request-id")
		require.NotEmpty(t, v)
		_, err := uuid.Parse(v)
		require.NoError(t, err, "generated request id should be a valid uuid")
		assert.Equal(t, v, getRequestState(c).requestID)
	})

	t.Run("generates UUID if no trusted header configured", func(t *testing.T) {
		conf.Server.TrustedRequestIdHeader = ""
		c, rec := newCtx(nil)

		s.MiddlewareRequestId(c)

		v := rec.Header().Get("x-request-id")
		require.NotEmpty(t, v)
		_, err := uuid.Parse(v)
		require.NoError(t, err)
		assert.Equal(t, v, getRequestState(c).requestID)
	})
}

func TestMiddlewareLogger(t *testing.T) {
	newLoggedRequest := func(t *testing.T, handler gin.HandlerFunc) string {
		t.Helper()

		buf := &bytes.Buffer{}
		log := slog.New(slog.NewTextHandler(buf, nil))

		srv := &Server{log: log}
		router := gin.New()
		router.Use(srv.MiddlewareAddRequestState, srv.MiddlewareRequestId, srv.MiddlewareLogger(log))
		router.GET("/test", handler)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))

		return buf.String()
	}

	t.Run("includes the request ID and the request attributes", func(t *testing.T) {
		out := newLoggedRequest(t, func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		assert.Contains(t, out, `msg="HTTP Request"`)
		assert.Contains(t, out, "id=")
		assert.Contains(t, out, "status=200")
		assert.Contains(t, out, "method=GET")
		assert.Contains(t, out, "path=/test")
	})

	t.Run("includes the error and marks the request as failed", func(t *testing.T) {
		out := newLoggedRequest(t, func(c *gin.Context) {
			_ = c.Error(errors.New("something broke"))
			c.String(http.StatusInternalServerError, "error")
		})

		assert.Contains(t, out, `msg="Failed request"`)
		assert.Contains(t, out, "id=")
		assert.Contains(t, out, `error="something broke"`)
		assert.Contains(t, out, "status=500")
	})

	t.Run("handlers can log with the request ID", func(t *testing.T) {
		var handlerRequestID string
		out := newLoggedRequest(t, func(c *gin.Context) {
			handlerRequestID = getRequestState(c).requestID
			c.String(http.StatusOK, "ok")
		})

		require.NotEmpty(t, handlerRequestID)
		// The request log line carries the same ID the handler saw
		assert.Contains(t, out, "id="+handlerRequestID)
	})

	t.Run("requestLogger tags the handler's own log lines with the request ID", func(t *testing.T) {
		buf := &bytes.Buffer{}
		log := slog.New(slog.NewTextHandler(buf, nil))
		srv := &Server{log: log}

		router := gin.New()
		router.Use(srv.MiddlewareAddRequestState, srv.MiddlewareRequestId, srv.MiddlewareLogger(log))
		router.GET("/test", func(c *gin.Context) {
			srv.requestLogger(c).InfoContext(c.Request.Context(), "from the handler")
			c.String(http.StatusOK, "ok")
		})
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))

		out := buf.String()
		assert.Contains(t, out, "from the handler")
		// The handler's line and the request line both carry an ID
		assert.GreaterOrEqual(t, strings.Count(out, "id="), 2)
	})
}

func TestGetPortal(t *testing.T) {
	newContextForPortal := func(portalName string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Params = gin.Params{{Key: "portal", Value: portalName}}

		// getPortal keeps the resolved portal in the request state, which the router attaches before any route runs
		(&Server{}).MiddlewareAddRequestState(c)

		return c
	}

	t.Run("resolves the portal from the route parameter", func(t *testing.T) {
		srv := &Server{portals: map[string]*Portal{"test1": {Name: "test1"}}}

		portal, err := srv.getPortal(newContextForPortal("test1"))
		require.NoError(t, err)
		require.NotNil(t, portal)
		assert.Equal(t, "test1", portal.Name)
	})

	t.Run("returns an error for an unknown portal", func(t *testing.T) {
		srv := &Server{portals: map[string]*Portal{"test1": {Name: "test1"}}}

		_, err := srv.getPortal(newContextForPortal("nope"))
		require.Error(t, err)
	})

	t.Run("resolves only once per request", func(t *testing.T) {
		srv := &Server{portals: map[string]*Portal{"test1": {Name: "test1"}}}
		c := newContextForPortal("test1")

		first, err := srv.getPortal(c)
		require.NoError(t, err)
		require.NotNil(t, first)

		// Removing the portal proves the second call did not look it up again
		delete(srv.portals, "test1")

		second, err := srv.getPortal(c)
		require.NoError(t, err)
		assert.Same(t, first, second)

		// A new request resolves from scratch, and now finds nothing
		_, err = srv.getPortal(newContextForPortal("test1"))
		require.Error(t, err)
	})
}
