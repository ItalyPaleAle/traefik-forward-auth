package server

import (
	"bytes"
	"errors"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"regexp"
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

// TestIsValidHostHeaderMatchesRegexp checks that isValidHostHeader accepts exactly the same values as the regular expression it replaced, which is kept here as the reference implementation
func TestIsValidHostHeaderMatchesRegexp(t *testing.T) {
	reference := regexp.MustCompile(`^(?:[\w-]+|(?:[\w\-]+\.)+\w+|\[[0-9\:]+\])(?::\d+)?$`)

	check := func(t *testing.T, v string) {
		t.Helper()
		assert.Equalf(t, reference.MatchString(v), isValidHostHeader(v), "mismatch for %q", v)
	}

	t.Run("representative values", func(t *testing.T) {
		//nolint:gosmopolitan
		values := []string{
			"", ".", "..", "-", "_", ":", "::",
			"example", "example.com", "sub.example.com", "a.b.c.d",
			"my-host", "my-host.example.com", "example.my-tld",
			"host_name", "host_name.example.com",
			"EXAMPLE.COM", "Example.Com",
			"123", "1.2.3.4", "192.168.0.1:8080",
			"example.com:443", "example.com:0", "example.com:",
			"example.com:abc", "example.com:80:80", "example.com::80",
			":8080", "example.com.", ".example.com", "example..com",
			"[::1]", "[::1]:8080", "[2001:db8::1]", "[2001:db8::1]:443",
			"[]", "[]:80", "[::1", "::1]", "[::1]x", "[::1]:", "[::1]:abc",
			"[abcd::1]", "[::1]80", "[[::1]]",
			"bad host", "bad!host", "host/path", "host?q", "host#f",
			"exam\tple", "exam\nple", "example.com ", " example.com",
			"a-", "-a", "a.b-", "a.-b", "a-.b", "xn--e1afmkfd.xn--p1ai",
			"host.example.com:65535", "host.example.com:99999999",
			"日本.jp", "café.com",
		}
		for _, v := range values {
			check(t, v)
		}
	})

	t.Run("generated combinations", func(t *testing.T) {
		pieces := []string{"", "a", "-", "_", ".", "1", ":", "]", "[", "z9"}
		for _, a := range pieces {
			for _, b := range pieces {
				for _, c := range pieces {
					for _, d := range pieces {
						check(t, a+b+c+d)
					}
				}
			}
		}
	})

	t.Run("random values", func(t *testing.T) {
		// Fuzz testing
		const alphabet = "abz09-_.:[]! \t"
		buf := make([]byte, 12)
		for range 200_000 {
			n := rand.Intn(len(buf)) // #nosec G404 -- test code
			for i := range n {
				buf[i] = alphabet[rand.Intn(len(alphabet))] // #nosec G404 -- test code
			}
			check(t, string(buf[:n]))
		}
	})
}

func TestMiddlewareLoggerSkipsDisabledLevels(t *testing.T) {
	// A handler that returns 200 logs at INFO, so a logger set to WARN drops the line entirely
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	srv := &Server{log: log}

	router := gin.New()
	router.Use(srv.MiddlewareAddRequestState, srv.MiddlewareRequestId, srv.MiddlewareLogger(log))
	router.GET("/ok", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	router.GET("/bad", func(c *gin.Context) { c.String(http.StatusBadRequest, "bad") })

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ok", nil))
	assert.Empty(t, buf.String(), "a 200 should not be logged when the level is WARN")

	// A 4xx logs at WARN, so it still comes through
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/bad", nil))
	assert.Contains(t, buf.String(), "status=400")
}

func TestMiddlewareLoggerClientIP(t *testing.T) {
	newRouter := func(buf *bytes.Buffer, withProxyHeaders bool) *gin.Engine {
		log := slog.New(slog.NewTextHandler(buf, nil))
		srv := &Server{log: log}

		router := gin.New()
		router.Use(srv.MiddlewareAddRequestState, srv.MiddlewareRequestId, srv.MiddlewareLogger(log))
		if withProxyHeaders {
			router.Use(srv.MiddlewareProxyHeaders)
		}
		router.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

		return router
	}

	t.Run("uses the IP MiddlewareProxyHeaders extracted", func(t *testing.T) {
		buf := &bytes.Buffer{}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set(headerXForwardedFor, "203.0.113.10, 10.0.0.1")
		req.Header.Set(headerXForwardedPort, "443")
		req.Header.Set(headerXForwardedProto, "https")
		req.Header.Set(headerXForwardedHost, "example.com")

		newRouter(buf, true).ServeHTTP(httptest.NewRecorder(), req)

		assert.Contains(t, buf.String(), "client=203.0.113.10")
	})

	t.Run("falls back to Gin on routes without the proxy headers middleware", func(t *testing.T) {
		buf := &bytes.Buffer{}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "198.51.100.7:1234"

		newRouter(buf, false).ServeHTTP(httptest.NewRecorder(), req)

		assert.Contains(t, buf.String(), "client=198.51.100.7")
	})
}
