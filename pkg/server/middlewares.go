package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

const (
	sessionAuthContextKey     = "session-auth"
	sessionProfileContextKey  = "session-profile"
	sessionProviderContextKey = "session-provider"
	requestIDContextKey       = "request-id"
	logMaskContextKey         = "log-mask"
	logMessageContextKey      = "log-message"
)

var proxyHeaders = []string{
	headerXForwardedFor,
	headerXForwardedPort,
	headerXForwardedProto,
	headerXForwardedHost,
}

var hostHeaderRe regexp.Regexp = *regexp.MustCompile(`^(?:[\w-]+|(?:[\w\-]+\.)+\w+|\[[0-9\:]+\])(?::\d+)?$`)

// MiddlewareRequireClientCertificate is a middleware that requires a valid client certificate to be present.
// This is meant to be used to enforce mTLS on specific routes, when the server's TLS is configured with VerifyClientCertIfGiven.
func (s *Server) MiddlewareRequireClientCertificate(c *gin.Context) {
	if c.Request.TLS == nil || !config.Get().Server.TLSClientAuth {
		// Do nothing if `tlsClientAuth` is disabled or if the server is running without TLS
		return
	}

	// Check if the client provided a valid TLS certificate
	if len(c.Request.TLS.PeerCertificates) == 0 {
		AbortWithError(c, NewResponseErrorf(http.StatusUnauthorized, "Client certificate not provided"))
		return
	}
}

// MiddlewareProxyHeaders is a middleware that gets values for source IP and port from the headers set by Traefik.
// It stops the request if the headers aren't set.
// This middleware should be used first in the chain.
func (s *Server) MiddlewareProxyHeaders(c *gin.Context) {
	// Ensure required headers are present
	for _, header := range proxyHeaders {
		if c.Request.Header.Get(header) == "" {
			AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Missing header %s", header))
			return
		}
	}

	// Get the X-Forwarded-For header
	xForwardedFor := c.Request.Header.Get(headerXForwardedFor)
	xForwardedPort := c.Request.Header.Get(headerXForwardedPort)

	// Split the X-Forwarded-For header to get the originating client IP
	clientIP, _, _ := strings.Cut(xForwardedFor, ",")
	clientIP = strings.TrimSpace(clientIP)

	// Get and validate the remote address
	_, err := netip.ParseAddrPort(net.JoinHostPort(clientIP, xForwardedPort))
	if err != nil {
		AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Invalid remote address and port: %v", err))
		return
	}

	// Validate X-Forwarded-Proto
	switch c.Request.Header.Get(headerXForwardedProto) {
	case "http", "https", "ws", "wss":
		// All good
	default:
		AbortWithError(c, NewResponseError(http.StatusBadRequest, "Invalid value for the 'X-Forwarded-Proto' header: must be 'http', 'https', 'ws', or 'wss'"))
		return
	}

	// Validate X-Forwarded-Host
	if !hostHeaderRe.MatchString(c.Request.Header.Get(headerXForwardedHost)) {
		AbortWithError(c, NewResponseError(http.StatusBadRequest, "Invalid value for the 'X-Forwarded-Host' header"))
		return
	}
}

// MiddlewareLoadAuthCookie is a middleware that checks if the request contains a valid authentication token in the cookie.
func (s *Server) MiddlewareLoadAuthCookie(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Get the cookie and parse it
	profile, provider, err := s.getSessionCookie(c, portal.Name)
	if err != nil {
		s.deleteSessionCookie(c, portal.Name)
		AbortWithError(c, NewInvalidTokenErrorf("Session cookie is invalid: %v", err))
		return
	}

	// If we don't have a valid session, stop here
	if profile == nil || profile.ID == "" || provider == nil {
		return
	}

	// Validate the session claims
	err = provider.ValidateRequestClaims(c.Request, profile)
	if err != nil {
		// If the claims are invalid for this session, delete the cookie and return a hard error
		s.deleteSessionCookie(c, portal.Name)
		AbortWithError(c, NewResponseErrorf(http.StatusUnauthorized, "Claims are invalid for the request: %v", err))
		return
	}

	// Set the claims in the context
	c.Set(sessionAuthContextKey, true)
	c.Set(sessionProfileContextKey, profile)
	c.Set(sessionProviderContextKey, provider)
}

// MiddlewareRequestId is a middleware that generates a unique request ID for each request
func (s *Server) MiddlewareRequestId(c *gin.Context) {
	// Check if we have a trusted request ID header and it has a value
	headerName := config.Get().Server.TrustedRequestIdHeader
	if headerName != "" {
		v := c.GetHeader(headerName)
		if v != "" {
			c.Set(requestIDContextKey, v)
			c.Header("x-request-id", v)
			return
		}
	}

	// If we get here, we have no request ID found in headers, so let's generate a new UUID
	reqUuid, err := uuid.NewRandom()
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to generate request ID UUID: %w", err))
		return
	}

	v := reqUuid.String()
	c.Set(requestIDContextKey, v)
	c.Header("x-request-id", v)
}

// MiddlewareCountMetrics is a Gin middleware that records requests served by the server
func (s *Server) MiddlewareCountMetrics(c *gin.Context) {
	if s.metrics == nil {
		// Process the request and do nothing
		c.Next()
		return
	}

	// Route name is "<method> <path>", where "path" is the path defined in the router
	route := c.Request.Method + " " + c.FullPath()
	start := time.Now()

	// Process the route
	c.Next()

	// Emit the metric
	s.metrics.RecordServerRequest(route, c.Writer.Status(), time.Since(start))
}

// MiddlewareLogger is a Gin middleware that uses zerlog for logging
func (s *Server) MiddlewareLogger(parentLog *slog.Logger) func(c *gin.Context) {
	healthCheckLogs := config.Get().Logs.OmitHealthChecks

	return func(c *gin.Context) {
		method := c.Request.Method

		// Ensure the logger in the context has a request ID, then store it in the context
		reqId := c.GetString(requestIDContextKey)
		log := parentLog.With(slog.String("id", reqId))
		c.Request = c.Request.WithContext(utils.LogToContext(c.Request.Context(), log))

		// Do not log OPTIONS requests
		if method == http.MethodOptions {
			return
		}

		// Omit logging /healthz calls if set
		if c.Request.URL.Path == "/healthz" && healthCheckLogs {
			return
		}

		// Start time to measure latency (request duration)
		start := time.Now()
		path := c.Request.URL.Path
		if c.Request.URL.RawQuery != "" {
			path = path + "?" + c.Request.URL.RawQuery
		}

		// Process request
		c.Next()

		// Other fields to include
		duration := time.Since(start)
		clientIP := c.ClientIP()
		statusCode := c.Writer.Status()
		respSize := c.Writer.Size()
		if respSize < 0 {
			// If no data was written, respSize could be -1
			respSize = 0
		}

		// May be present
		traefik := c.Request.Header.Get(headerXForwardedServer)

		// Get the logger and the appropriate error level
		var level slog.Level
		switch {
		case statusCode >= 200 && statusCode <= 399:
			level = slog.LevelInfo
		case statusCode >= 400 && statusCode <= 499:
			level = slog.LevelWarn
		default:
			level = slog.LevelError
		}

		// Check if we have a message
		msg := c.GetString(logMessageContextKey)
		if msg == "" {
			msg = "HTTP Request"
		}

		// Check if we have an error
		lastErr := c.Errors.Last()
		if lastErr != nil {
			// We'll pick the last error only
			log = log.With(slog.Any("error", lastErr.Err))

			// Set the message as request failed
			msg = "Failed request"
		}

		// Check if we want to mask something in the URL
		mask, ok := c.Get(logMaskContextKey)
		if ok {
			f, ok := mask.(func(string) string)
			if ok && f != nil {
				path = f(path)
			}
		}

		attrs := make([]slog.Attr, 0, 7)
		attrs = append(attrs,
			slog.Int("status", statusCode),
			slog.String("method", method),
			slog.String("path", path),
			slog.String("client", clientIP),
			slog.Float64("duration", float64(duration.Microseconds())/1000),
			slog.Int("respSize", respSize),
		)
		if traefik != "" {
			attrs = append(attrs, slog.String("traefik", traefik))
		}

		// Emit the log
		log.LogAttrs(c.Request.Context(), level, msg, attrs...)
	}
}

// MiddlewareLoggerMask returns a Gin middleware that adds the logMaskContextKey to mask the path using a regular expression
func (s *Server) MiddlewareLoggerMask(exp *regexp.Regexp, replace string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(logMaskContextKey, func(path string) string {
			return exp.ReplaceAllString(path, replace)
		})
	}
}

func (s *Server) getPortal(c *gin.Context) (Portal, error) {
	cfg := config.Get()

	portalName := strings.ToLower(c.Param("portal"))
	if portalName == "" && cfg.DefaultPortal != "" {
		portalName = cfg.DefaultPortal
	}

	portal, ok := s.portals[portalName]
	if !ok {
		return Portal{}, NewResponseError(http.StatusNotFound, "Portal not found")
	}

	return portal, nil
}

func (s *Server) getProvider(c *gin.Context) (Portal, auth.Provider, error) {
	portal, err := s.getPortal(c)
	if err != nil {
		return Portal{}, nil, err
	}

	providerName := strings.ToLower(c.Param("provider"))
	provider, ok := portal.Providers[providerName]
	if !ok {
		return Portal{}, nil, NewResponseError(http.StatusNotFound, "Provider not found")
	}

	return portal, provider, nil
}
