package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

var proxyHeaders = []string{
	"X-Forwarded-Server",
	"X-Forwarded-For",
	"X-Forwarded-Port",
	"X-Forwarded-Host",
}

// MiddlewareRequireClientCertificate is a middleware that requires a valid client certificate to be present.
// This is meant to be used to enforce mTLS on specific routes, when the server's TLS is configured with VerifyClientCertIfGiven.
func (s *Server) MiddlewareRequireClientCertificate(c *gin.Context) {
	if c.Request.TLS == nil || !config.Get().TLSClientAuth {
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
	xForwardedFor := c.Request.Header.Get("X-Forwarded-For")
	xForwardedPort := c.Request.Header.Get("X-Forwarded-Port")

	// Split the X-Forwarded-For header to get the originating client IP
	clientIP, _, _ := strings.Cut(xForwardedFor, ",")
	clientIP = strings.TrimSpace(clientIP)

	// Get and validate the remote address
	_, err := netip.ParseAddrPort(net.JoinHostPort(clientIP, xForwardedPort))
	if err != nil {
		AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Invalid remote address and port: %v", err))
		return
	}
}

// MiddlewareLoadAuthCookie is a middleware that checks if the request contains a valid authentication token in the cookie.
func (s *Server) MiddlewareLoadAuthCookie(c *gin.Context) {
	// Get the cookie and parse it
	profile, err := s.getSessionCookie(c)
	if err != nil {
		s.deleteSessionCookie(c)
		AbortWithError(c, fmt.Errorf("cookie error: %w", err))
		return
	}

	// If we don't have a valid session, stop here
	if profile == nil || profile.ID == "" {
		return
	}

	// Validate the session claims
	err = s.auth.ValidateRequestClaims(c.Request, profile)
	if err != nil {
		// If the claims are invalid for this session, delete the cookie and return a hard error
		s.deleteSessionCookie(c)
		AbortWithError(c, NewResponseErrorf(http.StatusUnauthorized, "Claims are invalid for the request: %v", err))
		return
	}

	// Check if the user is allowed per rules (again)
	err = s.auth.UserAllowed(profile)
	if err != nil {
		// If the user is not allowed, delete the cookie and return a hard error
		s.deleteSessionCookie(c)
		_ = c.Error(fmt.Errorf("access denied per allowlist rules: %w", err))
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Access denied per allowlist rules"))
		return
	}

	// Set the claims in the context
	c.Set("session-auth", true)
	c.Set("session-profile", profile)
}

// MiddlewareRequestId is a middleware that generates a unique request ID for each request
func (s *Server) MiddlewareRequestId(c *gin.Context) {
	// Check if we have a trusted request ID header and it has a value
	headerName := config.Get().TrustedRequestIdHeader
	if headerName != "" {
		v := c.GetHeader(headerName)
		if v != "" {
			c.Set("request-id", v)
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
	c.Set("request-id", v)
	c.Header("x-request-id", v)
}

// MiddlewareLogger is a Gin middleware that uses zerlog for logging
func (s *Server) MiddlewareLogger(parentLog *zerolog.Logger) func(c *gin.Context) {
	return func(c *gin.Context) {
		method := c.Request.Method

		// Ensure the logger in the context has a request ID, then store it in the context
		reqId := c.GetString("request-id")
		log := parentLog.With().
			Str("reqId", reqId).
			Logger()
		c.Request = c.Request.WithContext(log.WithContext(c.Request.Context()))

		// Do not log OPTIONS requests
		if method == http.MethodOptions {
			return
		}

		// Omit logging /healthz calls if set
		if c.Request.URL.Path == "/healthz" && config.Get().OmitHealthCheckLogs {
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
		traefik := c.Request.Header.Get("X-Forwarded-Server")
		duration := time.Since(start)
		clientIP := c.ClientIP()
		statusCode := c.Writer.Status()
		respSize := c.Writer.Size()
		if respSize < 0 {
			// If no data was written, respSize could be -1
			respSize = 0
		}

		// Get the logger and the appropriate error level
		var event *zerolog.Event
		switch {
		case statusCode >= 200 && statusCode <= 399:
			event = log.Info() //nolint:zerologlint
		case statusCode >= 400 && statusCode <= 499:
			event = log.Warn() //nolint:zerologlint
		default:
			event = log.Error() //nolint:zerologlint
		}

		// Check if we have an error
		if lastErr := c.Errors.Last(); lastErr != nil {
			// We'll pick the last error only
			event = event.Err(lastErr.Err)
		}

		// Check if we have a message
		msg := c.GetString("log-message")

		// Check if we want to mask something in the URL
		mask, ok := c.Get("log-mask")
		if ok {
			f, ok := mask.(func(string) string)
			if ok && f != nil {
				path = f(path)
			}
		}

		// Set parameters
		event.
			Int("status", statusCode).
			Str("method", method).
			Str("path", path).
			Str("clientIp", clientIP).
			Dur("duration", duration).
			Int("respSize", respSize).
			Str("traefik", traefik).
			Msg(msg)
	}
}

// MiddlewareLoggerMask returns a Gin middleware that adds the "log-mask" to mask the path using a regular expression
func (s *Server) MiddlewareLoggerMask(exp *regexp.Regexp, replace string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("log-mask", func(path string) string {
			return exp.ReplaceAllString(path, replace)
		})
	}
}
