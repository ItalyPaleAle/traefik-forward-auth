package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

// isValidHostHeader reports whether v is an acceptable value for the X-Forwarded-Host header.
// It accepts a hostname made of dot-separated labels, or an IPv6 address in square brackets, each optionally followed by ":<port>".
//
// This is equivalent to matching against `^(?:[\w-]+|(?:[\w\-]+\.)+\w+|\[[0-9\:]+\])(?::\d+)?$`, which was previously used for the matcher but was too costly in the hot path
func isValidHostHeader(v string) bool {
	if v == "" {
		return false
	}

	// Split off the optional ":<port>" suffix
	// A bracketed IPv6 address contains colons of its own, so for those the port can only start after the closing bracket
	var host, port string
	hasPort := false
	switch v[0] {
	case '[':
		end := strings.IndexByte(v, ']')
		if end < 0 {
			return false
		}
		host, port = v[:end+1], v[end+1:]
		if port != "" {
			if port[0] != ':' {
				return false
			}
			port = port[1:]
			hasPort = true
		}
	default:
		before, after, ok := strings.Cut(v, ":")
		if ok {
			host = before
			port = after
			hasPort = true
		} else {
			host = v
		}
	}

	// The port must be one or more digits
	if hasPort {
		if port == "" {
			return false
		}
		for i := range len(port) {
			if port[i] < '0' || port[i] > '9' {
				return false
			}
		}
	}

	// A value that is nothing but a port, such as ":8080", has no host to validate
	if host == "" {
		return false
	}

	// Bracketed IPv6 address: "[" one or more digits and colons "]"
	if host[0] == '[' {
		inner := host[1 : len(host)-1]
		if inner == "" {
			return false
		}
		for i := range len(inner) {
			if (inner[i] < '0' || inner[i] > '9') && inner[i] != ':' {
				return false
			}
		}
		return true
	}

	// Hostname: dot-separated labels of word characters, where every label but the last may also contain hyphens
	// A hostname with a single label (no dots) may contain hyphens too, matching the first branch of the regular expression
	start := 0
	for i := 0; i <= len(host); i++ {
		if i < len(host) && host[i] != '.' {
			continue
		}

		label := host[start:i]
		if label == "" {
			return false
		}

		// Hyphens are allowed in every label except the last one of a multi-label hostname
		allowHyphen := i < len(host) || start == 0
		for j := range len(label) {
			c := label[j]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
				// Word character, always allowed
			case c == '-' && allowHyphen:
				// Allowed in this position
			default:
				return false
			}
		}

		start = i + 1
	}

	return true
}

// MiddlewareAddRequestState is a middleware that attaches a requestState to the request's context.
// It must run before any other middleware or handler that reads or writes that state.
func (s *Server) MiddlewareAddRequestState(c *gin.Context) {
	rs := &requestState{}
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), requestStateKey{}, rs))
}

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
	// Read each header we need once, rather than once to check it's present and again to use its value
	h := c.Request.Header
	xForwardedFor := headerValue(h, headerXForwardedFor)
	xForwardedPort := headerValue(h, headerXForwardedPort)
	xForwardedProto := headerValue(h, headerXForwardedProto)
	xForwardedHost := headerValue(h, headerXForwardedHost)

	// Ensure required headers are present
	var missing string
	switch {
	case xForwardedFor == "":
		missing = headerXForwardedFor
	case xForwardedPort == "":
		missing = headerXForwardedPort
	case xForwardedProto == "":
		missing = headerXForwardedProto
	case xForwardedHost == "":
		missing = headerXForwardedHost
	}
	if missing != "" {
		AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Missing header %s", missing))
		return
	}

	// Get the X-Forwarded-For header and extract the originating client IP
	// X-Forwarded-For is conventionally a comma-separated chain "client, proxy1, ..."
	clientIP := utils.ClientIPFromXForwardedFor(xForwardedFor)

	// Get and validate the remote address
	// The address and port are validated separately because joining them into "host:port" just to have netip re-split it allocates on every request
	_, err := netip.ParseAddr(clientIP)
	if err != nil {
		AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Invalid remote address and port: %v", err))
		return
	}
	_, err = strconv.ParseUint(xForwardedPort, 10, 16)
	if err != nil {
		AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Invalid remote address and port: %v", err))
		return
	}

	// Validate X-Forwarded-Proto
	switch xForwardedProto {
	case "http", "https", "ws", "wss":
		// All good
	default:
		AbortWithError(c, NewResponseError(http.StatusBadRequest, "Invalid value for the 'X-Forwarded-Proto' header: must be 'http', 'https', 'ws', or 'wss'"))
		return
	}

	// Validate X-Forwarded-Host
	if !isValidHostHeader(xForwardedHost) {
		AbortWithError(c, NewResponseError(http.StatusBadRequest, "Invalid value for the 'X-Forwarded-Host' header"))
		return
	}

	// Keep the client IP for the request log line, so the logger doesn't parse X-Forwarded-For a second time
	rs := getRequestState(c)
	if rs != nil {
		rs.clientIP = clientIP
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
		// The session cookie is present but couldn't be validated (e.g. it's expired or tampered with)
		// We treat this the same as an unauthenticated request
		// We drop the bad cookie then continue, so that interactive routes redirect the user to sign in again instead of returning a 401 dead-end that breaks browser navigation (e.g. the back button)
		s.deleteSessionCookie(c, portal.Name)

		// Log a warning for cookies that look malformed or tampered with
		if invalidSessionCookieIsSuspicious(err) {
			log := s.requestLogger(c)
			log.WarnContext(c.Request.Context(),
				"Rejected a session cookie that failed validation; it may be malformed or tampered with",
				slog.Any("error", err),
			)
		}
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

	// Set the claims in the request state
	rs := getRequestState(c)
	if rs != nil {
		rs.authenticated = true
		rs.profile = profile
		rs.provider = provider
	}
}

// MiddlewareRequestId is a middleware that generates a unique request ID for each request
func (s *Server) MiddlewareRequestId(c *gin.Context) {
	rs := getRequestState(c)

	// Check if we have a trusted request ID header and it has a value
	headerName := config.Get().Server.TrustedRequestIdHeader
	if headerName != "" {
		v := c.GetHeader(headerName)
		if v != "" {
			if rs != nil {
				rs.requestID = v
			}
			setResponseHeader(c, headerXRequestID, v)
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
	if rs != nil {
		rs.requestID = v
	}
	setResponseHeader(c, headerXRequestID, v)
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

		rs := getRequestState(c)
		var reqId string
		if rs != nil {
			reqId = rs.requestID
		}

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
		// MiddlewareProxyHeaders already extracted the client IP from X-Forwarded-For for the routes that run it; fall back to Gin for the routes that don't (health checks, static assets, the API)
		clientIP := ""
		if rs != nil {
			clientIP = rs.clientIP
		}
		if clientIP == "" {
			clientIP = c.ClientIP()
		}
		statusCode := c.Writer.Status()
		// If no data was written, respSize could be -1
		respSize := max(c.Writer.Size(), 0)

		// May be present
		traefik := headerValue(c.Request.Header, headerXForwardedServer)

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

		// Nothing below is observable when the log line is going to be dropped, and building the attributes is a meaningful part of the cost of a request
		if !parentLog.Enabled(c.Request.Context(), level) {
			return
		}

		// Check if we have a message
		msg := "HTTP Request"
		if rs != nil && rs.logMessage != "" {
			msg = rs.logMessage
		}

		// Check if we have an error
		lastErr := c.Errors.Last()
		if lastErr != nil {
			// Set the message as request failed
			msg = "Failed request"
		}

		// Check if we want to mask something in the URL
		if rs != nil && rs.logMask != nil {
			path = rs.logMask(path)
		}

		// The request ID and the error are passed as attributes rather than derived onto the logger
		attrs := make([]slog.Attr, 0, 9)
		attrs = append(attrs, slog.String("id", reqId))
		if lastErr != nil {
			// We'll pick the last error only
			attrs = append(attrs, slog.Any("error", lastErr.Err))
		}
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
		parentLog.LogAttrs(c.Request.Context(), level, msg, attrs...)
	}
}

// MiddlewareLoggerMask returns a Gin middleware that masks the request path using a regular expression before it is logged
func (s *Server) MiddlewareLoggerMask(exp *regexp.Regexp, replace string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rs := getRequestState(c)
		if rs == nil {
			return
		}

		rs.logMask = func(path string) string {
			return exp.ReplaceAllString(path, replace)
		}
	}
}

func (s *Server) getPortal(c *gin.Context) (*Portal, error) {
	// Requests resolve the portal more than once, so the result is kept for the rest of the request
	rs := getRequestState(c)
	if rs != nil && rs.portal != nil {
		return rs.portal, nil
	}

	cfg := config.Get()

	portalName := strings.ToLower(c.Param("portal"))
	if portalName == "" && cfg.DefaultPortal != "" {
		portalName = cfg.DefaultPortal
	}

	portal, ok := s.portals[portalName]
	if !ok {
		return nil, NewResponseError(http.StatusNotFound, "Portal not found")
	}

	if rs != nil {
		rs.portal = portal
	}

	return portal, nil
}

func (s *Server) getProvider(c *gin.Context) (*Portal, auth.Provider, error) {
	portal, err := s.getPortal(c)
	if err != nil {
		return nil, nil, err
	}

	providerName := strings.ToLower(c.Param("provider"))
	provider, ok := portal.Providers[providerName]
	if !ok {
		return nil, nil, NewResponseError(http.StatusNotFound, "Provider not found")
	}

	return portal, provider, nil
}
