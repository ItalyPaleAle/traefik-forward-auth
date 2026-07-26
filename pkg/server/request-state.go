package server

import (
	"context"
	"log/slog"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// requestStateKey is the key the request state is stored under in the request's context
// The type is unexported so nothing outside this package can collide with it or reach the state
type requestStateKey struct{}

// requestState holds the values middlewares and handlers share for the duration of a single request
// It is attached to the request's context by MiddlewareAddRequestState, which runs before every route
// Note: Only the goroutine serving the request touches it, so the fields need no synchronization
type requestState struct {
	// ID of the request, included in the logs and returned in the X-Request-Id header
	requestID string

	// Portal the request is for
	// It is resolved from the route the first time it's needed, then reused for the rest of the request
	portal *Portal

	// Client IP, extracted from X-Forwarded-For by MiddlewareProxyHeaders
	// It is empty on routes that don't run that middleware
	clientIP string

	// User's session, populated when the request carries a valid session cookie
	profile       *user.Profile
	provider      auth.Provider
	authenticated bool

	// Message for the request log line, used in place of the default one when set
	logMessage string

	// Function that masks the request path before it is logged, if set
	logMask func(path string) string
}

// getRequestState returns the state attached to the request by MiddlewareAddRequestState
// It returns nil for a request that didn't go through that middleware, which in practice only happens when a handler is invoked directly rather than through the router
func getRequestState(c *gin.Context) *requestState {
	if c.Request == nil {
		return nil
	}

	return requestStateFromContext(c.Request.Context())
}

// requestStateFromContext returns the request state attached to a context, or nil if there is none
func requestStateFromContext(ctx context.Context) *requestState {
	rs, _ := ctx.Value(requestStateKey{}).(*requestState)
	return rs
}

// requestLogger returns a logger tagged with the ID of the current request.
// Handlers should use this rather than reaching for a logger in the context: the request only carries its ID, and the logger is derived from it here, at the point where something is actually logged.
func (s *Server) requestLogger(c *gin.Context) *slog.Logger {
	log := s.log
	if log == nil {
		log = slog.Default()
	}

	rs := getRequestState(c)
	if rs == nil || rs.requestID == "" {
		return log
	}

	return log.With(slog.String("id", rs.requestID))
}

// setLogMessage sets the message used for the request's log line, in place of the default one
func setLogMessage(c *gin.Context, msg string) {
	rs := getRequestState(c)
	if rs == nil {
		return
	}

	rs.logMessage = msg
}
