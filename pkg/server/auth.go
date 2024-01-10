package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

const sessionCookieName = "sess"

// CheckAuthCookieMiddleware is a middleware that checks if the request contains a valid authentication token in the cookie.
func (s *Server) CheckAuthCookieMiddleware(c *gin.Context) {
	// Check if we have a cookie
	val, err := c.Cookie(sessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		// No cookie found, so just return
		return
	} else if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to get session cookie: %w", err))
		return
	}

	// Parse the session
}

// Generates a session token as a JWT
func generateSessionToken(profile auth.UserProfile) (string, error) {

}
