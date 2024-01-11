package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"

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

type sessionTokenOpts struct {
	// Audience for the tokens
	// This is generally set to "auth-<traefik server name>"
	Audience string
	// Issuer for the tokens
	// This is set to the URL of the auth server
	Issuer string
}

// Generates a session token as a JWT
func generateSessionToken(profile auth.UserProfile) (string, error) {
	jwt.NewBuilder()
}
