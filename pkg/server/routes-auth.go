package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// RouteGetRoot is the handler for GET /
// This handles requests from Traefik and redirects users to auth servers if needed.
func (s *Server) RouteGetRoot(c *gin.Context) {
	// Check if we have a session
	profileAny, ok := c.Get("session-profile")
	if !ok {
		s.redirectToAuth(c)
		return
	}
	profile, ok := profileAny.(user.Profile)
	if !ok || profile.ID == "" {
		s.redirectToAuth(c)
		return
	}

	// If we are here, we have a valid session, so respond with a 200 status code
	s.metrics.RecordAuthentication(true)
	c.Header("X-Forwarded-User", profile.ID)
	c.Status(http.StatusOK)
}

func (s *Server) redirectToAuth(c *gin.Context) {
	s.metrics.RecordAuthentication(false)

	// Create a new nonce and set the cookie
	nonce, err := setNonceCookie(c)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to set nonce cookie: %w", err))
		return
	}

	// Redirect to the authorization URL
	redirectURI := c.GetHeader("X-Forwarded-Proto") + "://" + config.Get().Hostname + "/oauth/callback"
	authURL, err := s.auth.AuthorizeURL(nonce, redirectURI)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to get authorize URL: %w", err))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}
