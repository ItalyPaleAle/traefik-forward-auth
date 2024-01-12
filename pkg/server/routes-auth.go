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
	if !c.GetBool("session-auth") {
		s.redirectToAuth(c)
		return
	}
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

// RouteGetRoot is the handler for GET /oauth2/callback
// This handles redirects from OAuth2 identity providers after successful callbacks
func (s *Server) RouteOAuth2Callback(c *gin.Context) {
	// Check if there's an error in the query string
	if qsErr := c.Query("error"); qsErr != "" {
		c.Set("log-message", "Error from the app server: "+qsErr)
		AbortWithErrorJSON(c, NewResponseError(http.StatusFailedDependency, "The auth server returned an error"))
		return
	}

	// Ensure that we have a state and code parameters
	stateParam := c.Query("state")
	codeParam := c.Query("code")
	if stateParam == "" || codeParam == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "The parameters 'state' and 'code' are required in the query string"))
		return
	}

	// Get the nonce cookie
	nonce, err := getNonceCookie(c)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("invalid nonce cookie: %w", err))
		return
	} else if nonce == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Nonce cookie not found"))
		return
	}

	// Clear the nonce cookie
	deleteNonceCookie(c)

	// Check if the nonce matches
	if nonce != stateParam {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Nonce cookie does not match state token"))
		return
	}

	// Exchange the code for a token
	at, err := s.auth.ExchangeCode(c.Request.Context(), codeParam, getRedirectURI(c))
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to exchange code for access token: %w", err))
		return
	}

	// Retrieve the user profile
	profile, err := s.auth.RetrieveProfile(c.Request.Context(), at)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to retrieve user profile: %w", err))
		return
	}

	// Set the profile in the cookie
	err = setSessionCookie(c, &profile)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to set session cookie: %w", err))
		return
	}

	// TODO: redirect
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
	authURL, err := s.auth.AuthorizeURL(nonce, getRedirectURI(c))
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to get authorize URL: %w", err))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

func getRedirectURI(c *gin.Context) string {
	return c.GetHeader("X-Forwarded-Proto") + "://" + config.Get().Hostname + "/oauth2/callback"
}
