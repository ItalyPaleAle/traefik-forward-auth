package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// RouteGetAPIVerify is the handler for GET /api/portals/:portal/verify
// This API validates a token and returns the list of claims
// The token must be passed in the Authorization header
func (s *Server) RouteGetAPIVerify(c *gin.Context) {
	const bearerPrefix = "bearer "

	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// First, get the token
	// Try with the authorization header first
	val := c.GetHeader("Authorization")
	// Trim the "bearer" prefix if found
	if len(val) > len(bearerPrefix) && strings.ToLower(val[0:len(bearerPrefix)]) == bearerPrefix {
		val = val[len("bearer "):]
	}
	if len(val) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
		return
	}

	// Get the cookie domain for the current request host
	cookieDomain, _, ok := cookieDomainForContext(c)
	if !ok {
		// This is a configuration/routing problem rather than a token problem, so it returns 400 instead of an invalid-token error
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "Request host is not associated with this auth server"))
		return
	}

	// Parse the session token
	token, err := s.parseSessionToken(val, portal.Name, cookieDomain)
	if err != nil {
		AbortWithErrorJSON(c, NewInvalidTokenErrorf("Access token is invalid: %v", err))
		return
	}

	var provider string
	err = token.Get(user.ProviderNameClaim, &provider)
	if err != nil {
		AbortWithErrorJSON(c, NewInvalidTokenErrorf("failed to get '%s' claim from token: %v", user.ProviderNameClaim, err))
		return
	}

	// If we're here, the token is valid
	// We can return success and show the claims
	c.JSON(http.StatusOK, GetAPIVerifyResponse{
		Valid:    true,
		Portal:   portal.Name,
		Provider: provider,
		Claims:   token,
	})
}

// GetAPIVerifyResponse is the response from RouteGetAPIVerify
type GetAPIVerifyResponse struct {
	Valid    bool      `json:"valid"`
	Portal   string    `json:"portal"`
	Provider string    `json:"provider"`
	Claims   jwt.Token `json:"claims"`
}
