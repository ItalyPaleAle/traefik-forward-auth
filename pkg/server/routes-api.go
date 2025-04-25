package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// RouteGetAPIVerify is the handler for GET /api/portals/:portal/verify
// This API validates a token and returns the list of claims
// The token must be passed in the Authorization header
func (s *Server) RouteGetAPIVerify(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// First, get the token
	// Try with the authorization header first
	val := c.GetHeader("Authorization")
	if len(val) > 7 {
		// Trim the "bearer" prefix if found
		if strings.ToLower(val[0:len("bearer ")]) == "bearer " {
			val = val[len("bearer "):]
		}
	}
	if len(val) == 0 {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
		return
	}

	// Parse the session token
	token, err := s.parseSessionToken(val, portal.Name)
	if err != nil {
		AbortWithErrorJSON(c, NewInvalidTokenErrorf("Access token is invalid: %v", err))
		return
	}
	claims, err := token.AsMap(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, NewInvalidTokenErrorf("failed to get claims from token: %v", err))
		return
	}

	// If we're here, the token is valid
	// We can return success and show the claims
	c.JSON(http.StatusOK, GetAPIVerifyResponse{
		Valid:    true,
		Portal:   portal.Name,
		Provider: cast.ToString(claims[user.ProviderNameClaim]),
		Claims:   claims,
	})
}

// GetAPIVerifyResponse is the response from RouteGetAPIVerify
type GetAPIVerifyResponse struct {
	Valid    bool           `json:"valid"`
	Portal   string         `json:"portal"`
	Provider string         `json:"provider"`
	Claims   map[string]any `json:"claims"`
}
