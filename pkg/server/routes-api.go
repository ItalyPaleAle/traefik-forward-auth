package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RouteGetAPIVerify is the handler for GET /api/verify
// This API validates a token and returns the list of claims
// The token can be passed in the Authorization header
func (s *Server) RouteGetAPIVerify(c *gin.Context) {
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
	token, err := s.parseSessionToken(val)
	if err != nil {
		AbortWithErrorJSON(c, err)
		return
	}
	claims, err := token.AsMap(c.Request.Context())
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to get claims from token: %w", err))
		return
	}

	// If we're here, the token is valid
	// We can return success and show the claims
	c.JSON(http.StatusOK, GetAPIVerifyResponse{
		Valid:  true,
		Claims: claims,
	})
}

// GetAPIVerifyResponse is the response from RouteGetAPIVerify
type GetAPIVerifyResponse struct {
	Valid  bool           `json:"valid"`
	Claims map[string]any `json:"claims"`
}
