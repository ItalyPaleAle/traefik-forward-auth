package server

import "github.com/gin-gonic/gin"

// RouteGetRoot is the handler for GET /
// This handles requests from Traefik and redirects users to auth servers if needed.
func (s *Server) RouteGetRoot(c *gin.Context) {

}
