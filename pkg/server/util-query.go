package server

import (
	"github.com/gin-gonic/gin"
)

// queryValue returns the value of a query string parameter, or an empty string if it's not present.
//
// It is equivalent to gin's Context.Query, except that it doesn't parse the query string at all when the request doesn't have one.
// Requests Traefik forwards normally carry no query string, and gin parses it on the first Query call regardless, which allocates a map every time.
func queryValue(c *gin.Context, key string) string {
	if c.Request == nil || c.Request.URL == nil || c.Request.URL.RawQuery == "" {
		return ""
	}

	return c.Query(key)
}
