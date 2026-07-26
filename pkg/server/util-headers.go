package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// headerValue returns the first value of a request header, whose name must already be in canonical form
func headerValue(h http.Header, canonicalName string) string {
	// Reading the map directly skips the key canonicalization that http.Header.Get performs on every call
	v := h[canonicalName]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// setResponseHeader sets a response header, skipping the canonicalization http.Header.Set performs
// The name must already be in canonical form
// An empty value removes the header, matching the behavior of gin's Context.Header
func setResponseHeader(c *gin.Context, canonicalName string, value string) {
	h := c.Writer.Header()
	if value == "" {
		delete(h, canonicalName)
		return
	}
	h[canonicalName] = []string{value}
}
