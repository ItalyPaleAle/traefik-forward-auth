//go:build unit

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestGetReturnURLPreservesQuery exercises the fix for the bug where the post-auth redirect
// dropped the query string from X-Forwarded-Uri
// Deep links, OAuth callbacks behind the protected app, CSRF tokens, and pagination all live in the query, so the return URL must round-trip the original request URI verbatim
func TestGetReturnURLPreservesQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	makeCtx := func(forwardedURI string) *gin.Context {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXForwardedHost, "app.example.com")
		req.Header.Set(headerXForwardedProto, "https")
		if forwardedURI != "" {
			req.Header.Set(headerXForwardedURI, forwardedURI)
		}
		c.Request = req
		return c
	}

	tests := []struct {
		name         string
		forwardedURI string
		want         string
	}{
		{
			name:         "path only",
			forwardedURI: "/dashboard",
			want:         "https://app.example.com/dashboard",
		},
		{
			name:         "single query param",
			forwardedURI: "/dashboard?tab=details",
			want:         "https://app.example.com/dashboard?tab=details",
		},
		{
			name:         "multiple query params",
			forwardedURI: "/items?page=3&sort=desc&filter=active",
			want:         "https://app.example.com/items?page=3&sort=desc&filter=active",
		},
		{
			name:         "url-encoded query",
			forwardedURI: "/search?q=hello%20world&lang=en-US",
			want:         "https://app.example.com/search?q=hello%20world&lang=en-US",
		},
		{
			name:         "oauth callback shape",
			forwardedURI: "/oauth/callback?state=abc123&code=xyz789",
			want:         "https://app.example.com/oauth/callback?state=abc123&code=xyz789",
		},
		{
			name:         "absolute URI is reduced to path+query - host cannot be hijacked",
			forwardedURI: "https://evil.example/path?q=v",
			want:         "https://app.example.com/path?q=v",
		},
		{
			name:         "scheme-relative URI is reduced to path+query",
			forwardedURI: "//evil.example/path?q=v",
			want:         "https://app.example.com/path?q=v",
		},
		{
			name:         "empty path becomes /",
			forwardedURI: "?q=v",
			want:         "https://app.example.com/?q=v",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := makeCtx(tt.forwardedURI)
			got := getReturnURL(ctx, "default")
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGetReturnURLNoForwardedURIFallsBackToProfile verifies that the absence of X-Forwarded-Uri (which means the request did not originate from Traefik) routes the user to the portal's profile page instead of constructing an empty URL
func TestGetReturnURLNoForwardedURIFallsBackToProfile(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerXForwardedHost, "auth.example.com")
	req.Header.Set(headerXForwardedProto, "https")
	c.Request = req

	got := getReturnURL(c, "default")
	assert.Contains(t, got, "/profile")
}
