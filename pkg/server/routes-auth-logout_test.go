package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutePostLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := &Server{
		portals: map[string]Portal{
			"test1": {Name: "test1"},
		},
	}

	newContext := func(path string, portal string) (*gin.Context, *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, path, nil)
		c.Request.Header.Set("X-Forwarded-Proto", "https")
		if portal != "" {
			c.Params = gin.Params{{Key: "portal", Value: portal}}
		}
		return c, rec
	}

	t.Run("success redirects to portal with logout flag", func(t *testing.T) {
		c, rec := newContext("/portals/test1/logout", "test1")

		srv.RoutePostLogout(c)

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "https://tfa.example.com/portals/test1?logout=1", rec.Header().Get("Location"))
		assert.Contains(t, rec.Body.String(), "You've been logged out. Redirecting to portal: https://tfa.example.com/portals/test1?logout=1")
	})

	t.Run("unknown portal returns not found error", func(t *testing.T) {
		c, rec := newContext("/portals/unknown/logout", "unknown")

		srv.RoutePostLogout(c)

		assert.True(t, c.IsAborted())
		require.Len(t, c.Errors, 1)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "Error: Portal not found", rec.Body.String())
	})
}
