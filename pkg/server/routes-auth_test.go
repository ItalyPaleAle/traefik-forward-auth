package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

func TestServerAuthRoutes(t *testing.T) {
	cfg := config.Get()

	// Create the server
	// This will create in-memory listeners with bufconn too
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	t.Run("auth root redirects to signin", func(t *testing.T) {
		// Make a request to the auth root endpoint without a session
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/test1", testServerPort), nil)
		require.NoError(t, err)
		// Add required headers
		req.Header.Set("X-Forwarded-Server", "traefik@docker")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Port", "443")
		req.Header.Set("X-Forwarded-For", "1.1.1.1")
		req.Header.Set("X-Forwarded-Host", "example.com")

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Expect a SeeOther redirect to the signin page with a state token
		assert.Equal(t, http.StatusSeeOther, res.StatusCode)
		loc := res.Header.Get("Location")
		require.NotEmpty(t, loc)

		locUrl, err := url.Parse(loc)
		require.NoError(t, err)

		assert.Equal(t, "https", locUrl.Scheme)
		assert.Equal(t, cfg.Server.Hostname, locUrl.Host)
		assert.Equal(t, "/portals/test1/signin", locUrl.Path)
		assert.Contains(t, locUrl.Query().Get("state"), "~") // state has the format: id~nonce

		// Reset the log buffer
		logBuf.Reset()
	})
}

func TestCheckAuthzConditions(t *testing.T) {
	// Create a test server with predicates cache
	s := &Server{
		predicates: haxmap.New[string, cachedPredicate](),
	}

	// Create a test profile with email
	profile := &user.Profile{
		ID: "123",
		Email: &user.ProfileEmail{
			Value:    "test@example.com",
			Verified: true,
		},
	}

	t.Run("Valid condition returns true", func(t *testing.T) {
		// Condition that should be true
		ok, err := s.checkAuthzConditions(`ClaimEqual("email", "test@example.com")`, profile)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("Invalid condition syntax returns error", func(t *testing.T) {
		_, err := s.checkAuthzConditions(`"email" == "test@example.com"`, profile)
		require.Error(t, err)
	})

	t.Run("False condition returns false", func(t *testing.T) {
		// Condition that should be false
		ok, err := s.checkAuthzConditions(`ClaimEqual("email", "other@example.com")`, profile)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}
