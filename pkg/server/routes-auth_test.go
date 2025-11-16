package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

func TestServerAuthRoutes(t *testing.T) {
	testFn := func(rootPath string, expectedSigninPath string, setConfigFn func(c *config.Config)) func(t *testing.T) {
		return func(t *testing.T) {
			if setConfigFn != nil {
				t.Cleanup(config.SetTestConfig(setConfigFn))
			}

			// Create the server
			// This will create in-memory listeners with bufconn too
			srv, logBuf := newTestServer(t)
			require.NotNil(t, srv)
			stopServerFn := startTestServer(t, srv)
			defer stopServerFn(t)
			appClient := clientForListener(srv.appListener)

			t.Run("auth root redirects to signin", func(t *testing.T) {
				cfg := config.Get()

				reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("http://localhost:%d%s", testServerPort, rootPath), nil)
				require.NoError(t, err)
				populateRequiredProxyHeaders(t, req)

				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				assert.Equal(t, http.StatusSeeOther, res.StatusCode)

				locUrl := urlMustParse(t, res.Header.Get("Location"))
				assert.Equal(t, "https", locUrl.Scheme)
				assert.Equal(t, cfg.Server.Hostname, locUrl.Host)
				assert.Equal(t, expectedSigninPath, locUrl.Path)
				assert.Contains(t, locUrl.Query().Get("state"), "~")

				logBuf.Reset()
			})

			t.Run("auth root logout flag propagated", func(t *testing.T) {
				cfg := config.Get()

				reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("http://localhost:%d%s?logout=1", testServerPort, rootPath), nil)
				require.NoError(t, err)
				populateRequiredProxyHeaders(t, req)

				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				assert.Equal(t, http.StatusSeeOther, res.StatusCode)

				locUrl := urlMustParse(t, res.Header.Get("Location"))
				assert.Equal(t, "https", locUrl.Scheme)
				assert.Equal(t, cfg.Server.Hostname, locUrl.Host)
				assert.Equal(t, expectedSigninPath, locUrl.Path)
				assert.Contains(t, locUrl.Query().Get("state"), "~")
				assert.True(t, utils.IsTruthy(locUrl.Query().Get("logout")))

				logBuf.Reset()
			})

			t.Run("auth root reuses state cookie for same return URL", func(t *testing.T) {
				reqCtx1, cancel1 := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel1()
				req1, err := http.NewRequestWithContext(reqCtx1, http.MethodGet,
					fmt.Sprintf("http://localhost:%d%s", testServerPort, rootPath), nil)
				require.NoError(t, err)
				populateRequiredProxyHeaders(t, req1)

				res1, err := appClient.Do(req1)
				require.NoError(t, err)
				defer closeBody(res1)

				assert.Equal(t, http.StatusSeeOther, res1.StatusCode)
				state1 := urlMustParse(t, res1.Header.Get("Location")).Query().Get("state")
				require.NotEmpty(t, state1)
				cookies := res1.Header.Values("Set-Cookie")
				require.NotEmpty(t, cookies)

				reqCtx2, cancel2 := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel2()
				req2, err := http.NewRequestWithContext(reqCtx2, http.MethodGet,
					fmt.Sprintf("http://localhost:%d%s", testServerPort, rootPath), nil)
				require.NoError(t, err)
				populateRequiredProxyHeaders(t, req2)
				for _, c := range cookies {
					req2.Header.Add("Cookie", cookiePair(c))
				}

				res2, err := appClient.Do(req2)
				require.NoError(t, err)
				defer closeBody(res2)

				assert.Equal(t, http.StatusSeeOther, res2.StatusCode)
				state2 := urlMustParse(t, res2.Header.Get("Location")).Query().Get("state")
				assert.Equal(t, state1, state2)

				logBuf.Reset()
			})
		}
	}

	t.Run("no basePath and no defaultPortal", testFn("/portals/test1", "/portals/test1/signin", nil))

	t.Run("requesting default portal using short path", testFn("/", "/signin", func(c *config.Config) {
		c.DefaultPortal = "test1"
	}))

	t.Run("requesting default portal using long path", testFn("/portals/test1", "/portals/test1/signin", func(c *config.Config) {
		c.DefaultPortal = "test1"
	}))

	t.Run("has basePath and no defaultPortal", testFn("/auth/portals/test1", "/auth/portals/test1/signin", func(c *config.Config) {
		c.Server.BasePath = "/auth"
	}))

	t.Run("with basePath, requesting default portal using short path", testFn("/auth/", "/auth/signin", func(c *config.Config) {
		c.Server.BasePath = "/auth"
		c.DefaultPortal = "test1"
	}))

	t.Run("with basePath, requesting default portal using long path", testFn("/auth/portals/test1", "/auth/portals/test1/signin", func(c *config.Config) {
		c.Server.BasePath = "/auth"
		c.DefaultPortal = "test1"
	}))
}

func TestRouteGetAuthProvider(t *testing.T) {
	// Create the server
	srv, logBuf := newTestServer(t)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	// Helper to get a fresh state (stateCookieID~nonce) plus associated Set-Cookie headers
	getState := func(t *testing.T) (state string, cookies []string) {
		reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d/portals/test1", testServerPort), nil)
		require.NoError(t, err)
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		require.Equal(t, http.StatusSeeOther, res.StatusCode)

		loc := res.Header.Get("Location")
		st := urlMustParse(t, loc).Query().Get("state")
		require.NotEmpty(t, st)

		return st, res.Header.Values("Set-Cookie")
	}

	t.Run("success redirects to provider auth URL", func(t *testing.T) {
		state, cookies := getState(t)
		reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d/portals/test1/providers/testoauth2?state=%s", testServerPort, state), nil)
		require.NoError(t, err)

		populateRequiredProxyHeaders(t, req)
		for _, c := range cookies {
			req.Header.Add("Cookie", cookiePair(c))
		}

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		assert.Equal(t, http.StatusSeeOther, res.StatusCode)

		locUrl := urlMustParse(t, res.Header.Get("Location"))

		assert.Equal(t, "https://tfa.example.com/portals/test1/oauth2/callback", locUrl.Query().Get("redirect_uri"))
		assert.Contains(t, locUrl.Query().Get("state"), "~")

		logBuf.Reset()
	})

	t.Run("missing state param", func(t *testing.T) {
		reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d/portals/test1/providers/testoauth2", testServerPort), nil)
		require.NoError(t, err)
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		assert.Equal(t, http.StatusBadRequest, res.StatusCode)

		logBuf.Reset()
	})

	t.Run("invalid state format", func(t *testing.T) {
		// Just to have cookies set (though not required for this failure)
		_, cookies := getState(t)

		reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d/portals/test1/providers/testoauth2?state=badformat", testServerPort), nil)
		require.NoError(t, err)

		populateRequiredProxyHeaders(t, req)
		for _, c := range cookies { // attach cookies
			req.Header.Add("Cookie", cookiePair(c))
		}

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		logBuf.Reset()
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		state, cookies := getState(t)
		stateCookieID, nonce, ok := strings.Cut(state, "~")
		require.True(t, ok)
		badState := stateCookieID + "~" + nonce[0:len(nonce)-5] + "xxxxx"

		reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d/portals/test1/providers/testoauth2?state=%s", testServerPort, badState), nil)
		require.NoError(t, err)

		populateRequiredProxyHeaders(t, req)
		for _, c := range cookies {
			req.Header.Add("Cookie", cookiePair(c))
		}

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)

		logBuf.Reset()
	})
}

func TestCheckAuthzConditions(t *testing.T) {
	// Create a test server with predicates cache
	s := &Server{
		predicates: haxmap.New[string, cachedPredicate](),
	}

	profile := &user.Profile{
		ID: "123",
		Email: &user.ProfileEmail{
			Value:    "test@example.com",
			Verified: true,
		},
	}

	t.Run("Valid condition returns true", func(t *testing.T) {
		ok, err := s.checkAuthzConditions(`ClaimEqual("email", "test@example.com")`, profile)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("Invalid condition syntax returns error", func(t *testing.T) {
		_, err := s.checkAuthzConditions(`"email" == "test@example.com"`, profile)
		require.Error(t, err)
	})

	t.Run("False condition returns false", func(t *testing.T) {
		ok, err := s.checkAuthzConditions(`ClaimEqual("email", "other@example.com")`, profile)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("Predicates are cached", func(t *testing.T) {
		const cond = `ClaimEqual("email", "test@example.com")`

		// First call should cache the predicate
		ok1, err1 := s.checkAuthzConditions(cond, profile)
		require.NoError(t, err1)
		assert.True(t, ok1)

		// Verify the predicate is now in the cache
		cached1, found := s.predicates.Get(cond)
		require.True(t, found)
		assert.NotNil(t, cached1.predicate)
		lastUsed1 := cached1.lastUsed.Load()

		// Second call should retrieve from cache
		time.Sleep(1100 * time.Millisecond) // Sleep for more than 1 second to ensure unix timestamps differ
		ok2, err2 := s.checkAuthzConditions(cond, profile)
		require.NoError(t, err2)
		assert.True(t, ok2)

		// Verify the same cached entry is reused and lastUsed is updated
		cached2, found := s.predicates.Get(cond)
		require.True(t, found)

		// Since predicates are functions, we can't compare them directly
		// Instead, verify that the cache entry exists and lastUsed is updated
		lastUsed2 := cached2.lastUsed.Load()
		assert.Greater(t, lastUsed2, lastUsed1, "lastUsed timestamp should be updated on cache hit")
	})

	t.Run("Different conditions have separate cache entries", func(t *testing.T) {
		const cond1 = `ClaimEqual("email", "test@example.com")`
		const cond2 = `ClaimEqual("email", "other@example.com")`

		// Call with first condition
		ok1, err1 := s.checkAuthzConditions(cond1, profile)
		require.NoError(t, err1)
		assert.True(t, ok1)

		// Call with second condition
		ok2, err2 := s.checkAuthzConditions(cond2, profile)
		require.NoError(t, err2)
		assert.False(t, ok2)

		// Both should be in cache as different entries
		cached1, found1 := s.predicates.Get(cond1)
		require.True(t, found1)

		cached2, found2 := s.predicates.Get(cond2)
		require.True(t, found2)

		// Cache entries should be separate (different conditions)
		assert.NotEmpty(t, cached1.predicate)
		assert.NotEmpty(t, cached2.predicate)

		// Both should have lastUsed timestamps set
		assert.Positive(t, cached1.lastUsed.Load())
		assert.Positive(t, cached2.lastUsed.Load())
	})
}
