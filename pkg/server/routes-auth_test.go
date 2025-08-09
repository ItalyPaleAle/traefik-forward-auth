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
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
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

	const rootPath = "/portals/test1"
	const expectedSigninPath = "/portals/test1/signin"

	t.Run("auth root redirects to signin", func(t *testing.T) {
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
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d%s/?logout=1", testServerPort, rootPath), nil)
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
	})
}

func cookiePair(setCookie string) string {
	for i, r := range setCookie {
		if r == ';' {
			return setCookie[:i]
		}
	}
	return setCookie
}

func urlMustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	require.NotEmpty(t, raw)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
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
}
