package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
				assert.Equal(t, "example.com", locUrl.Host)
				assert.Equal(t, expectedSigninPath, locUrl.Path)
				assert.Contains(t, locUrl.Query().Get("state"), "~")

				logBuf.Reset()
			})

			t.Run("auth root logout flag propagated", func(t *testing.T) {
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
				assert.Equal(t, "example.com", locUrl.Host)
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

func TestRouteGetAuthRootAuthenticated(t *testing.T) {
	testFn := func(setConfigFn func(c *config.Config), checkResFn func(t *testing.T, res *http.Response, profile *user.Profile)) func(t *testing.T) {
		return func(t *testing.T) {
			if setConfigFn != nil {
				t.Cleanup(config.SetTestConfig(setConfigFn))
			}

			// Create the server
			srv, _ := newTestServer(t)
			require.NotNil(t, srv)
			stopServerFn := startTestServer(t, srv)
			defer stopServerFn(t)
			appClient := clientForListener(srv.appListener)

			cfg := config.Get()
			const portalName = "test1"

			// Create a session token with a full profile
			profile := createFullTestProfile()
			profile.Picture = createRandomStringWithPrefix("https://example.com/avatar.jpg?", 1025)
			token := createTestSessionToken(t, portalName, profile, time.Hour)
			cookieName := cfg.Cookies.CookieName(portalName)

			// Make a request to the /portals/:portal/profile.json endpoint
			reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
				fmt.Sprintf("http://localhost:%d/portals/%s", testServerPort, portalName), nil)
			require.NoError(t, err)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
			populateRequiredProxyHeaders(t, req)

			res, err := appClient.Do(req)
			require.NoError(t, err)
			defer closeBody(res)

			// Check the response
			if checkResFn != nil {
				checkResFn(t, res, profile)
			}
		}
	}

	t.Run("authenticated with default headers", testFn(nil, func(t *testing.T, res *http.Response, profile *user.Profile) {
		expectedAuthenticatedUser := fmt.Sprintf(
			`{"provider":"%s","portal":"test1","user":"%s"}`, profile.Provider, profile.ID,
		)
		require.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, profile.ID, res.Header.Get("X-Forwarded-User"))
		assert.Equal(t, profile.Name.FullName, res.Header.Get("X-Forwarded-Displayname"))
		assert.Equal(t, expectedAuthenticatedUser, res.Header.Get("X-Authenticated-User"))
	}))

	t.Run("authenticated with empty headers", testFn(func(c *config.Config) {
		// Non-nil but empty
		c.Portals[0].Headers = &[]config.ConfigPortalHeader{}
	}, func(t *testing.T, res *http.Response, profile *user.Profile) {
		require.Equal(t, http.StatusOK, res.StatusCode)
		assert.Empty(t, res.Header.Get("X-Forwarded-User"))
		assert.Empty(t, res.Header.Get("X-Forwarded-Displayname"))
		assert.Empty(t, res.Header.Get("X-Authenticated-User"))
	}))

	t.Run("authenticated with custom headers", testFn(func(c *config.Config) {
		c.Portals[0].Headers = &[]config.ConfigPortalHeader{
			{
				Name:  "X-Forwarded-Email",
				Claim: "email",
			},
			{
				Name:  "X-Forwarded-User",
				Claim: "email",
			},
			{
				Name:     "X-Portal",
				Property: "portal.name",
			},
			{
				Name:     "X-Provider",
				Property: "provider.name",
			},
			{
				Name:  "X-Missing-Claim",
				Claim: "missing",
			},
			{
				Name:  "X-Incompatible-Claim",
				Claim: "roles",
			},
			{
				Name:  "X-Claim-Too-Long",
				Claim: "picture",
			},
		}
	}, func(t *testing.T, res *http.Response, profile *user.Profile) {
		assert.Equal(t, profile.Email.Value, res.Header.Get("X-Forwarded-Email"))
		assert.Equal(t, profile.Email.Value, res.Header.Get("X-Forwarded-User"))
		assert.Equal(t, "test1", res.Header.Get("X-Portal"))
		assert.Equal(t, profile.Provider, res.Header.Get("X-Provider"))
		assert.Empty(t, res.Header.Get("X-Forwarded-Displayname"))
		assert.Empty(t, res.Header.Get("X-Authenticated-User"))
		assert.Empty(t, res.Header.Get("X-Missing-Claim"))
		assert.Empty(t, res.Header.Get("X-Incompatible-Claim"))
		assert.Empty(t, res.Header.Get("X-Claim-Too-Long"))
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

		assert.Equal(t, "https://example.com/portals/test1/oauth2/callback", locUrl.Query().Get("redirect_uri"))
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

// testProxyHeaders is a small builder for the X-Forwarded-* headers Traefik injects on each request
// All e2e tests below construct requests through it so the only varying input across modes is the host
type testProxyHeaders struct {
	host string // X-Forwarded-Host
	uri  string // X-Forwarded-URI; empty means do not set
}

func (p testProxyHeaders) apply(req *http.Request) {
	req.Header.Set(headerXForwardedProto, "https")
	req.Header.Set(headerXForwardedPort, "443")
	req.Header.Set(headerXForwardedFor, "1.1.1.1")
	if p.host != "" {
		req.Header.Set(headerXForwardedHost, p.host)
	}
	if p.uri != "" {
		req.Header.Set(headerXForwardedURI, p.uri)
	}
}

// doProxiedRequest issues a GET request with X-Forwarded-* headers and the given Set-Cookie strings as request cookies
// Returns the response (caller must close the body) and the path+query of the response Location header (empty for non-redirects)
func doProxiedRequest(t *testing.T, client *http.Client, path string, p testProxyHeaders, setCookies []string) *http.Response {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d%s", testServerPort, path), nil)
	require.NoError(t, err)
	p.apply(req)
	for _, sc := range setCookies {
		req.Header.Add("Cookie", cookiePair(sc))
	}
	res, err := client.Do(req)
	require.NoError(t, err)
	return res
}

// TestDedicatedSubdomainRedirects verifies that when an `authHost` is configured for the matched cookie domain, redirects to Traefik Forward Auth itself (sign-in page, OAuth2 callback) target the auth host rather than the app host
// This is the "dedicated sub-domain" mode where Traefik Forward Auth runs at e.g. auth.example.com while apps run at app.example.com
func TestDedicatedSubdomainRedirects(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = []config.ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	// Step 1: simulate the forward-auth call from Traefik for an app on app.example.com — TFA should redirect the user to auth.example.com to start the sign-in
	res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.example.com", uri: "/dashboard"}, nil)
	defer closeBody(res)

	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	signInURL := urlMustParse(t, res.Header.Get("Location"))
	assert.Equal(t, "auth.example.com", signInURL.Host, "sign-in redirect should target the configured authHost")
	assert.Equal(t, "/portals/test1/signin", signInURL.Path)
	state := signInURL.Query().Get("state")
	require.NotEmpty(t, state)

	// Capture the state cookies emitted on the first response so the next request can present them
	stateCookies := res.Header.Values("Set-Cookie")
	require.NotEmpty(t, stateCookies)

	// Step 2: follow up to the provider start endpoint — TFA should send the IdP a callback URL on the auth host
	// In dedicated sub-domain mode the user is now hitting Traefik Forward Auth directly at auth.example.com
	res2 := doProxiedRequest(t, appClient,
		"/portals/test1/providers/testoauth2?state="+state,
		testProxyHeaders{host: "auth.example.com"},
		stateCookies,
	)
	defer closeBody(res2)

	require.Equal(t, http.StatusSeeOther, res2.StatusCode)
	idpURL := urlMustParse(t, res2.Header.Get("Location"))
	assert.Equal(t, "https://auth.example.com/portals/test1/oauth2/callback", idpURL.Query().Get("redirect_uri"),
		"OAuth2 redirect_uri should target the configured authHost")
}

// TestSubpathModeRedirects verifies the "sub-path" mode where Traefik Forward Auth shares each app's host
// With no `server.domains` configured we expect cookies to be host-only and redirects to use the request host
func TestSubpathModeRedirects(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = nil
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.example.com", uri: "/dashboard"}, nil)
	defer closeBody(res)

	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	signInURL := urlMustParse(t, res.Header.Get("Location"))
	assert.Equal(t, "app.example.com", signInURL.Host, "sub-path mode should redirect on the request host")

	// State cookies should be scoped to the request host (since that's what TFA falls back to without a configured domain)
	stateCookies := res.Header.Values("Set-Cookie")
	require.NotEmpty(t, stateCookies)
	for _, sc := range stateCookies {
		assert.Contains(t, strings.ToLower(sc), "domain=app.example.com",
			"sub-path mode should scope cookies to the request host (got %q)", sc)
	}

	// The OAuth2 redirect_uri should also use the request host
	state := signInURL.Query().Get("state")
	res2 := doProxiedRequest(t, appClient,
		"/portals/test1/providers/testoauth2?state="+state,
		testProxyHeaders{host: "app.example.com"},
		stateCookies,
	)
	defer closeBody(res2)

	require.Equal(t, http.StatusSeeOther, res2.StatusCode)
	idpURL := urlMustParse(t, res2.Header.Get("Location"))
	assert.Equal(t, "https://app.example.com/portals/test1/oauth2/callback", idpURL.Query().Get("redirect_uri"))
}

// TestSubpathModeRedirectsWithDomain verifies sub-path mode where `server.domains` is configured but no `authHost` is set
// The cookie is scoped to the configured domain, but redirects still use the request host (since `authHost` defaults to `domain` and matches it for direct hits)
func TestSubpathModeRedirectsWithDomain(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = []config.ConfigServerDomain{
			{Domain: "example.com"},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	// Hit TFA directly on example.com (since this is sub-path mode the apps and TFA share the host)
	res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "example.com", uri: "/dashboard"}, nil)
	defer closeBody(res)

	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	signInURL := urlMustParse(t, res.Header.Get("Location"))
	assert.Equal(t, "example.com", signInURL.Host)

	// State cookies should be scoped to the configured domain
	cookieHadDomain := false
	for _, sc := range res.Header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(sc), "domain=example.com") {
			cookieHadDomain = true
		}
	}
	assert.True(t, cookieHadDomain, "expected state cookie to be scoped to example.com, got %v", res.Header.Values("Set-Cookie"))
}

// TestMixedDomainsRedirects verifies that with multiple domains — one with an explicit authHost and one without — the per-domain authHost is honored for each
// This is the case where one Traefik Forward Auth instance serves a "dedicated sub-domain" tenant alongside a "sub-path" tenant
func TestMixedDomainsRedirects(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = []config.ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
			{Domain: "tenant.local"},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	t.Run("example.com tenant uses authHost", func(t *testing.T) {
		res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.example.com", uri: "/x"}, nil)
		defer closeBody(res)
		require.Equal(t, http.StatusSeeOther, res.StatusCode)
		assert.Equal(t, "auth.example.com", urlMustParse(t, res.Header.Get("Location")).Host)
	})

	t.Run("tenant.local tenant stays on request host", func(t *testing.T) {
		res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "tenant.local", uri: "/x"}, nil)
		defer closeBody(res)
		require.Equal(t, http.StatusSeeOther, res.StatusCode)
		assert.Equal(t, "tenant.local", urlMustParse(t, res.Header.Get("Location")).Host)
	})
}

// TestStateCookieDomainAcrossHosts verifies that state cookies set during the forward-auth call from the app host are scoped to the cookie domain (not the app host) so the auth host can read them
// Without this, the state cookie set on app.example.com would not be visible on auth.example.com and the sign-in flow would loop
func TestStateCookieDomainAcrossHosts(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = []config.ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	// Step 1: forward-auth call from the app — produces a state cookie scoped to example.com
	res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.example.com", uri: "/dashboard"}, nil)
	defer closeBody(res)
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	stateCookies := res.Header.Values("Set-Cookie")
	require.NotEmpty(t, stateCookies)

	// The Domain attribute on each state cookie should be example.com so both app.example.com and auth.example.com can read it
	for _, sc := range stateCookies {
		assert.Contains(t, strings.ToLower(sc), "domain=example.com",
			"state cookie should be scoped to the cookie domain, not the app host (%q)", sc)
	}

	// Step 2: present the same state cookie via a request from auth.example.com — TFA must accept it
	state := urlMustParse(t, res.Header.Get("Location")).Query().Get("state")
	require.NotEmpty(t, state)
	res2 := doProxiedRequest(t, appClient,
		"/portals/test1/providers/testoauth2?state="+state,
		testProxyHeaders{host: "auth.example.com"},
		stateCookies,
	)
	defer closeBody(res2)
	require.Equal(t, http.StatusSeeOther, res2.StatusCode, "auth host should be able to read state cookies set on the cookie domain")
	assert.Contains(t, res2.Header.Get("Location"), "idp.example.com")
}

// TestUnmatchedHostRejected verifies that a request with X-Forwarded-Host that doesn't match any configured domain is rejected at the route level rather than silently falling back to host-only cookies
func TestUnmatchedHostRejected(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = []config.ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.evil.com", uri: "/dashboard"}, nil)
	defer closeBody(res)

	// Setting the state cookie fails inside RouteGetAuthRoot when the return URL host is not a configured domain
	// AbortWithError defaults to a 5xx response in that case
	assert.GreaterOrEqual(t, res.StatusCode, 500, "request from an unconfigured host should be rejected, got %d", res.StatusCode)
	assert.Empty(t, res.Header.Values("Set-Cookie"), "no cookies should be set for a request from an unconfigured host")
}

// TestLogoutRedirectsUseAuthHost verifies that the logout endpoint sends the user back to the public auth host when authHost is configured
// In sub-path mode (no authHost) the logout redirect still targets the request host
func TestLogoutRedirectsUseAuthHost(t *testing.T) {
	t.Run("dedicated sub-domain", func(t *testing.T) {
		t.Cleanup(config.SetTestConfig(func(c *config.Config) {
			c.Cookies.Domain = ""
			c.Server.Domains = []config.ConfigServerDomain{
				{Domain: "example.com", AuthHost: "auth.example.com"},
			}
		}))

		srv, _ := newTestServer(t)
		require.NotNil(t, srv)
		stopServerFn := startTestServer(t, srv)
		defer stopServerFn(t)
		appClient := clientForListener(srv.appListener)

		reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
			fmt.Sprintf("http://localhost:%d/portals/test1/logout", testServerPort), nil)
		require.NoError(t, err)
		// The logout request reaches TFA directly on the auth host in this mode
		testProxyHeaders{host: "auth.example.com"}.apply(req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)
		require.Equal(t, http.StatusSeeOther, res.StatusCode)
		assert.Equal(t, "https://auth.example.com/portals/test1?logout=1", res.Header.Get("Location"))
	})

	t.Run("sub-path mode", func(t *testing.T) {
		t.Cleanup(config.SetTestConfig(func(c *config.Config) {
			c.Cookies.Domain = ""
			c.Server.Domains = nil
		}))

		srv, _ := newTestServer(t)
		require.NotNil(t, srv)
		stopServerFn := startTestServer(t, srv)
		defer stopServerFn(t)
		appClient := clientForListener(srv.appListener)

		reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
			fmt.Sprintf("http://localhost:%d/portals/test1/logout", testServerPort), nil)
		require.NoError(t, err)
		testProxyHeaders{host: "example.com"}.apply(req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)
		require.Equal(t, http.StatusSeeOther, res.StatusCode)
		assert.Equal(t, "https://example.com/portals/test1?logout=1", res.Header.Get("Location"))
	})
}

// TestOAuth2CallbackRoundTrip drives the full sign-in flow end-to-end in dedicated sub-domain mode:
//  1. Forward-auth call from the app → 303 to the auth host's sign-in page (state cookie set with Domain=example.com)
//  2. Sign-in page → 303 to the provider start endpoint (single provider, so no template render)
//  3. Provider start → 303 to the IdP authorize URL with redirect_uri pointing at the auth host
//  4. Simulated IdP callback → 307 to the original returnURL (session cookie set with Domain=example.com)
//  5. Forward-auth call from the app, now presenting the session cookie → 200 (authenticated)
//
// This exercises the regression that motivated re-doing #47: a session cookie issued on auth.example.com
// must be readable on app.example.com, and every redirect along the way must target the right host
func TestOAuth2CallbackRoundTrip(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = []config.ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	// 1) Forward-auth call from the app — gets us a state cookie and the sign-in URL
	res1 := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.example.com", uri: "/dashboard?ref=email"}, nil)
	defer closeBody(res1)
	require.Equal(t, http.StatusSeeOther, res1.StatusCode)
	signinURL := urlMustParse(t, res1.Header.Get("Location"))
	require.Equal(t, "auth.example.com", signinURL.Host)
	stateCookies := res1.Header.Values("Set-Cookie")
	require.NotEmpty(t, stateCookies)
	for _, sc := range stateCookies {
		require.Contains(t, strings.ToLower(sc), "domain=example.com",
			"state cookie must be scoped to the parent cookie domain so auth.example.com can read it")
	}
	signinState := signinURL.Query().Get("state")
	require.NotEmpty(t, signinState)

	// 2) Sign-in page — single provider, so it 303s straight to the provider start endpoint
	res2 := doProxiedRequest(t, appClient, signinURL.RequestURI(), testProxyHeaders{host: "auth.example.com"}, stateCookies)
	defer closeBody(res2)
	require.Equal(t, http.StatusSeeOther, res2.StatusCode)
	providerURL := urlMustParse(t, res2.Header.Get("Location"))
	require.Equal(t, "/portals/test1/providers/testoauth2", providerURL.Path)

	// 3) Provider start — TFA produces an IdP authorize URL with state encoded as "provider~stateCookieID~nonce"
	res3 := doProxiedRequest(t, appClient, providerURL.RequestURI(), testProxyHeaders{host: "auth.example.com"}, stateCookies)
	defer closeBody(res3)
	require.Equal(t, http.StatusSeeOther, res3.StatusCode)
	idpURL := urlMustParse(t, res3.Header.Get("Location"))
	require.Equal(t, "idp.example.com", idpURL.Host)
	idpState := idpURL.Query().Get("state")
	require.NotEmpty(t, idpState)
	require.Equal(t, "https://auth.example.com/portals/test1/oauth2/callback", idpURL.Query().Get("redirect_uri"))

	// 4) Simulate the IdP redirecting the user back to the callback endpoint with the same state
	// The user is on auth.example.com here (the IdP redirect hits the auth host), so X-Forwarded-Host is auth.example.com
	callbackPath := "/portals/test1/oauth2/callback?state=" + url.QueryEscape(idpState) + "&code=test-code"
	res4 := doProxiedRequest(t, appClient, callbackPath, testProxyHeaders{host: "auth.example.com"}, stateCookies)
	defer closeBody(res4)
	require.Equal(t, http.StatusTemporaryRedirect, res4.StatusCode, "callback should 307 back to the original returnURL")
	assert.Equal(t, "https://app.example.com/dashboard?ref=email", res4.Header.Get("Location"),
		"post-auth redirect should preserve the original return URL including its query string")

	// The session cookie issued by the callback must be scoped to the parent domain so the app can read it on its own host
	sessionCookies := res4.Header.Values("Set-Cookie")
	require.NotEmpty(t, sessionCookies)
	cfg := config.Get()
	sessionCookieName := cfg.Cookies.CookieName("test1")
	var sessionCookie string
	for _, sc := range sessionCookies {
		if strings.HasPrefix(sc, sessionCookieName+"=") {
			sessionCookie = sc
			break
		}
	}
	require.NotEmpty(t, sessionCookie, "expected a Set-Cookie for %s in callback response", sessionCookieName)
	assert.Contains(t, strings.ToLower(sessionCookie), "domain=example.com",
		"session cookie must be scoped to the parent cookie domain so the app host can read it")

	// 5) Replay the forward-auth call from the app, this time presenting the session cookie — must authenticate
	res5 := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.example.com", uri: "/dashboard?ref=email"}, []string{sessionCookie})
	defer closeBody(res5)
	require.Equal(t, http.StatusOK, res5.StatusCode, "session cookie issued at auth.example.com should authenticate requests on app.example.com")
	assert.Equal(t, "test-user-1", res5.Header.Get("X-Forwarded-User"))
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
