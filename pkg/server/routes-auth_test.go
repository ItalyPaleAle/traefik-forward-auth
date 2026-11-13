package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
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
			srv, _ := newTestServer(t)
			require.NotNil(t, srv)
			startTestServer(t, srv)
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
			startTestServer(t, srv)
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
			req.AddCookie(&http.Cookie{Name: cookieName, Value: token}) //nolint:gosec
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
				Name:  "X-Forwarded-Groups",
				Claim: "groups",
			},
			{
				Name:  "X-Forwarded-Roles",
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
		// Groups and roles are encoded as space-separated lists
		assert.Equal(t, strings.Join(profile.Groups, " "), res.Header.Get("X-Forwarded-Groups"))
		assert.Equal(t, strings.Join(profile.Roles, " "), res.Header.Get("X-Forwarded-Roles"))
		assert.Empty(t, res.Header.Get("X-Claim-Too-Long"))
	}))
}

func TestRouteGetAuthRootInvalidCookie(t *testing.T) {
	const portalName = "test1"
	const suspiciousLogLine = "may be malformed or tampered with"

	testFn := func(cookieValue func(t *testing.T) string, expectSuspiciousLog bool) func(t *testing.T) {
		return func(t *testing.T) {
			srv, logBuf := newTestServer(t)
			require.NotNil(t, srv)
			startTestServer(t, srv)
			appClient := clientForListener(srv.appListener)

			cookieName := config.Get().Cookies.CookieName(portalName)

			// Read the current buffer
			_ = logBuf.String()

			reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d/portals/%s", testServerPort, portalName), nil)
			require.NoError(t, err)
			req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue(t)}) //nolint:gosec
			populateRequiredProxyHeaders(t, req)

			res, err := appClient.Do(req)
			require.NoError(t, err)
			defer closeBody(res)

			// The invalid cookie must lead to a redirect to sign-in, not a 401
			require.Equal(t, http.StatusSeeOther, res.StatusCode)
			locURL := urlMustParse(t, res.Header.Get("Location"))
			assert.Equal(t, "example.com", locURL.Host)
			assert.Equal(t, "/portals/"+portalName+"/signin", locURL.Path)
			assert.Contains(t, locURL.Query().Get("state"), "~")

			// The bad session cookie must be cleared
			assert.Contains(t, strings.Join(res.Header.Values("Set-Cookie"), "\n"), cookieName+"=")

			// A suspicious (malformed/tampered) cookie is logged as a warning, an expired one is not
			if expectSuspiciousLog {
				assert.Contains(t, logBuf.String(), suspiciousLogLine)
			} else {
				assert.NotContains(t, logBuf.String(), suspiciousLogLine)
			}
		}
	}

	// An expired token is well-formed and correctly signed, so it must not be logged as suspicious
	t.Run("expired token redirects to signin without warning", testFn(func(t *testing.T) string {
		return createTestSessionToken(t, portalName, createFullTestProfile(), -time.Hour)
	}, false))

	// A cookie that isn't a valid JWT may indicate tampering and must be logged as a warning
	t.Run("malformed token redirects to signin with warning", testFn(func(t *testing.T) string {
		return "not-a-valid-jwt-token"
	}, true))
}

func TestRouteGetAuthProvider(t *testing.T) {
	// Create the server
	srv, _ := newTestServer(t)
	startTestServer(t, srv)
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
	})

	t.Run("nonce mismatch redirects to signin with the cookie's nonce", func(t *testing.T) {
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

		// The request joins the sign-in from the state cookie rather than continuing to the provider
		require.Equal(t, http.StatusSeeOther, res.StatusCode)
		locURL := urlMustParse(t, res.Header.Get("Location"))
		assert.Equal(t, "/portals/test1/signin", locURL.Path)
		assert.Equal(t, state, locURL.Query().Get("state"))
		assert.Empty(t, res.Header.Values("Set-Cookie"), "the state cookie should not be deleted")
	})
}

// testProxyHeaders is a small builder for the X-Forwarded-* headers Traefik injects on each request
// All e2e tests below construct requests through it so the only varying input across modes is the host
type testProxyHeaders struct {
	host string // X-Forwarded-Host
	uri  string // X-Forwarded-URI, empty means do not set
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
	startTestServer(t, srv)
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

// TestDedicatedSubdomainRedirectsWithAuthHostPort verifies that a port included in `authHost` is preserved in the redirects to Traefik Forward Auth itself
// This covers deployments where the public endpoint is not served on the standard HTTPS port
func TestDedicatedSubdomainRedirectsWithAuthHostPort(t *testing.T) {
	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Cookies.Domain = ""
		c.Server.Domains = []config.ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com:30443"},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	startTestServer(t, srv)
	appClient := clientForListener(srv.appListener)

	res := doProxiedRequest(t, appClient, "/portals/test1", testProxyHeaders{host: "app.example.com:30443", uri: "/dashboard"}, nil)
	defer closeBody(res)

	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	signInURL := urlMustParse(t, res.Header.Get("Location"))
	assert.Equal(t, "auth.example.com:30443", signInURL.Host, "sign-in redirect should include the port configured in authHost")

	state := signInURL.Query().Get("state")
	require.NotEmpty(t, state)
	stateCookies := res.Header.Values("Set-Cookie")
	require.NotEmpty(t, stateCookies)

	res2 := doProxiedRequest(t, appClient,
		"/portals/test1/providers/testoauth2?state="+state,
		testProxyHeaders{host: "auth.example.com:30443"},
		stateCookies,
	)
	defer closeBody(res2)

	require.Equal(t, http.StatusSeeOther, res2.StatusCode)
	idpURL := urlMustParse(t, res2.Header.Get("Location"))
	assert.Equal(t, "https://auth.example.com:30443/portals/test1/oauth2/callback", idpURL.Query().Get("redirect_uri"), "OAuth2 redirect_uri should include the port configured in authHost")
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
	startTestServer(t, srv)
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
	startTestServer(t, srv)
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
	startTestServer(t, srv)
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
	startTestServer(t, srv)
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
	startTestServer(t, srv)
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
		startTestServer(t, srv)
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
		startTestServer(t, srv)
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
	startTestServer(t, srv)
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

func TestRoutePostLogout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := &Server{
		portals: map[string]*Portal{
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
		assert.Equal(t, "https://example.com/portals/test1?logout=1", rec.Header().Get("Location"))
		assert.Contains(t, rec.Body.String(), "You've been logged out. Redirecting to portal: https://example.com/portals/test1?logout=1")
	})

	t.Run("unknown portal returns not found error", func(t *testing.T) {
		c, rec := newContext("/portals/unknown/logout", "unknown")

		srv.RoutePostLogout(c)

		assert.True(t, c.IsAborted())
		require.Len(t, c.Errors, 1)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, "Error: Portal not found", rec.Body.String())
	})

	// The request host is example.com in all these cases
	crossSiteTests := []struct {
		name          string
		secFetchSite  string
		origin        string
		wantForbidden bool
	}{
		{name: "same-origin form post", secFetchSite: "same-origin", origin: "https://example.com"},
		{name: "same-origin with a port in the origin", secFetchSite: "same-origin", origin: "https://example.com:8443"},
		{name: "same-site without origin", secFetchSite: "same-site"},
		{name: "user-initiated request", secFetchSite: "none"},
		{name: "origin without sec-fetch-site", origin: "https://example.com"},
		{name: "cross-site sec-fetch-site", secFetchSite: "cross-site", wantForbidden: true},
		{name: "cross-site sec-fetch-site with matching origin", secFetchSite: "cross-site", origin: "https://example.com", wantForbidden: true},
		{name: "origin from another site", origin: "https://evil.example", wantForbidden: true},
		{name: "same-site from a host the request isn't for", secFetchSite: "same-site", origin: "https://other.example.com", wantForbidden: true},
		{name: "null origin", origin: "null", wantForbidden: true},
	}
	for _, tt := range crossSiteTests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newContext("/portals/test1/logout", "test1")
			if tt.secFetchSite != "" {
				c.Request.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}
			if tt.origin != "" {
				c.Request.Header.Set("Origin", tt.origin)
			}

			srv.RoutePostLogout(c)

			if tt.wantForbidden {
				assert.True(t, c.IsAborted())
				assert.Equal(t, http.StatusForbidden, rec.Code)
				assert.Empty(t, rec.Header().Values("Set-Cookie"), "cookies must not be deleted on a rejected request")
			} else {
				assert.Equal(t, http.StatusSeeOther, rec.Code)
			}
		})
	}

	t.Run("dedicated sub-domain accepts apps under the same domain", func(t *testing.T) {
		t.Cleanup(config.SetTestConfig(func(c *config.Config) {
			c.Cookies.Domain = ""
			c.Server.Domains = []config.ConfigServerDomain{
				{Domain: "example.com", AuthHost: "auth.example.com"},
				{Domain: "example.net", AuthHost: "auth.example.net"},
			}
		}))

		tests := []struct {
			origin        string
			wantForbidden bool
		}{
			{origin: "https://auth.example.com"},
			{origin: "https://app.example.com"},
			{origin: "https://app.example.net", wantForbidden: true},
			{origin: "https://example.org", wantForbidden: true},
		}
		for _, tt := range tests {
			c, rec := newContext("/portals/test1/logout", "test1")
			c.Request.Header.Set(headerXForwardedHost, "auth.example.com")
			c.Request.Header.Set("Sec-Fetch-Site", "same-site")
			c.Request.Header.Set("Origin", tt.origin)

			srv.RoutePostLogout(c)

			if tt.wantForbidden {
				assert.Equal(t, http.StatusForbidden, rec.Code, "origin %s", tt.origin)
			} else {
				assert.Equal(t, http.StatusSeeOther, rec.Code, "origin %s", tt.origin)
			}
		}
	})
}

func TestGetStateParam(t *testing.T) {
	const (
		validID    = "AbC-_fGhI9k"
		validNonce = "AbCdEfGhIjKl-_09"
	)

	provider := auth.NewTestProviderOAuth2()
	portal := &Portal{
		Name: "myportal",
		Providers: map[string]auth.Provider{
			provider.GetProviderName(): provider,
		},
		ProvidersList: []string{provider.GetProviderName()},
	}

	// Builds a context for a request whose "state" query string parameter is set to the value
	// When omit is true the parameter is not included at all
	makeCtx := func(state string, omit bool) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		target := "/"
		if !omit {
			target += "?" + url.Values{"state": []string{state}}.Encode()
		}
		c.Request = httptest.NewRequest(http.MethodGet, target, nil)
		return c
	}

	requireErrorCode := func(t *testing.T, err error, code int) {
		t.Helper()

		var respErr ResponseError
		require.ErrorAs(t, err, &respErr)
		assert.Equal(t, code, respErr.Code)
	}

	t.Run("without provider", func(t *testing.T) {
		t.Run("valid state", func(t *testing.T) {
			raw := validID + "~" + validNonce
			res, err := getStateParam(makeCtx(raw, false), portal, false)
			require.NoError(t, err)

			assert.Equal(t, raw, res.raw)
			assert.Equal(t, validID, res.stateCookieID)
			assert.Equal(t, validNonce, res.nonce)
			assert.Nil(t, res.provider)
		})

		t.Run("missing parameter", func(t *testing.T) {
			_, err := getStateParam(makeCtx("", true), portal, false)
			requireErrorCode(t, err, http.StatusBadRequest)
		})

		t.Run("empty parameter", func(t *testing.T) {
			_, err := getStateParam(makeCtx("", false), portal, false)
			requireErrorCode(t, err, http.StatusBadRequest)
		})

		invalid := map[string]string{
			"no separator":                  validID + validNonce,
			"empty cookie ID":               "~" + validNonce,
			"empty nonce":                   validID + "~",
			"only separator":                "~",
			"cookie ID too short":           validID[:len(validID)-1] + "~" + validNonce,
			"cookie ID too long":            validID + "A~" + validNonce,
			"nonce too short":               validID + "~" + validNonce[:len(validNonce)-1],
			"nonce too long":                validID + "~" + validNonce + "A",
			"extra separator in nonce":      validID + "~" + validNonce[:len(validNonce)-1] + "~",
			"three parts":                   "testoauth2~" + validID + "~" + validNonce,
			"HTML in cookie ID":             "<b>bold</b>~" + validNonce,
			"HTML in nonce":                 validID + "~<script>alert(1)</s>",
			"script tag with right lengths": "<script>a~" + validNonce,
			"quote in cookie ID":            `AbC"fGhI9k~` + validNonce,
			"space in nonce":                validID + "~AbCdEfGh IjKl-_0",
			"padding character":             validID + "~AbCdEfGhIjKl-_0=",
			"standard base64 plus":          validID + "~AbCdEfGhIjKl+_09",
			"standard base64 slash":         validID + "~AbCdEfGhIjKl/_09",
			"percent sign":                  validID + "~AbCdEfGhIjKl%_09",
			"null byte":                     validID + "~AbCdEfGhIjKl\x00_09",
			"non-ASCII character":           validID + "~AbCdEfGhIjKlé_0",
			"newline":                       validID + "~AbCdEfGhIjKl\n_09",
		}
		for name, state := range invalid {
			t.Run("invalid: "+name, func(t *testing.T) {
				_, err := getStateParam(makeCtx(state, false), portal, false)
				requireErrorCode(t, err, http.StatusUnauthorized)
			})
		}
	})

	t.Run("with provider", func(t *testing.T) {
		t.Run("valid state", func(t *testing.T) {
			raw := provider.GetProviderName() + "~" + validID + "~" + validNonce
			res, err := getStateParam(makeCtx(raw, false), portal, true)
			require.NoError(t, err)

			assert.Equal(t, raw, res.raw)
			assert.Equal(t, validID, res.stateCookieID)
			assert.Equal(t, validNonce, res.nonce)
			assert.Same(t, provider, res.provider)
		})

		t.Run("missing parameter", func(t *testing.T) {
			_, err := getStateParam(makeCtx("", true), portal, true)
			requireErrorCode(t, err, http.StatusBadRequest)
		})

		t.Run("no separator", func(t *testing.T) {
			_, err := getStateParam(makeCtx("testoauth2", false), portal, true)
			requireErrorCode(t, err, http.StatusUnauthorized)
		})

		unknownProviders := map[string]string{
			"unknown name":    "other",
			"empty name":      "",
			"wrong case":      "TestOAuth2",
			"HTML in name":    "<script>alert(1)</script>",
			"prefix of name":  "testoauth",
			"name with space": "testoauth2 ",
		}
		for name, providerName := range unknownProviders {
			t.Run("unknown provider: "+name, func(t *testing.T) {
				state := providerName + "~" + validID + "~" + validNonce
				_, err := getStateParam(makeCtx(state, false), portal, true)
				requireErrorCode(t, err, http.StatusConflict)
			})
		}

		t.Run("state without provider", func(t *testing.T) {
			// The cookie ID is read as the provider name, which isn't a known provider
			_, err := getStateParam(makeCtx(validID+"~"+validNonce, false), portal, true)
			requireErrorCode(t, err, http.StatusConflict)
		})

		invalid := map[string]string{
			"no cookie ID and nonce": "testoauth2~",
			"no nonce":               "testoauth2~" + validID,
			"empty cookie ID":        "testoauth2~~" + validNonce,
			"empty nonce":            "testoauth2~" + validID + "~",
			"cookie ID too short":    "testoauth2~" + validID[:5] + "~" + validNonce,
			"nonce too long":         "testoauth2~" + validID + "~" + validNonce + "A",
			"extra separator":        "testoauth2~" + validID + "~" + validNonce + "~extra",
			"HTML in cookie ID":      "testoauth2~<b>bold</b>~" + validNonce,
			"HTML in nonce":          "testoauth2~" + validID + "~<script>alert(1)</s>",
			"invalid character":      "testoauth2~" + validID + "~AbCdEfGhIjKl+_09",
		}
		for name, state := range invalid {
			t.Run("invalid: "+name, func(t *testing.T) {
				_, err := getStateParam(makeCtx(state, false), portal, true)
				requireErrorCode(t, err, http.StatusUnauthorized)
			})
		}
	})

	t.Run("accepts values generated by the server", func(t *testing.T) {
		// Guards the expected lengths against changes to how the cookie ID and nonce are generated
		stateCookieID := getStateCookieID("https://app.example.com/some/path?foo=bar")
		nonce, err := (&Server{}).generateNonce()
		require.NoError(t, err)

		raw := stateCookieID + "~" + nonce
		res, err := getStateParam(makeCtx(raw, false), portal, false)
		require.NoError(t, err)
		assert.Equal(t, stateCookieID, res.stateCookieID)
		assert.Equal(t, nonce, res.nonce)

		raw = provider.GetProviderName() + "~" + raw
		res, err = getStateParam(makeCtx(raw, false), portal, true)
		require.NoError(t, err)
		assert.Equal(t, stateCookieID, res.stateCookieID)
		assert.Equal(t, nonce, res.nonce)
	})
}

func TestIsValidStateToken(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		length int
		want   bool
	}{
		{name: "all lowercase", value: "abcdef", length: 6, want: true},
		{name: "all uppercase", value: "ABCDEF", length: 6, want: true},
		{name: "digits", value: "012345", length: 6, want: true},
		{name: "dash and underscore", value: "-_-_-_", length: 6, want: true},
		{name: "range boundaries", value: "azAZ09", length: 6, want: true},
		{name: "empty with length 0", value: "", length: 0, want: true},
		{name: "empty with non-zero length", value: "", length: 6, want: false},
		{name: "too short", value: "abcde", length: 6, want: false},
		{name: "too long", value: "abcdefg", length: 6, want: false},
		{name: "plus", value: "abcde+", length: 6, want: false},
		{name: "slash", value: "abcde/", length: 6, want: false},
		{name: "equals", value: "abcde=", length: 6, want: false},
		{name: "tilde", value: "abcde~", length: 6, want: false},
		{name: "dot", value: "abcde.", length: 6, want: false},
		{name: "space", value: "abcde ", length: 6, want: false},
		{name: "angle bracket", value: "abcde<", length: 6, want: false},
		{name: "characters adjacent to ranges", value: "@[`{:/", length: 6, want: false},
		// The multi-byte character is 2 bytes, so the string is 6 bytes long and still must be rejected
		{name: "multi-byte character", value: "abcdé", length: 6, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isValidStateToken(tc.value, tc.length))
		})
	}
}
