package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

// These tests cover sign-ins started by several browser tabs at the same time
// Each test replays a specific interleaving of requests and responses, using testCookieJar to apply Set-Cookie headers in the order the browser receives them

const concurrentTestReturnURL = "https://example.com/app"

// tabResponse holds the parts of a response that the tests check
// The body is closed as soon as the response is received, since the tests never read it
type tabResponse struct {
	StatusCode int
	Header     http.Header
}

// testCookieJar simulates a browser's cookie jar for a single site
type testCookieJar map[string]string

// apply stores the cookies set by the response, and removes the ones it deletes
func (j testCookieJar) apply(t *testing.T, res tabResponse) {
	t.Helper()

	for _, sc := range res.Header.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(sc)
		require.NoError(t, err)

		if cookie.MaxAge < 0 {
			delete(j, cookie.Name)
		} else {
			j[cookie.Name] = cookie.Value
		}
	}
}

// snapshot returns the cookies the browser would send with its next request, as "name=value" pairs
func (j testCookieJar) snapshot() []string {
	res := make([]string, 0, len(j))
	for k, v := range j {
		res = append(res, k+"="+v)
	}
	return res
}

// stateCookies returns the names of the state cookies in the jar
func (j testCookieJar) stateCookies() []string {
	res := []string{}
	for k := range j {
		if strings.HasPrefix(k, stateCookieNamePrefix+"_") {
			res = append(res, k)
		}
	}
	return res
}

// newConcurrentTestServer starts a test server whose only portal uses the given test provider
func newConcurrentTestServer(t *testing.T, provider string) *http.Client {
	t.Helper()

	t.Cleanup(config.SetTestConfig(func(c *config.Config) {
		c.Portals = []config.ConfigPortal{
			{
				Name:        "test1",
				DisplayName: "Test 1",
				Providers: []config.ConfigPortalProvider{
					{TestProvider: new(provider)},
				},
				AuthenticationTimeout: 10 * time.Second,
			},
		}
	}))

	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	startTestServer(t, srv)
	return clientForListener(srv.appListener)
}

// doTabRequest issues a GET request from a browser tab, sending the given "name=value" cookie pairs
func doTabRequest(t *testing.T, client *http.Client, path string, p testProxyHeaders, cookies []string) tabResponse {
	t.Helper()

	reqCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf("http://localhost:%d%s", testServerPort, path), nil)
	require.NoError(t, err)
	p.apply(req)

	// The "testseamless" provider identifies the user with this header, and other routes ignore it
	req.Header.Set("X-Seamless-User", "test-user-1")

	for _, c := range cookies {
		req.Header.Add("Cookie", c)
	}

	res, err := client.Do(req)
	require.NoError(t, err)
	defer closeBody(res)

	return tabResponse{
		StatusCode: res.StatusCode,
		Header:     res.Header,
	}
}

// redirectTarget returns the path and query of the response's Location header, so the redirect can be followed against the test server
func redirectTarget(t *testing.T, res tabResponse) string {
	t.Helper()
	return urlMustParse(t, res.Header.Get("Location")).RequestURI()
}

// startConcurrentSignins replays the start of the sequence from issue 70
// Two tabs load the same protected URL at the same time without a session, and each starts a sign-in with its own nonce
// The two state cookies have the same name, so the browser keeps only the one from tab 1, which it received last
// Both tabs then load the sign-in page with that cookie, and must continue with the same sign-in
// It returns the responses from the sign-in page for tab 1 and tab 2
func startConcurrentSignins(t *testing.T, client *http.Client, jar testCookieJar) (signin1 tabResponse, signin2 tabResponse) {
	t.Helper()

	app := testProxyHeaders{host: "example.com", uri: "/app"}
	direct := testProxyHeaders{host: "example.com"}

	root2 := doTabRequest(t, client, "/portals/test1", app, nil)
	root1 := doTabRequest(t, client, "/portals/test1", app, nil)
	require.Equal(t, http.StatusSeeOther, root2.StatusCode)
	require.Equal(t, http.StatusSeeOther, root1.StatusCode)
	require.NotEqual(t, root1.Header.Get("Location"), root2.Header.Get("Location"), "each tab should start a sign-in with its own nonce")

	jar.apply(t, root2)
	jar.apply(t, root1)
	require.Len(t, jar.stateCookies(), 1, "both tabs should share a single state cookie name")

	// Both requests are sent before either response is received
	cookies := jar.snapshot()
	signin2 = doTabRequest(t, client, redirectTarget(t, root2), direct, cookies)
	signin1 = doTabRequest(t, client, redirectTarget(t, root1), direct, cookies)
	require.Equal(t, http.StatusSeeOther, signin2.StatusCode)
	require.Equal(t, http.StatusSeeOther, signin1.StatusCode)
	assert.True(t, strings.HasPrefix(urlMustParse(t, signin1.Header.Get("Location")).Path, "/portals/test1/providers/"), "the sign-in page should forward to the only provider")
	require.Equal(t, signin1.Header.Get("Location"), signin2.Header.Get("Location"), "tab 2 should join the sign-in from the state cookie")

	jar.apply(t, signin2)
	jar.apply(t, signin1)
	require.Len(t, jar.stateCookies(), 1, "the sign-in page should not delete the state cookie")

	return signin1, signin2
}

func TestConcurrentSigninSameReturnURL(t *testing.T) {
	app := testProxyHeaders{host: "example.com", uri: "/app"}
	direct := testProxyHeaders{host: "example.com"}

	t.Run("seamless provider", func(t *testing.T) {
		client := newConcurrentTestServer(t, "testseamless")
		jar := testCookieJar{}

		signin1, signin2 := startConcurrentSignins(t, client, jar)

		// Tab 1 finishes first
		res1 := doTabRequest(t, client, redirectTarget(t, signin1), direct, jar.snapshot())
		require.Equal(t, http.StatusSeeOther, res1.StatusCode)
		assert.Equal(t, concurrentTestReturnURL, res1.Header.Get("Location"))
		jar.apply(t, res1)

		// Tab 2 finishes after the browser has stored tab 1's response
		// This used to fail because completing tab 1's sign-in deleted the state cookie
		res2 := doTabRequest(t, client, redirectTarget(t, signin2), direct, jar.snapshot())
		require.Equal(t, http.StatusSeeOther, res2.StatusCode)
		assert.Equal(t, concurrentTestReturnURL, res2.Header.Get("Location"))
		jar.apply(t, res2)

		// The browser now has a session
		final := doTabRequest(t, client, "/portals/test1", app, jar.snapshot())
		assert.Equal(t, http.StatusOK, final.StatusCode)
	})

	t.Run("oauth2 provider", func(t *testing.T) {
		client := newConcurrentTestServer(t, "testoauth2")
		jar := testCookieJar{}

		signin1, signin2 := startConcurrentSignins(t, client, jar)

		// Both tabs are sent to the identity provider with the same state
		idp1 := doTabRequest(t, client, redirectTarget(t, signin1), direct, jar.snapshot())
		idp2 := doTabRequest(t, client, redirectTarget(t, signin2), direct, jar.snapshot())
		require.Equal(t, http.StatusSeeOther, idp1.StatusCode)
		require.Equal(t, http.StatusSeeOther, idp2.StatusCode)
		state1 := urlMustParse(t, idp1.Header.Get("Location")).Query().Get("state")
		state2 := urlMustParse(t, idp2.Header.Get("Location")).Query().Get("state")
		require.NotEmpty(t, state1)
		require.Equal(t, state1, state2)

		// Tab 1's callback arrives first
		cb1 := doTabRequest(t, client, "/portals/test1/oauth2/callback?code=code-1&state="+url.QueryEscape(state1), direct, jar.snapshot())
		require.Equal(t, http.StatusTemporaryRedirect, cb1.StatusCode)
		assert.Equal(t, concurrentTestReturnURL, cb1.Header.Get("Location"))
		jar.apply(t, cb1)

		// Tab 2's callback arrives after the browser has stored tab 1's response
		cb2 := doTabRequest(t, client, "/portals/test1/oauth2/callback?code=code-2&state="+url.QueryEscape(state2), direct, jar.snapshot())
		require.Equal(t, http.StatusTemporaryRedirect, cb2.StatusCode)
		assert.Equal(t, concurrentTestReturnURL, cb2.Header.Get("Location"))
		jar.apply(t, cb2)

		// The browser now has a session
		final := doTabRequest(t, client, "/portals/test1", app, jar.snapshot())
		assert.Equal(t, http.StatusOK, final.StatusCode)
	})
}

// TestOAuth2CallbackNonceMismatchRestartsSignin covers a tab that reaches the identity provider before another tab overwrites the shared state cookie
// The first tab's callback can't be completed, so it must restart from the return URL and join the other tab's sign-in, without deleting the state cookie
func TestOAuth2CallbackNonceMismatchRestartsSignin(t *testing.T) {
	client := newConcurrentTestServer(t, "testoauth2")
	jar := testCookieJar{}
	app := testProxyHeaders{host: "example.com", uri: "/app"}
	direct := testProxyHeaders{host: "example.com"}

	// Tab 1 starts a sign-in and is sent to the identity provider
	root1 := doTabRequest(t, client, "/portals/test1", app, nil)
	jar.apply(t, root1)
	signin1 := doTabRequest(t, client, redirectTarget(t, root1), direct, jar.snapshot())
	jar.apply(t, signin1)
	idp1 := doTabRequest(t, client, redirectTarget(t, signin1), direct, jar.snapshot())
	require.Equal(t, http.StatusSeeOther, idp1.StatusCode)
	state1 := urlMustParse(t, idp1.Header.Get("Location")).Query().Get("state")
	require.NotEmpty(t, state1)

	// Tab 2's request was sent before tab 1's state cookie was stored, so it starts a separate sign-in and its state cookie replaces tab 1's
	root2 := doTabRequest(t, client, "/portals/test1", app, nil)
	jar.apply(t, root2)
	signin2URL := root2.Header.Get("Location")

	// Tab 1's callback no longer matches the state cookie
	cb1 := doTabRequest(t, client, "/portals/test1/oauth2/callback?code=code-1&state="+url.QueryEscape(state1), direct, jar.snapshot())
	require.Equal(t, http.StatusSeeOther, cb1.StatusCode)
	assert.Equal(t, concurrentTestReturnURL, cb1.Header.Get("Location"), "tab 1 should restart from its return URL")
	assert.Empty(t, cb1.Header.Values("Set-Cookie"), "no session should be created and the state cookie should not be deleted")
	jar.apply(t, cb1)

	// Following the redirect, tab 1 joins tab 2's sign-in
	restart := doTabRequest(t, client, "/portals/test1", app, jar.snapshot())
	require.Equal(t, http.StatusSeeOther, restart.StatusCode)
	assert.Equal(t, signin2URL, restart.Header.Get("Location"))
}

// TestCompletedSigninConsumesStateCookie checks that the state cookie is kept only briefly after its sign-in completes, and that its nonce isn't used to start a new sign-in
func TestCompletedSigninConsumesStateCookie(t *testing.T) {
	client := newConcurrentTestServer(t, "testseamless")
	jar := testCookieJar{}
	app := testProxyHeaders{host: "example.com", uri: "/app"}
	direct := testProxyHeaders{host: "example.com"}

	// Complete a sign-in
	root := doTabRequest(t, client, "/portals/test1", app, nil)
	jar.apply(t, root)
	signin := doTabRequest(t, client, redirectTarget(t, root), direct, jar.snapshot())
	jar.apply(t, signin)
	res := doTabRequest(t, client, redirectTarget(t, signin), direct, jar.snapshot())
	require.Equal(t, http.StatusSeeOther, res.StatusCode)
	require.Equal(t, concurrentTestReturnURL, res.Header.Get("Location"))

	// The state cookie is set again with a short lifetime instead of being deleted
	var stateCookie *http.Cookie
	for _, sc := range res.Header.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(sc)
		require.NoError(t, err)
		if strings.HasPrefix(cookie.Name, stateCookieNamePrefix+"_") {
			stateCookie = cookie
		}
	}
	require.NotNil(t, stateCookie, "expected the state cookie to be set again")
	assert.Positive(t, stateCookie.MaxAge)
	assert.LessOrEqual(t, stateCookie.MaxAge, int(stateCookieConsumedLifetime.Seconds()))

	// A new sign-in for the same return URL, without the session cookie, must not re-use the consumed nonce
	newRoot := doTabRequest(t, client, "/portals/test1", app, []string{stateCookie.Name + "=" + stateCookie.Value})
	require.Equal(t, http.StatusSeeOther, newRoot.StatusCode)
	oldState := urlMustParse(t, root.Header.Get("Location")).Query().Get("state")
	newState := urlMustParse(t, newRoot.Header.Get("Location")).Query().Get("state")
	require.NotEmpty(t, newState)
	assert.NotEqual(t, oldState, newState)
}

// TestCompletedSigninKeepsOtherStateCookies covers two tabs signing in on different return URLs at the same time
// Completing the first sign-in used to delete every state cookie for the portal, which broke the second tab's callback
func TestCompletedSigninKeepsOtherStateCookies(t *testing.T) {
	client := newConcurrentTestServer(t, "testoauth2")
	jar := testCookieJar{}
	direct := testProxyHeaders{host: "example.com"}

	// Each tab starts a sign-in on its own URL and is sent to the identity provider
	startSignin := func(uri string) string {
		root := doTabRequest(t, client, "/portals/test1", testProxyHeaders{host: "example.com", uri: uri}, nil)
		jar.apply(t, root)
		signin := doTabRequest(t, client, redirectTarget(t, root), direct, jar.snapshot())
		jar.apply(t, signin)
		idp := doTabRequest(t, client, redirectTarget(t, signin), direct, jar.snapshot())
		require.Equal(t, http.StatusSeeOther, idp.StatusCode)
		return urlMustParse(t, idp.Header.Get("Location")).Query().Get("state")
	}
	stateA := startSignin("/a")
	stateB := startSignin("/b")
	require.Len(t, jar.stateCookies(), 2)

	// Tab A finishes first, and must leave tab B's state cookie alone
	cbA := doTabRequest(t, client, "/portals/test1/oauth2/callback?code=code-a&state="+url.QueryEscape(stateA), direct, jar.snapshot())
	require.Equal(t, http.StatusTemporaryRedirect, cbA.StatusCode)
	assert.Equal(t, "https://example.com/a", cbA.Header.Get("Location"))
	jar.apply(t, cbA)
	require.Len(t, jar.stateCookies(), 2)

	// Tab B can still finish
	cbB := doTabRequest(t, client, "/portals/test1/oauth2/callback?code=code-b&state="+url.QueryEscape(stateB), direct, jar.snapshot())
	require.Equal(t, http.StatusTemporaryRedirect, cbB.StatusCode)
	assert.Equal(t, "https://example.com/b", cbB.Header.Get("Location"))
}
