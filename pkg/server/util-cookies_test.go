package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

const testPortalName = "test1"

func TestSetSessionCookie(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	t.Run("success", func(t *testing.T) {
		// Create a test profile
		testProfile := &user.Profile{
			ID: "test-user-123",
			Name: user.ProfileName{
				FullName: "Test User",
			},
			Email: &user.ProfileEmail{
				Value:    "test@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
		}

		// Create a gin context for testing
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		// Test setting session cookie
		err := srv.setSessionCookie(c, testPortalName, testProfile, 2*time.Hour)
		require.NoError(t, err)

		// Check that cookie was set in response
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		cfg := config.Get()
		expectedCookieName := cfg.Cookies.CookieName(testPortalName)
		assert.Equal(t, expectedCookieName, cookies[0].Name)
		assert.NotEmpty(t, cookies[0].Value)
		assert.True(t, cookies[0].HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
		assert.Equal(t, int((2*time.Hour).Seconds())-1, cookies[0].MaxAge)
	})

	t.Run("with nil profile", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		err := srv.setSessionCookie(c, testPortalName, nil, time.Hour)
		require.Error(t, err)
		require.ErrorContains(t, err, "profile is nil")
	})

	t.Run("cookie too large", func(t *testing.T) {
		// Create a test profile with very large field values to exceed cookie size limit
		largeString := strings.Repeat("a", 2000) // 2000 characters
		testProfile := &user.Profile{
			ID: "test-user-" + largeString, // Make ID very long
			Name: user.ProfileName{
				FullName: "Test User " + largeString,
				First:    "Test " + largeString,
				Last:     "User " + largeString,
				Middle:   "Middle " + largeString,
				Nickname: "Nick " + largeString,
			},
			Email: &user.ProfileEmail{
				Value:    "test" + largeString + "@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
			Picture:  "https://example.com/picture/" + largeString,
			Locale:   "en-US-" + largeString,
			Timezone: "America/New_York-" + largeString,
			Groups:   []string{"group1-" + largeString, "group2-" + largeString},
			Roles:    []string{"role1-" + largeString, "role2-" + largeString},
			AdditionalClaims: map[string]any{
				"custom_claim_1": "value1-" + largeString,
				"custom_claim_2": "value2-" + largeString,
				"custom_claim_3": "value3-" + largeString,
			},
		}

		// Create a gin context for testing
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		// Test setting session cookie with large profile - should fail
		err := srv.setSessionCookie(c, testPortalName, testProfile, time.Hour)
		require.Error(t, err)
		require.ErrorContains(t, err, "cookie is too large and exceeds the allowed size")

		// Check that no cookie was set in response
		cookies := w.Result().Cookies()
		assert.Empty(t, cookies)
	})
}

func TestGetSessionCookie(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	t.Run("success", func(t *testing.T) {
		// First set a session cookie
		testProfile := &user.Profile{
			ID: "test-user-123",
			Name: user.ProfileName{
				FullName: "Test User",
			},
			Email: &user.ProfileEmail{
				Value:    "test@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		err := srv.setSessionCookie(c, testPortalName, testProfile, time.Hour)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		// Create a new context with the cookie for reading
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c2.Request.AddCookie(cookies[0])

		// Test getting session cookie
		profile, provider, err := srv.getSessionCookie(c2, testPortalName)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.NotNil(t, provider)

		// Verify profile data
		assert.Equal(t, testProfile.ID, profile.ID)
		assert.Equal(t, testProfile.Name, profile.Name)
		assert.Equal(t, testProfile.Email, profile.Email)
		assert.Equal(t, testProfile.Provider, profile.Provider)
	})

	t.Run("no cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		profile, provider, err := srv.getSessionCookie(c, testPortalName)
		require.NoError(t, err)
		assert.Nil(t, profile)
		assert.Nil(t, provider)
	})

	t.Run("invalid JWT token", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		cfg := config.Get()
		cookieName := cfg.Cookies.CookieName(testPortalName)

		// Add an invalid JWT cookie
		invalidCookie := &http.Cookie{
			Name:  cookieName,
			Value: "invalid.jwt.token",
		}
		c.Request.AddCookie(invalidCookie)

		profile, provider, err := srv.getSessionCookie(c, testPortalName)
		require.Error(t, err)
		assert.Nil(t, profile)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "failed to parse session token JWT")
	})

	t.Run("empty cookie value", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		cfg := config.Get()
		cookieName := cfg.Cookies.CookieName(testPortalName)

		// Add an empty cookie
		emptyCookie := &http.Cookie{
			Name:  cookieName,
			Value: "",
		}
		c.Request.AddCookie(emptyCookie)

		profile, provider, err := srv.getSessionCookie(c, testPortalName)

		// Empty cookie should return an error about the cookie being empty
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
		assert.Nil(t, profile)
		assert.Nil(t, provider)
	})
}

func TestDeleteSessionCookie(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	t.Run("success", func(t *testing.T) {
		// First set a session cookie
		testProfile := &user.Profile{
			ID: "test-user-456",
			Name: user.ProfileName{
				FullName: "Test User 2",
			},
			Email: &user.ProfileEmail{
				Value:    "test2@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		err := srv.setSessionCookie(c, testPortalName, testProfile, 2*time.Hour)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		// Create a new context with the cookie
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c2.Request.AddCookie(cookies[0])

		// Delete the session cookie
		srv.deleteSessionCookie(c2, testPortalName)

		// Check that deletion cookie was set
		deletionCookies := w2.Result().Cookies()
		require.Len(t, deletionCookies, 1)
		assert.Equal(t, cookies[0].Name, deletionCookies[0].Name)
		assert.Empty(t, deletionCookies[0].Value)
		assert.Equal(t, -1, deletionCookies[0].MaxAge)
	})

	t.Run("no existing cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		// Delete session cookie when none exists
		srv.deleteSessionCookie(c, testPortalName)

		// Should not set any deletion cookie since no cookie existed in the request
		deletionCookies := w.Result().Cookies()
		assert.Empty(t, deletionCookies)
	})
}

func TestSetStateCookie(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	portal := srv.portals[testPortalName]
	require.NotNil(t, portal, "test portal should exist")

	t.Run("success", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("User-Agent", "Test Agent")
		c.Request.Header.Set("Accept-Language", "en-US")

		// Generate a nonce
		nonce, err := srv.generateNonce()
		require.NoError(t, err)
		require.NotEmpty(t, nonce)

		testReturnURL := "https://example.com/return"
		testStateCookieID := "test-state-123"

		// Set state cookie
		err = srv.setStateCookie(c, portal, nonce, testReturnURL, testStateCookieID)
		require.NoError(t, err)

		// Check that cookie was set
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		expectedCookieName := stateCookieName(testPortalName, testStateCookieID)
		assert.Equal(t, expectedCookieName, cookies[0].Name)
		assert.NotEmpty(t, cookies[0].Value)
		assert.True(t, cookies[0].HttpOnly)
	})

	t.Run("invalid nonce", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("User-Agent", "Test Agent")

		testReturnURL := "https://example.com/return"
		testStateCookieID := "test-state-123"

		// Use invalid nonce (not base64 URL encoded)
		invalidNonce := "invalid-nonce-not-base64!"

		err := srv.setStateCookie(c, portal, invalidNonce, testReturnURL, testStateCookieID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nonce")
	})
}

func TestGetStateCookie(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	portal := srv.portals[testPortalName]
	require.NotNil(t, portal, "test portal should exist")

	t.Run("success", func(t *testing.T) {
		// First set a state cookie
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("User-Agent", "Test Agent")
		c.Request.Header.Set("Accept-Language", "en-US")

		nonce, err := srv.generateNonce()
		require.NoError(t, err)

		testReturnURL := "https://example.com/return"
		testStateCookieID := "test-state-123"

		err = srv.setStateCookie(c, portal, nonce, testReturnURL, testStateCookieID)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		// Create a new context with the cookie for reading
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c2.Request.Header.Set("User-Agent", "Test Agent")
		c2.Request.Header.Set("Accept-Language", "en-US")
		c2.Request.AddCookie(cookies[0])

		// Get state cookie
		content, err := srv.getStateCookie(c2, portal, testStateCookieID)
		require.NoError(t, err)

		assert.Equal(t, testPortalName, content.portal)
		assert.Equal(t, nonce, content.nonce)
		assert.Equal(t, testReturnURL, content.returnURL)
	})

	t.Run("no cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		content, err := srv.getStateCookie(c, portal, "nonexistent-state")
		require.NoError(t, err)
		assert.Equal(t, stateCookieContent{}, content)
	})

	t.Run("invalid JWT token", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		stateCookieID := "invalid-state"
		cookieName := stateCookieName(testPortalName, stateCookieID)

		// Add an invalid JWT cookie
		invalidCookie := &http.Cookie{
			Name:  cookieName,
			Value: "invalid.jwt.token",
		}
		c.Request.AddCookie(invalidCookie)

		_, err := srv.getStateCookie(c, portal, stateCookieID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JWT")
	})

	t.Run("wrong_user_agent", func(t *testing.T) {
		// First set a state cookie with one User-Agent
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("User-Agent", "Test Agent")
		c.Request.Header.Set("Accept-Language", "en-US")

		nonce, err := srv.generateNonce()
		require.NoError(t, err)

		testReturnURL := "https://example.com/return"
		testStateCookieID := "test-state-456"

		err = srv.setStateCookie(c, portal, nonce, testReturnURL, testStateCookieID)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		// Try to read with different User-Agent
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c2.Request.Header.Set("User-Agent", "Different Agent") // Different User-Agent
		c2.Request.Header.Set("Accept-Language", "en-US")
		c2.Request.AddCookie(cookies[0])

		content, err := srv.getStateCookie(c2, portal, testStateCookieID)
		// This should fail due to signature mismatch
		require.Error(t, err)
		assert.Equal(t, stateCookieContent{}, content)
	})

	t.Run("malformed cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		stateCookieID := "malformed-state"
		cookieName := stateCookieName(testPortalName, stateCookieID)

		// Add a malformed cookie (not even JWT format)
		malformedCookie := &http.Cookie{
			Name:  cookieName,
			Value: "not-a-jwt",
		}
		c.Request.AddCookie(malformedCookie)

		_, err := srv.getStateCookie(c, portal, stateCookieID)
		require.Error(t, err)
	})
}

func TestDeleteStateCookies(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	portal := srv.portals[testPortalName]
	require.NotNil(t, portal, "test portal should exist")

	t.Run("success multiple cookies", func(t *testing.T) {
		// Set multiple state cookies
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("User-Agent", "Test Agent")

		nonce1, err := srv.generateNonce()
		require.NoError(t, err)
		nonce2, err := srv.generateNonce()
		require.NoError(t, err)

		err = srv.setStateCookie(c, portal, nonce1, "https://example.com/1", "state1")
		require.NoError(t, err)
		err = srv.setStateCookie(c, portal, nonce2, "https://example.com/2", "state2")
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 2)

		// Create a new context with the cookies for deletion
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		for _, cookie := range cookies {
			c2.Request.AddCookie(cookie)
		}

		// Delete all state cookies
		srv.deleteStateCookies(c2, testPortalName)

		// Check that deletion cookies were set
		deletionCookies := w2.Result().Cookies()
		require.Len(t, deletionCookies, 2)

		for _, cookie := range deletionCookies {
			assert.True(t, strings.HasPrefix(cookie.Name, "tf_state_"+testPortalName+"_"))
			assert.Empty(t, cookie.Value)
			assert.Equal(t, -1, cookie.MaxAge)
		}
	})

	t.Run("no state cookies", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		// Delete state cookies when none exist
		srv.deleteStateCookies(c, testPortalName)

		// Should not set any deletion cookies
		deletionCookies := w.Result().Cookies()
		assert.Empty(t, deletionCookies)
	})

	t.Run("mixed cookies", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		// Add both state cookies and non-state cookies
		stateCookie := &http.Cookie{
			Name:  "tf_state_" + testPortalName + "_test123",
			Value: "some-value",
		}
		regularCookie := &http.Cookie{
			Name:  "regular_cookie",
			Value: "regular-value",
		}

		c.Request.AddCookie(stateCookie)
		c.Request.AddCookie(regularCookie)

		// Delete state cookies
		srv.deleteStateCookies(c, testPortalName)

		// Should only delete state cookies
		deletionCookies := w.Result().Cookies()
		require.Len(t, deletionCookies, 1)
		assert.Equal(t, stateCookie.Name, deletionCookies[0].Name)
		assert.Empty(t, deletionCookies[0].Value)
		assert.Equal(t, -1, deletionCookies[0].MaxAge)
	})
}

func TestGenerateNonce(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	nonce1, err := srv.generateNonce()
	require.NoError(t, err)
	require.NotEmpty(t, nonce1)

	nonce2, err := srv.generateNonce()
	require.NoError(t, err)
	require.NotEmpty(t, nonce2)

	// Nonces should be different
	assert.NotEqual(t, nonce1, nonce2)
}
