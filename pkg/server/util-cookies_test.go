package server

import (
	"fmt"
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

	t.Run("cookie chunking for large profile", func(t *testing.T) {
		// Create a test profile with large field values that will require chunking
		// (need to exceed 3500 bytes)
		largeString := strings.Repeat("a", 1_500) // 1500 characters
		testProfile := &user.Profile{
			ID: "test-user-" + largeString,
			Name: user.ProfileName{
				FullName: "Test User " + largeString,
				First:    "Test " + largeString,
				Last:     "User " + largeString,
			},
			Email: &user.ProfileEmail{
				Value:    "test" + largeString + "@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
			Groups:   []string{"group1-" + largeString, "group2-" + largeString},
		}

		// Create a gin context for testing
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		// Test setting session cookie with large profile - should succeed with chunking
		err := srv.setSessionCookie(c, testPortalName, testProfile, time.Hour)
		require.NoError(t, err)

		// Check that multiple cookies were set (chunked)
		cookies := w.Result().Cookies()
		require.NotEmpty(t, cookies)
		t.Logf("Number of cookie chunks: %d", len(cookies))

		cfg := config.Get()
		baseCookieName := cfg.Cookies.CookieName(testPortalName)

		// Verify cookie names
		assert.Equal(t, baseCookieName, cookies[0].Name)
		if len(cookies) > 1 {
			for i := 1; i < len(cookies); i++ {
				expectedName := fmt.Sprintf("%s_%d", baseCookieName, i)
				assert.Equal(t, expectedName, cookies[i].Name)
			}
		}

		// Now test reading the chunked cookie
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		for _, cookie := range cookies {
			c2.Request.AddCookie(cookie)
		}

		// Should be able to read the chunked cookie successfully
		profile, provider, err := srv.getSessionCookie(c2, testPortalName)
		require.NoError(t, err)
		require.NotNil(t, profile)
		require.NotNil(t, provider)

		// Verify profile data matches
		assert.Equal(t, testProfile.ID, profile.ID)
		assert.Equal(t, testProfile.Name.FullName, profile.Name.FullName)
		assert.Equal(t, testProfile.Email.Value, profile.Email.Value)
	})

	t.Run("cookie too large", func(t *testing.T) {
		// Create an extremely large profile that exceeds even chunked cookie limits
		// With 250 chunks max and 3500 bytes per chunk, max is ~875,000 bytes
		// Let's create something that will definitely exceed this
		veryLargeString := strings.Repeat("a", 500_000) // 500KB string
		testProfile := &user.Profile{
			ID: "test-user-" + veryLargeString,
			Name: user.ProfileName{
				FullName: "Test User " + veryLargeString,
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

		// Test setting session cookie - should fail
		err := srv.setSessionCookie(c, testPortalName, testProfile, time.Hour)
		require.Error(t, err)
		require.ErrorContains(t, err, "cookie is too large")

		// Check that no cookies were set in response
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

	t.Run("delete chunked cookies", func(t *testing.T) {
		// Create a large profile that requires chunking
		largeString := strings.Repeat("a", 1500)
		testProfile := &user.Profile{
			ID: "test-user-chunked-delete",
			Name: user.ProfileName{
				FullName: "Test User " + largeString,
				First:    "Test " + largeString,
			},
			Email: &user.ProfileEmail{
				Value:    "test" + largeString + "@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
			Groups:   []string{"group1-" + largeString, "group2-" + largeString},
		}

		// Set the chunked cookie
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		err := srv.setSessionCookie(c, testPortalName, testProfile, time.Hour)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.NotEmpty(t, cookies)
		numChunks := len(cookies)
		t.Logf("Created %d cookie chunks", numChunks)

		// Create a new context with all the cookie chunks
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		for _, cookie := range cookies {
			c2.Request.AddCookie(cookie)
		}

		// Delete the chunked cookies
		srv.deleteSessionCookie(c2, testPortalName)

		// Check that all chunks were deleted
		deletionCookies := w2.Result().Cookies()
		require.Len(t, deletionCookies, numChunks, "should delete all cookie chunks")

		// Verify all deletion cookies have MaxAge = -1
		for _, cookie := range deletionCookies {
			assert.Empty(t, cookie.Value)
			assert.Equal(t, -1, cookie.MaxAge)
		}
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

func TestTokenCaching(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	t.Run("valid token is cached", func(t *testing.T) {
		// Create a test profile
		testProfile := &user.Profile{
			ID: "test-user-cache-1",
			Name: user.ProfileName{
				FullName: "Cache Test User",
			},
			Email: &user.ProfileEmail{
				Value:    "cache@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
		}

		// Set a session cookie
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		err := srv.setSessionCookie(c, testPortalName, testProfile, time.Hour)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		cookieValue := cookies[0].Value

		// First parse - should validate and cache
		token1, err := srv.parseSessionToken(cookieValue, testPortalName)
		require.NoError(t, err)
		require.NotNil(t, token1)

		// Compute cache key
		cacheKey := srv.tokenCacheKey(cookieValue)

		// Verify validation result is in the cache
		valid, ok := srv.tokenCache.Get(cacheKey)
		require.True(t, ok, "token validation result should be in cache")
		require.True(t, valid, "cached validation result should be true")

		// Second parse - should use cache
		token2, err := srv.parseSessionToken(cookieValue, testPortalName)
		require.NoError(t, err)
		require.NotNil(t, token2)

		// Verify both tokens have the same subject (user ID)
		sub1, _ := token1.Subject()
		sub2, _ := token2.Subject()
		assert.Equal(t, sub1, sub2)
	})

	t.Run("invalid token is cached", func(t *testing.T) {
		const invalidToken = "invalid.jwt.token.value" //nolint:gosec

		// First parse - should fail and cache the error
		token1, err := srv.parseSessionToken(invalidToken, testPortalName)
		require.Error(t, err)
		require.Nil(t, token1)

		// Compute cache key
		cacheKey := srv.tokenCacheKey(invalidToken)

		// Verify the validation failure is in the cache
		valid, ok := srv.tokenCache.Get(cacheKey)
		require.True(t, ok, "validation result should be in cache")
		require.False(t, valid, "cached validation result should be false")

		// Second parse - should return cached error
		token2, err := srv.parseSessionToken(invalidToken, testPortalName)
		require.Error(t, err)
		require.Nil(t, token2)
	})

	t.Run("cache TTL respects token expiration", func(t *testing.T) {
		// Create a test profile with short expiration
		testProfile := &user.Profile{
			ID: "test-user-cache-ttl",
			Name: user.ProfileName{
				FullName: "TTL Test User",
			},
			Email: &user.ProfileEmail{
				Value:    "ttl@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
		}

		// Set a session cookie with 2 minute expiration (minimum is 1 minute)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		const shortExpiration = 2 * time.Minute
		err := srv.setSessionCookie(c, testPortalName, testProfile, shortExpiration)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		cookieValue := cookies[0].Value

		// Parse the token
		token, err := srv.parseSessionToken(cookieValue, testPortalName)
		require.NoError(t, err)
		require.NotNil(t, token)

		// Check the TTL computation for valid token
		ttl := computeTokenCacheTTL(token, false)

		// TTL should be less than or equal to the token expiration
		// and also less than 5 minutes (max cache TTL)
		assert.LessOrEqual(t, ttl, shortExpiration+time.Second)
		assert.LessOrEqual(t, ttl, 5*time.Minute)
	})

	t.Run("cache TTL for invalid tokens is 5 minutes", func(t *testing.T) {
		const invalidToken = "another.invalid.token" //nolint:gosec

		// Parse invalid token
		_, err := srv.parseSessionToken(invalidToken, testPortalName)
		require.Error(t, err)

		// Check that the TTL for invalid tokens is 5 minutes
		ttl := computeTokenCacheTTL(nil, true)
		assert.Equal(t, 5*time.Minute, ttl)
	})

	t.Run("cache uses SHA-256 hash as key", func(t *testing.T) {
		testToken := "test.token.value"

		// Compute cache key
		cacheKey := srv.tokenCacheKey(testToken)

		// Verify it's a valid base64 string of the right length (43 chars for 32 bytes using RawURLEncoding)
		assert.Len(t, cacheKey, 43)

		// Verify it's consistent
		cacheKey2 := srv.tokenCacheKey(testToken)
		assert.Equal(t, cacheKey, cacheKey2)

		// Verify different tokens produce different keys
		cacheKey3 := srv.tokenCacheKey("different.token.value")
		assert.NotEqual(t, cacheKey, cacheKey3)
	})
}

func TestGetSessionCookieWithCache(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	t.Run("getSessionCookie uses cached token", func(t *testing.T) {
		// Create a test profile
		testProfile := &user.Profile{
			ID: "test-user-cache-2",
			Name: user.ProfileName{
				FullName: "Cache Test User 2",
			},
			Email: &user.ProfileEmail{
				Value:    "cache2@example.com",
				Verified: true,
			},
			Provider: "testoauth2",
		}

		// Set a session cookie
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest(http.MethodGet, "/", nil)

		err := srv.setSessionCookie(c, testPortalName, testProfile, time.Hour)
		require.NoError(t, err)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)

		cfg := config.Get()
		cookieName := cfg.Cookies.CookieName(testPortalName)
		cookieValue := cookies[0].Value

		// First call - should parse and cache
		w2 := httptest.NewRecorder()
		c2, _ := gin.CreateTestContext(w2)
		c2.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c2.Request.AddCookie(&http.Cookie{
			Name:  cookieName,
			Value: cookieValue,
		})

		profile1, provider1, err := srv.getSessionCookie(c2, testPortalName)
		require.NoError(t, err)
		require.NotNil(t, profile1)
		require.NotNil(t, provider1)

		// Verify token is in cache
		cacheKey := srv.tokenCacheKey(cookieValue)
		_, ok := srv.tokenCache.Get(cacheKey)
		require.True(t, ok, "token should be in cache after first call")

		// Second call - should use cached token
		w3 := httptest.NewRecorder()
		c3, _ := gin.CreateTestContext(w3)
		c3.Request, _ = http.NewRequest(http.MethodGet, "/", nil)
		c3.Request.AddCookie(&http.Cookie{
			Name:  cookieName,
			Value: cookieValue,
		})

		profile2, provider2, err := srv.getSessionCookie(c3, testPortalName)
		require.NoError(t, err)
		require.NotNil(t, profile2)
		require.NotNil(t, provider2)

		// Verify profiles match
		assert.Equal(t, profile1.ID, profile2.ID)
		assert.Equal(t, profile1.Name, profile2.Name)
		assert.Equal(t, profile1.Email, profile2.Email)
	})
}
