package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

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
		invalidToken := "invalid.jwt.token.value"

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

		shortExpiration := 2 * time.Minute
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
		ttl := srv.computeTokenCacheTTL(token, false)

		// TTL should be less than or equal to the token expiration
		// and also less than 5 minutes (max cache TTL)
		assert.LessOrEqual(t, ttl, shortExpiration+time.Second)
		assert.LessOrEqual(t, ttl, 5*time.Minute)
	})

	t.Run("cache TTL for invalid tokens is 5 minutes", func(t *testing.T) {
		invalidToken := "another.invalid.token"

		// Parse invalid token
		_, err := srv.parseSessionToken(invalidToken, testPortalName)
		require.Error(t, err)

		// Check that the TTL for invalid tokens is 5 minutes
		ttl := srv.computeTokenCacheTTL(nil, true)
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
