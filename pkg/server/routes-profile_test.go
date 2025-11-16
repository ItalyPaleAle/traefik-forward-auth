package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

func TestRouteGetProfile(t *testing.T) {
	// Create the server
	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	cfg := config.Get()
	const portalName = "test1"

	t.Run("authenticated user with full profile", func(t *testing.T) {
		// Create a session token with a full profile
		profile := createFullTestProfile()
		token := createTestSessionToken(t, portalName, profile, time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request to the /portals/:portal/profile endpoint with the session cookie
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "text/plain; charset=utf-8", res.Header.Get("Content-Type"))

		// Read the response body
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		// Verify the complete content (note: additional claims are not displayed in the text format)
		expected := `Authenticated

Provider: testoauth2
ID: user123
Name:
   Full Name: John Doe
   Nickname: johnd
   First: John
   Middle: Q
   Last: Doe
Email:
   Address: john@example.com
   Verified: true
Picture: https://example.com/avatar.jpg
Locale: en-US
Timezone: America/New_York
Groups:
  - admins
  - users
Roles:
  - admin
  - editor
`
		assert.Equal(t, expected, bodyStr)
	})

	t.Run("authenticated user with minimal profile", func(t *testing.T) {
		// Create a session token with a minimal profile
		profile := &user.Profile{
			Provider: "testoauth2",
			ID:       "user456",
			Name: user.ProfileName{
				FullName: "Jane Smith",
			},
		}
		token := createTestSessionToken(t, portalName, profile, time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request to the /portals/:portal/profile endpoint
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)

		// Read the response body
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		// Verify the complete content
		expected := `Authenticated

Provider: testoauth2
ID: user456
Name:
   Full Name: Jane Smith
`
		assert.Equal(t, expected, bodyStr)
	})

	t.Run("unauthenticated user without cookie", func(t *testing.T) {
		// Make a request without a session cookie
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile", testServerPort, portalName), nil)
		require.NoError(t, err)
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
		require.Equal(t, "text/plain; charset=utf-8", res.Header.Get("Content-Type"))

		// Read the response body
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		assert.Equal(t, "Error: Not authenticated", bodyStr)
	})

	t.Run("expired session cookie", func(t *testing.T) {
		// Create an expired session token
		profile := &user.Profile{
			Provider: "testoauth2",
			ID:       "user789",
			Name: user.ProfileName{
				FullName: "Test User",
			},
		}
		token := createTestSessionToken(t, portalName, profile, -time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request with the expired cookie
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("single group and role", func(t *testing.T) {
		// Create a profile with a single group and role
		profile := &user.Profile{
			Provider: "testoauth2",
			ID:       "user_single",
			Name: user.ProfileName{
				FullName: "Single User",
			},
			Groups: []string{"developers"},
			Roles:  []string{"viewer"},
		}
		token := createTestSessionToken(t, portalName, profile, time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)

		// Read the response body
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		// Verify the complete content
		expected := `Authenticated

Provider: testoauth2
ID: user_single
Name:
   Full Name: Single User
Group: developers
Role: viewer
`
		assert.Equal(t, expected, bodyStr)
	})
}

func TestRouteGetProfileJSON(t *testing.T) {
	// Create the server
	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	cfg := config.Get()
	const portalName = "test1"

	t.Run("authenticated user with full profile", func(t *testing.T) {
		// Create a session token with a full profile
		profile := createFullTestProfile()
		token := createTestSessionToken(t, portalName, profile, time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request to the /portals/:portal/profile.json endpoint
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile.json", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "application/json; charset=utf-8", res.Header.Get("Content-Type"))

		// Parse the response body
		var response map[string]any
		err = json.NewDecoder(res.Body).Decode(&response)
		require.NoError(t, err)

		// Verify the response structure
		assert.Equal(t, true, response["authenticated"])
		assert.Equal(t, "testoauth2", response["provider"])
		assert.Equal(t, "user123", response["id"])

		// Verify name fields
		name, ok := response["name"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "John Doe", name["full"])
		assert.Equal(t, "johnd", name["nickname"])
		assert.Equal(t, "John", name["first"])
		assert.Equal(t, "Doe", name["last"])

		// Verify email
		email, ok := response["email"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "john@example.com", email["address"])
		assert.Equal(t, true, email["verified"])

		// Verify other fields
		assert.Equal(t, "https://example.com/avatar.jpg", response["picture"])
		assert.Equal(t, "en-US", response["local"])
		assert.Equal(t, "America/New_York", response["timezone"])

		// Verify groups and roles
		groups, ok := response["groups"].([]any)
		require.True(t, ok)
		assert.Len(t, groups, 2)
		assert.Contains(t, groups, "admins")
		assert.Contains(t, groups, "users")

		roles, ok := response["roles"].([]any)
		require.True(t, ok)
		assert.Len(t, roles, 2)
		assert.Contains(t, roles, "admin")
		assert.Contains(t, roles, "editor")

		// Note: Additional claims are populated by the provider's PopulateAdditionalClaims method
		// Since we're using a test provider, additional claims won't be populated from the token
	})

	t.Run("authenticated user with minimal profile", func(t *testing.T) {
		// Create a session token with a minimal profile
		profile := &user.Profile{
			Provider: "testoauth2",
			ID:       "user456",
			Name: user.ProfileName{
				FullName: "Jane Smith",
			},
		}
		token := createTestSessionToken(t, portalName, profile, time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request to the /portals/:portal/profile.json endpoint
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile.json", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)

		// Parse the response body
		var response map[string]any
		err = json.NewDecoder(res.Body).Decode(&response)
		require.NoError(t, err)

		// Verify basic fields
		assert.Equal(t, true, response["authenticated"])
		assert.Equal(t, "testoauth2", response["provider"])
		assert.Equal(t, "user456", response["id"])

		name, ok := response["name"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "Jane Smith", name["full"])

		// Verify optional fields are not present
		_, hasEmail := response["email"]
		assert.False(t, hasEmail)
		_, hasPicture := response["picture"]
		assert.False(t, hasPicture)
		_, hasGroups := response["groups"]
		assert.False(t, hasGroups)
		_, hasRoles := response["roles"]
		assert.False(t, hasRoles)
		_, hasAdditionalClaims := response["additionalClaims"]
		assert.False(t, hasAdditionalClaims)
	})

	t.Run("unauthenticated user without cookie", func(t *testing.T) {
		// Make a request without a session cookie
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile.json", testServerPort, portalName), nil)
		require.NoError(t, err)
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		assertResponseError(t, res, http.StatusUnauthorized, "Not authenticated")
	})

	t.Run("expired session cookie", func(t *testing.T) {
		// Create an expired session token
		profile := &user.Profile{
			Provider: "testoauth2",
			ID:       "user789",
			Name: user.ProfileName{
				FullName: "Test User",
			},
		}
		token := createTestSessionToken(t, portalName, profile, -time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request with the expired cookie
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile.json", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("email not verified", func(t *testing.T) {
		// Create a profile with unverified email
		profile := &user.Profile{
			Provider: "testoauth2",
			ID:       "user_unverified",
			Name: user.ProfileName{
				FullName: "Unverified User",
			},
			Email: &user.ProfileEmail{
				Value:    "unverified@example.com",
				Verified: false,
			},
		}
		token := createTestSessionToken(t, portalName, profile, time.Hour)
		cookieName := cfg.Cookies.CookieName(portalName)

		// Make a request
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/portals/%s/profile.json", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		populateRequiredProxyHeaders(t, req)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)

		// Parse the response body
		var response map[string]any
		err = json.NewDecoder(res.Body).Decode(&response)
		require.NoError(t, err)

		// Verify email is present but not verified
		email, ok := response["email"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "unverified@example.com", email["address"])
		assert.Equal(t, false, email["verified"])
	})
}

// createFullTestProfile creates a user profile with all fields populated for testing
func createFullTestProfile() *user.Profile {
	return &user.Profile{
		Provider: "testoauth2",
		ID:       "user123",
		Name: user.ProfileName{
			FullName: "John Doe",
			Nickname: "johnd",
			First:    "John",
			Middle:   "Q",
			Last:     "Doe",
		},
		Email: &user.ProfileEmail{
			Value:    "john@example.com",
			Verified: true,
		},
		Picture:  "https://example.com/avatar.jpg",
		Locale:   "en-US",
		Timezone: "America/New_York",
		Groups:   []string{"admins", "users"},
		Roles:    []string{"admin", "editor"},
	}
}
