package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// testGetAPIVerifyResponse is a test-only version of GetAPIVerifyResponse with Claims as a map
type testGetAPIVerifyResponse struct {
	Valid    bool           `json:"valid"`
	Portal   string         `json:"portal"`
	Provider string         `json:"provider"`
	Claims   map[string]any `json:"claims"`
}

func TestRouteGetAPIVerify(t *testing.T) {
	// Create the server
	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	cfg := config.Get()
	const portalName = "test1"

	profile := &user.Profile{
		Provider: "testoauth2",
		ID:       "test@example.com",
	}

	t.Run("valid token with bearer prefix", func(t *testing.T) {
		// Create a valid session token
		token := createTestSessionToken(t, portalName, profile, time.Hour)

		// Make a request to the /api/portals/:portal/verify endpoint
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "application/json; charset=utf-8", res.Header.Get("Content-Type"))

		// Parse the response body
		var response testGetAPIVerifyResponse
		err = json.NewDecoder(res.Body).Decode(&response)
		require.NoError(t, err)

		// Verify the response
		assert.True(t, response.Valid)
		assert.Equal(t, portalName, response.Portal)
		assert.Equal(t, "testoauth2", response.Provider)
		assert.NotNil(t, response.Claims)

		// Verify claims are present
		assert.Equal(t, "test@example.com", response.Claims["sub"])
		assert.Equal(t, []any{cfg.GetTokenAudienceClaim()}, response.Claims["aud"])
		assert.Equal(t, "testoauth2", response.Claims["tf_provider"])
	})

	t.Run("valid token without bearer prefix", func(t *testing.T) {
		// Create a valid session token
		token := createTestSessionToken(t, portalName, profile, time.Hour)

		// Make a request without the "Bearer" prefix
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", token)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusOK, res.StatusCode)

		// Parse the response body
		var response testGetAPIVerifyResponse
		err = json.NewDecoder(res.Body).Decode(&response)
		require.NoError(t, err)

		// Verify the response
		assert.True(t, response.Valid)
		assert.Equal(t, portalName, response.Portal)
		assert.Equal(t, "testoauth2", response.Provider)
	})

	t.Run("missing authorization header", func(t *testing.T) {
		// Make a request without an Authorization header
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		assertResponseError(t, res, http.StatusUnauthorized, "Not authenticated")
	})

	t.Run("empty authorization header", func(t *testing.T) {
		// Make a request with an empty Authorization header
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "")

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		assertResponseError(t, res, http.StatusUnauthorized, "Not authenticated")
	})

	t.Run("invalid token", func(t *testing.T) {
		// Make a request with an invalid token
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer invalid-token-123")

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
		require.Equal(t, "application/json", res.Header.Get("Content-Type"))

		// Parse the response body
		data := struct {
			Error string `json:"error"`
		}{}
		err = json.NewDecoder(res.Body).Decode(&data)
		require.NoError(t, err)
		assert.Equal(t, "Access token is invalid", data.Error)
	})

	t.Run("expired token", func(t *testing.T) {
		// Create an expired session token
		token := createTestSessionToken(t, portalName, profile, -time.Hour)

		// Make a request with the expired token
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Parse the response body
		data := struct {
			Error string `json:"error"`
		}{}
		err = json.NewDecoder(res.Body).Decode(&data)
		require.NoError(t, err)
		assert.Equal(t, "Access token is invalid", data.Error)
	})

	t.Run("token missing provider claim", func(t *testing.T) {
		// Create a token without the provider claim
		cfg := config.Get()
		now := time.Now()
		builder := jwt.NewBuilder()
		token, err := builder.
			Issuer(jwtIssuer + ":" + cfg.GetTokenAudienceClaim() + ":" + portalName).
			Audience([]string{cfg.GetTokenAudienceClaim()}).
			Subject("test@example.com").
			IssuedAt(now).
			Expiration(now.Add(time.Hour)).
			NotBefore(now).
			Build()
		require.NoError(t, err)

		// Sign the token
		tokenBytes, err := jwt.NewSerializer().
			Sign(jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey())).
			Serialize(token)
		require.NoError(t, err)

		// Make a request with the token
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+string(tokenBytes))

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Parse the response body
		data := struct {
			Error string `json:"error"`
		}{}
		err = json.NewDecoder(res.Body).Decode(&data)
		require.NoError(t, err)
		assert.Equal(t, "Access token is invalid", data.Error)
	})

	t.Run("token for wrong portal", func(t *testing.T) {
		// Create a token for a different portal
		const wrongPortal = "different-portal"
		token := createTestSessionToken(t, wrongPortal, profile, time.Hour)

		// Make a request to the test1 portal with a token for a different portal
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response - should fail because the issuer won't match
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)

		// Parse the response body
		data := struct {
			Error string `json:"error"`
		}{}
		err = json.NewDecoder(res.Body).Decode(&data)
		require.NoError(t, err)
		assert.Equal(t, "Access token is invalid", data.Error)
	})

	t.Run("invalid portal name", func(t *testing.T) {
		// Create a valid token
		token := createTestSessionToken(t, portalName, profile, time.Hour)

		// Make a request to a non-existent portal
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, "nonexistent"), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, http.StatusNotFound, res.StatusCode)
	})

	t.Run("bearer prefix case insensitive", func(t *testing.T) {
		// Create a valid session token
		token := createTestSessionToken(t, portalName, profile, time.Hour)

		testCases := []string{
			"BEARER " + token,
			"bearer " + token,
			"BeArEr " + token,
		}

		for _, authHeader := range testCases {
			t.Run(authHeader[:6], func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("http://localhost:%d/api/portals/%s/verify", testServerPort, portalName), nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", authHeader)

				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				// Check the response
				require.Equal(t, http.StatusOK, res.StatusCode)

				// Parse the response body
				var response testGetAPIVerifyResponse
				err = json.NewDecoder(res.Body).Decode(&response)
				require.NoError(t, err)

				// Verify the response
				assert.True(t, response.Valid)
			})
		}
	})
}
