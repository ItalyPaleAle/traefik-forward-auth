package auth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoogleOAuth2FlowAndClaims(t *testing.T) {
	signer := newTestSigningKey(t)

	provider, err := NewGoogle(t.Context(), NewGoogleOptions{
		ClientID:     "cid",
		ClientSecret: "secret",
	})
	require.NoError(t, err)

	authURL, err := provider.OAuth2AuthorizeURL("state-1", "https://app.example.com/callback")
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth", u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, "openid profile email", u.Query().Get("scope"))

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://oauth2.googleapis.com/token":
				body, readErr := io.ReadAll(req.Body)
				if readErr != nil {
					return nil, readErr
				}
				vals, parseErr := url.ParseQuery(string(body))
				if parseErr != nil {
					return nil, parseErr
				}
				if vals.Get("code") != "code-1" {
					return nil, assert.AnError
				}
				if vals.Get("client_id") != "cid" {
					return nil, assert.AnError
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"access-1","expires_in":3600,"scope":"openid email"}`)),
				}, nil
			case "https://www.googleapis.com/oauth2/v3/certs":
				return signer.serveJWKS(), nil
			default:
				return nil, assert.AnError
			}
		}),
	}

	at, err := provider.OAuth2ExchangeCode(t.Context(), "state-1", "code-1", "https://app.example.com/callback")
	require.NoError(t, err)
	assert.Equal(t, "access-1", at.AccessToken)

	now := time.Now().Unix()
	at.IDToken = signer.SignClaims(t, map[string]any{
		"iss":             "https://accounts.google.com",
		"aud":             "cid",
		"sub":             "sub-1",
		"name":            "Google User",
		"email":           "user@example.com",
		googleClaimDomain: "example.com",
		"exp":             now + 600,
		"iat":             now,
	})

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), at)
	require.NoError(t, err)
	assert.Equal(t, "sub-1", profile.ID)
	assert.Equal(t, "example.com", profile.AdditionalClaims[googleClaimDomain])

	tok, err := jwt.NewBuilder().Claim(googleClaimDomain, "example.org").Build()
	require.NoError(t, err)
	claims := map[string]any{}
	provider.PopulateAdditionalClaims(tok, func(k string, v any) { claims[k] = v })
	assert.Equal(t, "example.org", claims[googleClaimDomain])
}
