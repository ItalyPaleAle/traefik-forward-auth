package auth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPocketIDOAuth2Flow(t *testing.T) {
	provider, err := NewPocketID(t.Context(), NewPocketIDOptions{
		Endpoint:     "https://pocket.example.com/",
		ClientID:     "cid",
		ClientSecret: "secret",
	})
	require.NoError(t, err)

	authURL, err := provider.OAuth2AuthorizeURL("st", "https://app.example.com/callback")
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, "https://pocket.example.com/authorize", u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, "openid profile email groups", u.Query().Get("scope"))

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://pocket.example.com/api/oidc/token":
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

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"at","expires_in":60}`)),
				}, nil
			case "https://pocket.example.com/api/oidc/userinfo":
				if req.Header.Get("Authorization") != "Bearer at" {
					return nil, assert.AnError
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"sub":"u1","name":"Pocket User"}`)),
				}, nil
			default:
				return nil, assert.AnError
			}
		}),
	}

	at, err := provider.OAuth2ExchangeCode(t.Context(), "st", "code-1", "https://app.example.com/callback")
	require.NoError(t, err)

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), at)
	require.NoError(t, err)
	assert.Equal(t, "u1", profile.ID)
	assert.Equal(t, "Pocket User", profile.Name.FullName)
}
