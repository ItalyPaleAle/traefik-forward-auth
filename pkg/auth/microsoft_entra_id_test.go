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

func TestMicrosoftEntraIDOAuth2FlowAndClaims(t *testing.T) {
	signer := newTestSigningKey(t)

	provider, err := NewMicrosoftEntraID(t.Context(), NewMicrosoftEntraIDOptions{
		TenantID:     "tenant-1",
		ClientID:     "cid",
		ClientSecret: "secret",
	})
	require.NoError(t, err)

	authURL, err := provider.OAuth2AuthorizeURL("st", "https://app.example.com/callback")
	require.NoError(t, err)

	u, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize", u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, "openid profile email", u.Query().Get("scope"))

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token":
				body, rErr := io.ReadAll(req.Body)
				if rErr != nil {
					return nil, rErr
				}
				vals, rErr := url.ParseQuery(string(body))
				if rErr != nil {
					return nil, rErr
				}
				if vals.Get("code") != "code-1" {
					return nil, assert.AnError
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"access-1","expires_in":3600}`)),
				}, nil
			case "https://login.microsoftonline.com/tenant-1/discovery/v2.0/keys":
				return signer.serveJWKS(), nil
			default:
				return nil, assert.AnError
			}
		}),
	}

	at, err := provider.OAuth2ExchangeCode(t.Context(), "st", "code-1", "https://app.example.com/callback")
	require.NoError(t, err)

	now := time.Now().Unix()
	at.IDToken = signer.SignClaims(t, map[string]any{
		"iss":                     "https://login.microsoftonline.com/tenant-1/v2.0",
		"aud":                     "cid",
		"sub":                     "subject-1",
		microsoftEntraIDClaimOid:  "oid-1",
		microsoftEntraIDClaimTid:  "tenant-1",
		microsoftEntraIDClaimWids: []string{"role-a", "role-b"},
		"exp":                     now + 600,
		"iat":                     now,
	})

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), at)
	require.NoError(t, err)
	assert.Equal(t, "oid-1", profile.ID)
	assert.Equal(t, "tenant-1", profile.AdditionalClaims[microsoftEntraIDClaimTid])
	assert.Equal(t, []string{"role-a", "role-b"}, profile.AdditionalClaims[microsoftEntraIDClaimWids])

	tok, err := jwt.NewBuilder().
		Claim(microsoftEntraIDClaimTid, "tenant-2").
		Claim(microsoftEntraIDClaimWids, []string{"role-x"}).
		Build()
	require.NoError(t, err)

	claims := map[string]any{}
	provider.PopulateAdditionalClaims(tok, func(k string, v any) { claims[k] = v })
	assert.Equal(t, "tenant-2", claims[microsoftEntraIDClaimTid])
	assert.Equal(t, []string{"role-x"}, claims[microsoftEntraIDClaimWids])
}
