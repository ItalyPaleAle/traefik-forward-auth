package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenIDConnectOAuth2AuthorizeURLIncludesPKCE(t *testing.T) {
	provider, err := newOpenIDConnectInternal(
		t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			PKCEKey:      []byte("01234567890123456789012345678901"),
		},
		// #nosec G101 - No credentials
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
		},
	)
	require.NoError(t, err)

	authURL, err := provider.OAuth2AuthorizeURL("state", "https://app.example.com/callback")
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("code_challenge"))
}

func TestOpenIDConnectExchangeCodeAndRetrieveProfileFromUserInfo(t *testing.T) {
	provider, err := newOpenIDConnectInternal(
		t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
		},
		// #nosec G101 - No credentials
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case "https://idp.example.com/token":
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
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"access-1","expires_in":3600}`)),
				}, nil
			case "https://idp.example.com/userinfo":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"sub":"user-1","name":"User One","email":"user1@example.com"}`)),
				}, nil
			default:
				return nil, assert.AnError
			}
		}),
	}

	at, err := provider.OAuth2ExchangeCode(t.Context(), "state", "code-1", "https://app.example.com/callback")
	require.NoError(t, err)
	profile, err := provider.OAuth2RetrieveProfile(t.Context(), at)
	require.NoError(t, err)
	assert.Equal(t, "user-1", profile.ID)
}

func TestOpenIDConnectRetrieveProfileFromIDToken(t *testing.T) {
	signer := newTestSigningKey(t)

	provider, err := newOpenIDConnectInternal(t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		// #nosec G101 - No credentials
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			TokenIssuer:  "https://issuer.example.com",
		},
		// #nosec G101 - No credentials
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
			JWKSUri:       "https://idp.example.com/jwks",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://idp.example.com/jwks" {
				return signer.serveJWKS(), nil
			}
			return nil, assert.AnError
		}),
	}

	now := time.Now().Unix()
	idToken := signer.SignClaims(t, map[string]any{
		"iss":  "https://issuer.example.com",
		"aud":  "cid",
		"sub":  "sub-1",
		"name": "Name",
		"exp":  now + 600,
		"iat":  now,
	})

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), OAuth2AccessToken{AccessToken: "access", IDToken: idToken})
	require.NoError(t, err)
	assert.Equal(t, "sub-1", profile.ID)
}

// TestOpenIDConnectRejectsUnsignedIDToken verifies an `alg=none` ID token is rejected
func TestOpenIDConnectRejectsUnsignedIDToken(t *testing.T) {
	signer := newTestSigningKey(t)

	// #nosec G101 - No credentials
	provider, err := newOpenIDConnectInternal(t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			TokenIssuer:  "https://issuer.example.com",
		},
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
			JWKSUri:       "https://idp.example.com/jwks",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://idp.example.com/jwks" {
				return signer.serveJWKS(), nil
			}
			return nil, assert.AnError
		}),
	}

	now := time.Now().Unix()
	idToken, err := buildUnsignedJWT(map[string]any{
		"iss": "https://issuer.example.com",
		"aud": "cid",
		"sub": "attacker",
		"exp": now + 600,
		"iat": now,
	})
	require.NoError(t, err)

	_, err = provider.OAuth2RetrieveProfile(t.Context(), OAuth2AccessToken{AccessToken: "access", IDToken: idToken})
	require.Error(t, err, "unsigned (alg=none) ID token must be rejected")
	assert.Contains(t, err.Error(), "ID token")
}

// TestOpenIDConnectRejectsIDTokenSignedWithUnknownKey verifies that an ID token whose signature is valid but signed with a key not present in the IdP's JWKS is rejected
func TestOpenIDConnectRejectsIDTokenSignedWithUnknownKey(t *testing.T) {
	signer := newTestSigningKey(t) // the IdP's published key set
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	provider, err := newOpenIDConnectInternal(t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		// #nosec G101 - No credentials
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			TokenIssuer:  "https://issuer.example.com",
		},
		// #nosec G101 - No credentials
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
			JWKSUri:       "https://idp.example.com/jwks",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://idp.example.com/jwks" {
				return signer.serveJWKS(), nil
			}
			return nil, assert.AnError
		}),
	}

	now := time.Now().Unix()
	forged := signClaimsWithKey(t, attackerKey, map[string]any{
		"iss": "https://issuer.example.com",
		"aud": "cid",
		"sub": "attacker",
		"exp": now + 600,
		"iat": now,
	})

	_, err = provider.OAuth2RetrieveProfile(t.Context(), OAuth2AccessToken{AccessToken: "access", IDToken: forged})
	require.Error(t, err, "ID token signed with a key not in the JWKS must be rejected")
	assert.Contains(t, err.Error(), "ID token")
}

// TestOpenIDConnectAcceptsValidAtHash verifies that a valid at_hash claim passes verification
func TestOpenIDConnectAcceptsValidAtHash(t *testing.T) {
	signer := newTestSigningKey(t)

	provider, err := newOpenIDConnectInternal(t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		// #nosec G101 - No credentials
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			TokenIssuer:  "https://issuer.example.com",
		},
		// #nosec G101 - No credentials
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
			JWKSUri:       "https://idp.example.com/jwks",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://idp.example.com/jwks" {
				return signer.serveJWKS(), nil
			}
			return nil, assert.AnError
		}),
	}

	const accessToken = "the-real-access-token"
	now := time.Now().Unix()
	idToken := signer.SignClaims(t, map[string]any{
		"iss":     "https://issuer.example.com",
		"aud":     "cid",
		"sub":     "sub-1",
		"exp":     now + 600,
		"iat":     now,
		"at_hash": computeTestAtHashES256(accessToken),
	})

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), OAuth2AccessToken{
		AccessToken: accessToken,
		IDToken:     idToken,
	})
	require.NoError(t, err)
	assert.Equal(t, "sub-1", profile.ID)
}

// TestOpenIDConnectRejectsAtHashMismatch verifies that an at_hash bound to a DIFFERENT access token is rejected
// This catches an attacker who swaps either the ID token or the access token for one minted under a different exchange
func TestOpenIDConnectRejectsAtHashMismatch(t *testing.T) {
	signer := newTestSigningKey(t)

	provider, err := newOpenIDConnectInternal(t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		// #nosec G101 - No credentials
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			TokenIssuer:  "https://issuer.example.com",
		},
		// #nosec G101 - No credentials
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
			JWKSUri:       "https://idp.example.com/jwks",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://idp.example.com/jwks" {
				return signer.serveJWKS(), nil
			}
			return nil, assert.AnError
		}),
	}

	now := time.Now().Unix()
	// at_hash is bound to "the-victim-access-token", but we present "attacker-supplied-token"
	idToken := signer.SignClaims(t, map[string]any{
		"iss":     "https://issuer.example.com",
		"aud":     "cid",
		"sub":     "sub-1",
		"exp":     now + 600,
		"iat":     now,
		"at_hash": computeTestAtHashES256("the-victim-access-token"),
	})

	_, err = provider.OAuth2RetrieveProfile(t.Context(), OAuth2AccessToken{
		AccessToken: "attacker-supplied-token",
		IDToken:     idToken,
	})
	require.Error(t, err, "ID token whose at_hash does not match the access_token must be rejected")
	assert.Contains(t, err.Error(), "at_hash")
}

// TestOpenIDConnectAcceptsMissingAtHash verifies that ID tokens without an at_hash claim are accepted
// The claim is OPTIONAL in the authorization-code flow per OIDC Core 3.1.3.6
func TestOpenIDConnectAcceptsMissingAtHash(t *testing.T) {
	signer := newTestSigningKey(t)

	provider, err := newOpenIDConnectInternal(t.Context(),
		"openidconnect",
		ProviderMetadata{Name: "openidconnect"},
		// #nosec G101 - No credentials
		NewOpenIDConnectOptions{
			ClientID:     "cid",
			ClientSecret: "secret",
			TokenIssuer:  "https://issuer.example.com",
		},
		// #nosec G101 - No credentials
		OAuth2Endpoints{
			Authorization: "https://idp.example.com/authorize",
			Token:         "https://idp.example.com/token",
			UserInfo:      "https://idp.example.com/userinfo",
			JWKSUri:       "https://idp.example.com/jwks",
		},
	)
	require.NoError(t, err)

	provider.httpClient = &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://idp.example.com/jwks" {
				return signer.serveJWKS(), nil
			}
			return nil, assert.AnError
		}),
	}

	now := time.Now().Unix()
	idToken := signer.SignClaims(t, map[string]any{
		"iss": "https://issuer.example.com",
		"aud": "cid",
		"sub": "sub-1",
		"exp": now + 600,
		"iat": now,
		// no at_hash
	})

	profile, err := provider.OAuth2RetrieveProfile(t.Context(), OAuth2AccessToken{
		AccessToken: "any-access-token",
		IDToken:     idToken,
	})
	require.NoError(t, err)
	assert.Equal(t, "sub-1", profile.ID)
}

func TestFetchOIDCEndpoints(t *testing.T) {
	ts := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example.com/auth","token_endpoint":"https://idp.example.com/token","userinfo_endpoint":"https://idp.example.com/userinfo"}`))
		}),
	)
	defer ts.Close()

	endpoints, err := fetchOIDCEndpoints(t.Context(), ts.URL, ts.Client(), 2*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/auth", endpoints.Authorization)
	assert.Equal(t, "https://idp.example.com/token", endpoints.Token)
	assert.Equal(t, "https://idp.example.com/userinfo", endpoints.UserInfo)
}
