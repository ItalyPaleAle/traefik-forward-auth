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
	"sync"
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

// jwksTestServer is a mock JWKS endpoint that counts the requests it receives
type jwksTestServer struct {
	mu      sync.Mutex
	key     *signingKey
	fail    bool
	fetches int
}

func (s *jwksTestServer) client() *http.Client {
	return &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			s.mu.Lock()
			defer s.mu.Unlock()

			s.fetches++
			if s.fail {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("down")),
				}, nil
			}
			return s.key.serveJWKS(), nil
		}),
	}
}

func (s *jwksTestServer) set(key *signingKey, fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = key
	s.fail = fail
}

func (s *jwksTestServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func newTestJWKSFetcher(t *testing.T, srv *jwksTestServer) *jwksFetcher {
	t.Helper()
	httpClient := srv.client()
	f, err := newJWKSFetcher(t.Context(), "https://idp.example.com/jwks", func() *http.Client { return httpClient }, time.Second)
	require.NoError(t, err)
	return f
}

// allowForcedRefresh makes the next Get behave as if the last forced refresh happened long enough ago
func allowForcedRefresh(f *jwksFetcher) {
	f.lastForcedRefresh.Store(time.Now().Add(-2 * jwksForcedRefreshInterval).UnixNano())
}

// TestJWKSFetcherRefreshesOnUnknownKeyID verifies that a token signed with a key that isn't in the cached JWKS triggers a refresh, which is what happens after the IdP rotates its keys
func TestJWKSFetcherRefreshesOnUnknownKeyID(t *testing.T) {
	oldKey := newTestSigningKeyWithID(t, "old-key")
	newKey := newTestSigningKeyWithID(t, "new-key")
	srv := &jwksTestServer{key: oldKey}
	f := newTestJWKSFetcher(t, srv)

	// The keys are fetched on first use
	set, err := f.Get(t.Context(), "old-key")
	require.NoError(t, err)
	_, ok := set.LookupKeyID("old-key")
	assert.True(t, ok)
	assert.Equal(t, 1, srv.count())

	// A known key doesn't cause a fetch
	_, err = f.Get(t.Context(), "old-key")
	require.NoError(t, err)
	assert.Equal(t, 1, srv.count())

	// The IdP rotates its keys
	srv.set(newKey, false)

	// Right after the first fetch, an unknown key doesn't cause another fetch, so tokens with made-up key IDs can't make us hammer the IdP
	set, err = f.Get(t.Context(), "new-key")
	require.NoError(t, err)
	_, ok = set.LookupKeyID("new-key")
	assert.False(t, ok)
	assert.Equal(t, 1, srv.count())

	// Once the interval has passed, the unknown key causes a refresh
	allowForcedRefresh(f)
	set, err = f.Get(t.Context(), "new-key")
	require.NoError(t, err)
	_, ok = set.LookupKeyID("new-key")
	assert.True(t, ok)
	assert.Equal(t, 2, srv.count())

	// Tokens without a key ID never cause a refresh
	allowForcedRefresh(f)
	_, err = f.Get(t.Context(), "")
	require.NoError(t, err)
	assert.Equal(t, 2, srv.count())
}

// TestJWKSFetcherFailures verifies that fetch failures are retried at most once per interval, and that the last keys fetched successfully keep being used
func TestJWKSFetcherFailures(t *testing.T) {
	key := newTestSigningKeyWithID(t, "key-1")
	srv := &jwksTestServer{key: key, fail: true}
	f := newTestJWKSFetcher(t, srv)

	// The first fetch fails
	_, err := f.Get(t.Context(), "key-1")
	require.Error(t, err)
	assert.Equal(t, 1, srv.count())

	// Within the interval, there's no new attempt
	_, err = f.Get(t.Context(), "key-1")
	require.Error(t, err)
	assert.Equal(t, 1, srv.count())

	// After the interval, the IdP has recovered and the keys are fetched
	srv.set(key, false)
	allowForcedRefresh(f)
	set, err := f.Get(t.Context(), "key-1")
	require.NoError(t, err)
	_, ok := set.LookupKeyID("key-1")
	assert.True(t, ok)
	assert.Equal(t, 2, srv.count())

	// The IdP fails again: a refresh for an unknown key fails, but the keys we already have are still returned
	srv.set(key, true)
	allowForcedRefresh(f)
	set, err = f.Get(t.Context(), "other-key")
	require.NoError(t, err)
	_, ok = set.LookupKeyID("key-1")
	assert.True(t, ok)
	assert.Equal(t, 3, srv.count())
}

// TestIDTokenKeyID verifies that the key ID is read from the token's JWS header
func TestIDTokenKeyID(t *testing.T) {
	key := newTestSigningKeyWithID(t, "my-key")
	token := key.SignClaims(t, map[string]any{"sub": "user"})

	assert.Equal(t, "my-key", idTokenKeyID([]byte(token)))
	assert.Empty(t, idTokenKeyID([]byte("not-a-jwt")))
}

// TestIdPResponseSizeIsLimited verifies that a response from the identity provider larger than maxIdPResponseSize is rejected instead of being read whole
func TestIdPResponseSizeIsLimited(t *testing.T) {
	const doc = `{"issuer":"https://issuer.example.com","authorization_endpoint":"https://issuer.example.com/authorize","token_endpoint":"https://issuer.example.com/token","userinfo_endpoint":"https://issuer.example.com/userinfo","jwks_uri":"https://issuer.example.com/jwks"}`

	newServer := func(padding int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Leading whitespace is valid JSON, so the document only fails to parse if the reader stops before reaching it
			_, _ = io.WriteString(w, strings.Repeat(" ", padding)+doc)
		}))
	}

	t.Run("within the limit", func(t *testing.T) {
		ts := newServer(maxIdPResponseSize - len(doc))
		defer ts.Close()

		endpoints, err := fetchOIDCEndpoints(t.Context(), ts.URL, ts.Client(), 2*time.Second)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.com/token", endpoints.Token)
	})

	t.Run("over the limit", func(t *testing.T) {
		ts := newServer(maxIdPResponseSize)
		defer ts.Close()

		_, err := fetchOIDCEndpoints(t.Context(), ts.URL, ts.Client(), 2*time.Second)
		require.Error(t, err)
	})
}
