package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// buildUnsignedJWT returns a JWT with `alg=none` (no signature)
// Used to verify the verifier rejects unsigned tokens — never use this to construct a "valid" token
func buildUnsignedJWT(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{
		"alg": "none",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".", nil
}

// signingKey is a generated ECDSA P-256 keypair plus its public JWK published as a one-key JWKS
type signingKey struct {
	priv    *ecdsa.PrivateKey
	jwksRaw []byte
}

// newTestSigningKey generates a fresh ECDSA P-256 key pair and serializes the public key as a JWKS suitable for serving from a mock JWKS endpoint
func newTestSigningKey(t *testing.T) *signingKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pub, err := jwk.Import[jwk.Key](priv.Public())
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "test-key-1"))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, "ES256"))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, "sig"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	raw, err := json.Marshal(set)
	require.NoError(t, err)

	return &signingKey{priv: priv, jwksRaw: raw}
}

// SignClaims signs the given claims as an ES256 JWT with the test key
func (s *signingKey) SignClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	priv, err := jwk.Import[jwk.Key](s.priv)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, "test-key-1"))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv))
	require.NoError(t, err)
	return string(signed)
}

// signClaimsWithKey signs the given claims with the provided ECDSA key
// Used to verify tokens signed with a key NOT present in the JWKS are rejected
func signClaimsWithKey(t *testing.T, priv *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		require.NoError(t, tok.Set(k, v))
	}
	jwkPriv, err := jwk.Import[jwk.Key](priv)
	require.NoError(t, err)
	require.NoError(t, jwkPriv.Set(jwk.KeyIDKey, "wrong-key"))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), jwkPriv))
	require.NoError(t, err)
	return string(signed)
}

// serveJWKS returns an http.Response that delivers the JWKS JSON
func (s *signingKey) serveJWKS() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(s.jwksRaw))),
	}
}

// computeTestAtHashES256 is the test-side mirror of computeAtHash for ES256 access tokens
// Tests use it to embed a valid at_hash claim into their signed ID tokens
func computeTestAtHashES256(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
