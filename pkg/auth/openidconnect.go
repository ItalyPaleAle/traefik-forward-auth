package auth

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// ID token validation constants
const (
	// Allowed clock skew when validating exp/nbf/iat
	idTokenClockSkew = 30 * time.Second
	// How long a fetched JWKS is considered fresh
	jwksTTL = 15 * time.Minute
	// Bounds how often we retry after a fetch failure
	jwksNegativeCacheTTL = 30 * time.Second
)

// OpenIDConnect manages authentication with a generic OpenID Connect provider.
// It is based on the OAuth 2 provider.
type OpenIDConnect struct {
	oAuth2

	profileModifier profileModifierFn

	// jwks fetches and caches the IdP's signing keys for verifying ID-token signatures
	// This is nil when no JWKS URI is configured
	// In that case OAuth2RetrieveProfile falls back to invoking the UserInfo endpoint if set
	jwks *jwksFetcher
}

// jwksFetcher fetches and caches a JWKS over HTTP
// It performs an initial fetch on first use and then refreshes the keys after jwksTTL has elapsed
// Fetch failures fall back to the last known good set (when available) and are retried at most every jwksNegativeCacheTTL
type jwksFetcher struct {
	uri          string
	httpClientFn func() *http.Client
	timeout      time.Duration

	mu        sync.RWMutex
	set       jwk.Set
	fetchedAt time.Time
	lastErrAt time.Time
	lastErr   error
}

// Get returns the latest JWKS, fetching or refreshing it as needed
func (f *jwksFetcher) Get(ctx context.Context) (jwk.Set, error) {
	f.mu.RLock()
	if f.set != nil && time.Since(f.fetchedAt) < jwksTTL {
		set := f.set
		f.mu.RUnlock()
		return set, nil
	}
	f.mu.RUnlock()

	return f.refresh(ctx)
}

func (f *jwksFetcher) refresh(ctx context.Context) (jwk.Set, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Re-check after acquiring the write lock — another goroutine may have refreshed
	if f.set != nil && time.Since(f.fetchedAt) < jwksTTL {
		return f.set, nil
	}

	// Honor the negative cache so we don't hammer a struggling IdP
	if f.set == nil && f.lastErr != nil && time.Since(f.lastErrAt) < jwksNegativeCacheTTL {
		return nil, f.lastErr
	}

	fetchCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	set, err := fetchJWKS(fetchCtx, f.httpClientFn(), f.uri)
	if err != nil {
		f.lastErr = fmt.Errorf("failed to fetch JWKS from %q: %w", f.uri, err)
		f.lastErrAt = time.Now()

		// Serve a stale set if we have one — better than failing during a transient failure
		if f.set != nil {
			return f.set, nil
		}

		return nil, f.lastErr
	}

	f.set = set
	f.fetchedAt = time.Now()
	f.lastErr = nil

	return set, nil
}

// fetchJWKS retrieves and parses a JWKS from the given URI
func fetchJWKS(parentCtx context.Context, client *http.Client, uri string) (jwk.Set, error) {
	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("invalid response status code: %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return set, nil
}

type profileModifierFn struct {
	Token  func(openid.Token, *user.Profile) error
	Claims func(map[string]any, *user.Profile) error
}

// NewOpenIDConnectOptions is the options for NewOpenIDConnect
type NewOpenIDConnectOptions struct {
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// Client assertion option
	ClientAssertion string
	// Token issuer
	TokenIssuer string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
	// Scopes for requesting the token
	// This is optional and defaults to "openid profile email"
	Scopes string
	// Key for generating PKCE code verifiers
	// Enables the use of PKCE if non-empty
	PKCEKey []byte
	// Skip validating TLS certificates when connecting to the Identity Provider
	TLSSkipVerify bool
	// Optional, PEM-encoded CA certificate used when connecting to the Identity Provider
	TLSCACertificate []byte
	// Allows providers to modify the user profile
	profileModifier profileModifierFn
	// Audience for client assertion tokens
	clientAssertionAudience string
}

// NewOpenIDConnect returns a new OpenIDConnect provider
// The endpoints are resolved by retrieving the openid-configuration document from the URL of the token issuer.
func NewOpenIDConnect(ctx context.Context, opts NewOpenIDConnectOptions) (*OpenIDConnect, error) {
	if opts.ClientID == "" {
		return nil, errors.New("value for clientId is required in config for auth with provider 'openidconnect'")
	}
	if opts.ClientSecret == "" && opts.ClientAssertion == "" {
		return nil, errors.New("value for either clientSecret or clientAssertion is required in config for auth with provider 'openidconnect'")
	}
	if opts.TokenIssuer == "" {
		return nil, errors.New("value for tokenIssuer is required in config for auth with provider 'openidconnect'")
	}
	_, err := url.Parse(opts.TokenIssuer)
	if err != nil {
		return nil, fmt.Errorf("value for tokenIssuer is invalid in config for auth with provider 'openidconnect': failed to parse URL: %w", err)
	}
	if opts.RequestTimeout < time.Second {
		opts.RequestTimeout = 10 * time.Second
	}

	// Set default scopes if not specified
	if opts.Scopes == "" {
		opts.Scopes = "openid profile email"
	}

	// Get the client assertion provider (will be nil if the option is an empty string)
	clientAssertionProvider, err := getClientAssertionProvider(opts.ClientAssertion, opts.TokenIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get client assertion provider for auth with provider 'openidconnect': %w", err)
	}

	// Create the provider
	const providerType = "openidconnect"
	metadata := ProviderMetadata{
		DisplayName: "OpenID Connect",
		Name:        providerType,
		Icon:        "openid",
		Color:       "pink",
	}
	oauth2, err := NewOAuth2(providerType, metadata, NewOAuth2Options{
		Config: OAuth2Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
		},

		RequestTimeout:   opts.RequestTimeout,
		TokenIssuer:      opts.TokenIssuer,
		Scopes:           opts.Scopes,
		PKCEKey:          opts.PKCEKey,
		TLSSkipVerify:    opts.TLSSkipVerify,
		TLSCACertificate: opts.TLSCACertificate,

		clientAssertionProvider: clientAssertionProvider,
	})
	if err != nil {
		return nil, err
	}

	// Fetch the openid-configuration document and set the endpoints
	// We retry this in case of failures
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = time.Second
	bo.MaxInterval = 30 * time.Second
	endpoints, err := backoff.Retry(ctx, func() (OAuth2Endpoints, error) {
		return fetchOIDCEndpoints(ctx, opts.TokenIssuer, oauth2.GetHTTPClient(), opts.RequestTimeout)
	}, backoff.WithBackOff(bo))
	if err != nil {
		return nil, err
	}

	err = oauth2.SetEndpoints(endpoints)
	if err != nil {
		return nil, err
	}

	oidc := &OpenIDConnect{
		oAuth2:          oauth2,
		profileModifier: opts.profileModifier,
	}

	// JWKS is required for the public OIDC entrypoint: ID tokens must be verifiable
	// The discovery document is required to include `jwks_uri` per OpenID Connect Discovery 1.0
	// The fetcher is lazy: keys are fetched on first ID-token verification
	oidc.jwks, err = newJWKSFetcher(endpoints.JWKSUri, oidc.GetHTTPClient, opts.RequestTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to configure JWKS for auth with provider 'openidconnect': %w", err)
	}

	return oidc, nil
}

// newOpenIDConnectInternal returns a new OpenIDConnect provider
// It is meant to be used by structs that embed OpenIDConnect
func newOpenIDConnectInternal(_ context.Context, providerType string, providerMetadata ProviderMetadata, opts NewOpenIDConnectOptions, endpoints OAuth2Endpoints) (*OpenIDConnect, error) {
	if opts.ClientID == "" {
		return nil, fmt.Errorf("value for clientId is required in config for auth with provider '%s'", providerType)
	}
	if opts.ClientSecret == "" && opts.ClientAssertion == "" {
		return nil, fmt.Errorf("value for clientSecret or clientAssertion is required in config for auth with provider '%s'", providerType)
	}

	// Get the client assertion provider (will be nil if the option is an empty string)
	clientAssertionAudience := opts.clientAssertionAudience
	if clientAssertionAudience == "" {
		clientAssertionAudience = opts.TokenIssuer
	}
	clientAssertionProvider, err := getClientAssertionProvider(opts.ClientAssertion, clientAssertionAudience)
	if err != nil {
		return nil, fmt.Errorf("failed to get client assertion provider for auth with provider '%s': %w", providerType, err)
	}

	// Create the underlying OAuth2 provider
	oauth2, err := NewOAuth2(providerType, providerMetadata, NewOAuth2Options{
		Config: OAuth2Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
		},

		RequestTimeout:   opts.RequestTimeout,
		TokenIssuer:      opts.TokenIssuer,
		Scopes:           opts.Scopes,
		PKCEKey:          opts.PKCEKey,
		TLSSkipVerify:    opts.TLSSkipVerify,
		TLSCACertificate: opts.TLSCACertificate,

		clientAssertionProvider: clientAssertionProvider,
	})
	if err != nil {
		return nil, err
	}

	err = oauth2.SetEndpoints(endpoints)
	if err != nil {
		return nil, err
	}

	oidc := &OpenIDConnect{
		oAuth2:          oauth2,
		profileModifier: opts.profileModifier,
	}

	// If a JWKS URI is provided, configure a fetcher so we can verify ID-token signatures
	// When unset, the provider falls back to UserInfo-based profile retrieval
	if endpoints.JWKSUri != "" {
		oidc.jwks, err = newJWKSFetcher(endpoints.JWKSUri, oidc.GetHTTPClient, opts.RequestTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to configure JWKS for auth with provider '%s': %w", providerType, err)
		}
	}

	return oidc, nil
}

func (a *OpenIDConnect) OAuth2RetrieveProfile(ctx context.Context, at OAuth2AccessToken) (profile *user.Profile, err error) {
	if at.AccessToken == "" {
		return nil, errors.New("missing parameter at")
	}

	// Check if we have an ID token to get the profile from
	// We only use the ID token when we can verify its signature against a JWKS, otherwise fall through to the UserInfo endpoint, which is authenticated by the bearer access token
	if at.IDToken != "" && a.tokenIssuer != "" && a.jwks != nil {
		set, err := a.jwks.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS for ID token verification: %w", err)
		}

		// Parse and verify the ID token
		token, err := jwt.Parse(
			[]byte(at.IDToken),
			jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithIssuer(a.tokenIssuer),
			jwt.WithAudience(a.config.ClientID),
			jwt.WithAcceptableSkew(idTokenClockSkew),
			jwt.WithToken(openid.New()),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID token: %w", err)
		}
		oidToken, ok := token.(openid.Token)
		if !ok {
			return nil, errors.New("failed to parse ID token: included claims cannot be cast to openid.Token")
		}

		// Per OIDC Core 3.1.3.6: when an ID token contains an `at_hash` claim, it must equal the base64url-encoded left-half of a hash of the access_token octets, where the hash algorithm is implied by the JWS `alg`
		// The claim is OPTIONAL in the authorization-code flow but, if present, MUST be validated
		// This binds the ID token to the access token returned alongside it, so an attacker who substitutes one but not the other is caught
		err = validateAccessTokenHash([]byte(at.IDToken), oidToken, at.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to validate ID token at_hash: %w", err)
		}

		profile, err = user.NewProfileFromOpenIDToken(oidToken, a.GetProviderName())
		if err != nil {
			return nil, fmt.Errorf("invalid claims in token: %w", err)
		}

		if a.profileModifier.Token != nil {
			err = a.profileModifier.Token(oidToken, profile)
			if err != nil {
				return nil, fmt.Errorf("error from profile modifier callback: %w", err)
			}
		}

		return profile, nil
	}

	// Retrieve the profile with an API call
	if at.AccessToken == "" {
		return nil, errors.New("missing AccessToken in parameter at")
	}

	reqCtx, cancel := context.WithTimeout(ctx, a.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, a.endpoints.UserInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+at.AccessToken)

	res, err := a.GetHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response status code: %d", res.StatusCode)
	}

	claims := map[string]any{}
	err = json.NewDecoder(res.Body).Decode(&claims)
	if err != nil {
		return nil, fmt.Errorf("invalid response body: %w", err)
	}

	profile, err = user.NewProfileFromClaims(claims, a.GetProviderName())
	if err != nil {
		return nil, fmt.Errorf("invalid claims in token: %w", err)
	}

	if a.profileModifier.Claims != nil {
		err = a.profileModifier.Claims(claims, profile)
		if err != nil {
			return nil, fmt.Errorf("error from profile modifier callback: %w", err)
		}
	}

	return profile, nil
}

func fetchOIDCEndpoints(ctx context.Context, tokenIssuer string, client *http.Client, timeout time.Duration) (endpoints OAuth2Endpoints, err error) {
	var reqURL string
	if strings.HasSuffix(tokenIssuer, "/") {
		reqURL = tokenIssuer + ".well-known/openid-configuration"
	} else {
		reqURL = tokenIssuer + "/.well-known/openid-configuration"
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, reqURL, nil)
	if err != nil {
		return endpoints, fmt.Errorf("failed to create HTTP request for openid-configuration document: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		return endpoints, fmt.Errorf("failed to request openid-configuration document: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return endpoints, fmt.Errorf("failed to request openid-configuration document: invalid response status code '%d'", res.StatusCode)
	}

	err = json.NewDecoder(res.Body).Decode(&endpoints)
	if err != nil {
		return endpoints, fmt.Errorf("failed to parse response from openid-configuration document: %w", err)
	}

	if !endpoints.Valid() {
		return endpoints, errors.New("invalid openid-configuration document: not all required endpoints found")
	}

	return endpoints, nil
}

// newJWKSFetcher validates the JWKS URI and returns a lazy fetcher
// The first network call happens on first use, not at construction
// httpClientFn is invoked at fetch time so test code can swap the underlying client after provider construction without losing the JWKS path
func newJWKSFetcher(jwksURI string, httpClientFn func() *http.Client, requestTimeout time.Duration) (*jwksFetcher, error) {
	if jwksURI == "" {
		return nil, errors.New("jwks_uri is required to verify ID token signatures: the OpenID Connect discovery document did not include one")
	}

	if httpClientFn == nil {
		return nil, errors.New("an HTTP client getter is required to fetch the JWKS")
	}

	parsed, err := url.Parse(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("invalid jwks_uri %q: %w", jwksURI, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("invalid jwks_uri %q: scheme must be http or https", jwksURI)
	}

	if requestTimeout < time.Second {
		requestTimeout = 10 * time.Second
	}

	return &jwksFetcher{
		uri:          jwksURI,
		httpClientFn: httpClientFn,
		timeout:      requestTimeout,
	}, nil
}

// validateAccessTokenHash implements the OIDC Core 3.1.3.6 `at_hash` check
// It is a no-op when the ID token does not include an `at_hash` claim
// When present, it recomputes the expected hash from the access_token using the hash family implied by the JWS algorithm header and compares it against the claim in constant time
func validateAccessTokenHash(idTokenRaw []byte, idToken openid.Token, accessToken string) error {
	atHash, err := jwt.Get[string](idToken, "at_hash")
	if err != nil || atHash == "" {
		// Claim absent — nothing to validate (allowed in authorization-code flow)
		//nolint:nilerr
		return nil
	}

	if accessToken == "" {
		return errors.New("ID token contains an at_hash claim but no access_token was provided")
	}

	// Read the JWS header `alg` from the original token bytes
	// We cannot trust a value re-derived from the parsed claims, but the header was authenticated by the signature verification that already succeeded
	msg, err := jws.Parse(idTokenRaw)
	if err != nil {
		return fmt.Errorf("failed to parse ID token JWS header: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return errors.New("ID token JWS has no signatures")
	}

	alg, ok := sigs[0].ProtectedHeaders().Algorithm()
	if !ok {
		return errors.New("ID token JWS header is missing alg")
	}

	expected, err := computeAtHash(alg.String(), accessToken)
	if err != nil {
		return err
	}

	// Constant-time comparison to avoid timing leaks
	if subtle.ConstantTimeCompare([]byte(expected), []byte(atHash)) != 1 {
		return errors.New("at_hash claim does not match the access_token")
	}

	return nil
}

// computeAtHash returns the OIDC Core 3.1.3.6 `at_hash` value for the given access_token under the specified JWS algorithm
// The hash family is derived from the algorithm name: an unknown or unsupported algorithm returns an error rather than silently using a default
func computeAtHash(alg string, accessToken string) (string, error) {
	var h hash.Hash
	switch alg {
	// SHA-256 family
	case "RS256", "ES256", "PS256", "HS256":
		h = sha256.New()
	// SHA-384 family
	case "RS384", "ES384", "PS384", "HS384":
		h = sha512.New384()
	// SHA-512 family — including EdDSA, which OIDC binds to SHA-512 for at_hash
	case "RS512", "ES512", "PS512", "HS512", "EdDSA":
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported alg %q for at_hash validation", alg)
	}

	h.Write([]byte(accessToken))
	sum := h.Sum(nil)

	// Take the left-most half of the digest
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

// Compile-time interface assertion
var _ OAuth2Provider = &OpenIDConnect{}
