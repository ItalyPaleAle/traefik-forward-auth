package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// oAuth2 is a Provider for authenticating with OAuth2.
// This Provider cannot be used directly; instead, other providers can embed this struct and implement OAuth2RetrieveProfile.
type oAuth2 struct {
	baseProvider

	config         OAuth2Config
	providerType   string
	endpoints      OAuth2Endpoints
	tokenIssuer    string
	scopes         string
	requestTimeout time.Duration
	pkceKey        []byte

	tokenExchangeParametersModifier tokenExchangeParametersModifierFn

	httpClient *http.Client
}

type OAuth2Config struct {
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
}

type OAuth2Endpoints struct {
	// Authorization URL
	Authorization string `json:"authorization_endpoint"`
	// Token URL
	Token string `json:"token_endpoint"`
	// User Info URL
	UserInfo string `json:"userinfo_endpoint"`
}

type tokenExchangeParametersModifierFn func(context.Context, url.Values) error

// NewOAuth2Options is the options for NewOAuth2
type NewOAuth2Options struct {
	Config OAuth2Config
	// Optional value for the issuer claim
	TokenIssuer string
	// Scopes for requesting the token
	// This is optional and defaults to "openid profile email"
	Scopes string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
	// Key for generating PKCE code verifiers
	// Enables the use of PKCE if non-empty
	PKCEKey []byte
	// Skip validating TLS certificates when connecting to the Identity Provider
	TLSSkipVerify bool
	// Optional, PEM-encoded CA certificate used when connecting to the Identity Provider
	TLSCACertificate []byte

	// Some providers validate client secrets separately
	skipClientSecretValidation bool
	// Allows providers to modify the parameters passed to the IdP while invoking the token endpoint
	tokenExchangeParametersModifier tokenExchangeParametersModifierFn
}

// NewOAuth2 returns a new OAuth2 provider
func NewOAuth2(providerType string, providerMetadata ProviderMetadata, opts NewOAuth2Options) (p oAuth2, err error) {
	if opts.Config.ClientID == "" {
		return p, errors.New("value for clientId is required in config for auth provider")
	}
	if opts.Config.ClientSecret == "" && !opts.skipClientSecretValidation {
		return p, errors.New("value for clientSecret is required in config for auth provider")
	}
	if providerType == "" {
		return p, errors.New("missing parameter providerType")
	}

	scopes := opts.Scopes
	if scopes == "" {
		scopes = "openid profile email"
	}
	reqTimeout := opts.RequestTimeout
	if reqTimeout < time.Second {
		reqTimeout = 10 * time.Second
	}

	// Get the HTTP transport
	httpTransport := http.DefaultTransport.(*http.Transport) //nolint:forcetypeassert
	if opts.TLSSkipVerify {
		httpTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         tls.VersionTLS12,
		}
	} else if len(opts.TLSCACertificate) > 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(opts.TLSCACertificate)
		httpTransport.TLSClientConfig = &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		}
	}

	// Update the transport for the HTTP client to include tracing information
	httpClient := &http.Client{
		Transport: otelhttp.NewTransport(httpTransport),
	}

	p = oAuth2{
		baseProvider: baseProvider{
			metadata: providerMetadata,
		},

		config:         opts.Config,
		providerType:   providerType,
		tokenIssuer:    opts.TokenIssuer,
		scopes:         scopes,
		httpClient:     httpClient,
		requestTimeout: reqTimeout,
		pkceKey:        opts.PKCEKey,

		tokenExchangeParametersModifier: opts.tokenExchangeParametersModifier,
	}
	return p, nil
}

func (a *oAuth2) SetEndpoints(endpoints OAuth2Endpoints) error {
	if !endpoints.Valid() {
		return errors.New("all endpoints must be specified")
	}

	a.endpoints = endpoints
	return nil
}

func (a *oAuth2) GetHTTPClient() *http.Client {
	return a.httpClient
}

func (a *oAuth2) GetProviderType() string {
	return a.providerType
}

func (a *oAuth2) OAuth2AuthorizeURL(state string, redirectURL string) (string, error) {
	if state == "" {
		return "", errors.New("parameter state is required")
	}

	params := url.Values{
		"client_id":     []string{a.config.ClientID},
		"redirect_uri":  []string{redirectURL},
		"response_type": []string{"code"},
		"scope":         []string{a.scopes},
		"state":         []string{state},
	}

	// Add a code challenge if PKCE is enabled
	if len(a.pkceKey) != 0 {
		codeVerifier := a.getPKCECodeVerifier(state, redirectURL)

		// Create the SHA-256 hash of the code verifier as code challenge
		codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])

		params.Add("code_challenge", codeChallenge)
		params.Add("code_challenge_method", "S256")
	}

	return a.endpoints.Authorization + "?" + params.Encode(), nil
}

func (a *oAuth2) getPKCECodeVerifier(state string, redirectURL string) string {
	// Because we don't have a place to store secrets conveniently, we won't use a random code verifier
	// Instead, we're generating a HMAC message based on other random data, using the PKCE key
	h := hmac.New(sha256.New, a.pkceKey)
	h.Write([]byte("tfa-pkce"))
	h.Write([]byte(a.config.ClientID))
	h.Write([]byte(state))
	h.Write([]byte(redirectURL))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (a *oAuth2) OAuth2ExchangeCode(ctx context.Context, state string, code string, redirectURL string) (OAuth2AccessToken, error) {
	if code == "" {
		return OAuth2AccessToken{}, errors.New("parameter code is required")
	}

	data := url.Values{
		"code":          []string{code},
		"client_id":     []string{a.config.ClientID},
		"client_secret": []string{a.config.ClientSecret},
		"redirect_uri":  []string{redirectURL},
		"grant_type":    []string{"authorization_code"},
	}

	// Add the code verifier if PKCE is enabled
	if len(a.pkceKey) != 0 {
		data.Add("code_verifier", a.getPKCECodeVerifier(state, redirectURL))
	}

	if a.tokenExchangeParametersModifier != nil {
		err := a.tokenExchangeParametersModifier(ctx, data)
		if err != nil {
			return OAuth2AccessToken{}, err
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, a.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, a.endpoints.Token, strings.NewReader(data.Encode()))
	if err != nil {
		return OAuth2AccessToken{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := a.httpClient.Do(req)
	if err != nil {
		return OAuth2AccessToken{}, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return OAuth2AccessToken{}, fmt.Errorf("invalid response status code: %d", res.StatusCode)
	}

	var tokenResponse oAuth2TokenResponse
	err = json.NewDecoder(res.Body).Decode(&tokenResponse)
	if err != nil {
		return OAuth2AccessToken{}, fmt.Errorf("invalid response body: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return OAuth2AccessToken{}, errors.New("missing access_token in response")
	}

	expires := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	return OAuth2AccessToken{
		Provider:     a.providerType,
		AccessToken:  tokenResponse.AccessToken,
		Expires:      expires,
		IDToken:      tokenResponse.IDToken,
		RefreshToken: tokenResponse.RefreshToken,
		Scopes:       strings.Split(tokenResponse.Scope, " "),
	}, nil
}

type oAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func (a *oAuth2) OAuth2RetrieveProfile(ctx context.Context, at OAuth2AccessToken) (profile *user.Profile, err error) {
	// This method needs to be implemented in structs that embed OAuth2
	panic("Method OAuth2RetrieveProfile must be implemented by a struct inheriting OAuth2")
}

// Valid returns true if all fields are set
func (e OAuth2Endpoints) Valid() bool {
	return e.Authorization != "" && e.Token != "" && e.UserInfo != ""
}

// Compile-time interface assertion
var _ OAuth2Provider = &oAuth2{}
