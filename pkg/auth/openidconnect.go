package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwt/openid"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// OpenIDConnect manages authentication with a generic OpenID Connect provider.
// It is based on the OAuth 2 provider.
type OpenIDConnect struct {
	oAuth2

	profileModifier profileModifierFn
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
	// Token issuer
	TokenIssuer string
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
	// Allows providers to modify the user profile
	profileModifier profileModifierFn
}

// NewOpenIDConnect returns a new OpenIDConnect provider
// The endpoints are resolved by retrieving the openid-configuration document from the URL of the token issuer.
func NewOpenIDConnect(ctx context.Context, opts NewOpenIDConnectOptions) (*OpenIDConnect, error) {
	if opts.ClientID == "" {
		return nil, errors.New("value for clientId is required in config for auth with provider 'openidconnect'")
	}
	if opts.ClientSecret == "" {
		return nil, errors.New("value for clientSecret is required in config for auth with provider 'openidconnect'")
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
		PKCEKey:          opts.PKCEKey,
		TLSSkipVerify:    opts.TLSSkipVerify,
		TLSCACertificate: opts.TLSCACertificate,

		skipClientSecretValidation:      opts.skipClientSecretValidation,
		tokenExchangeParametersModifier: opts.tokenExchangeParametersModifier,
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

	return &OpenIDConnect{
		oAuth2:          oauth2,
		profileModifier: opts.profileModifier,
	}, nil
}

// newOpenIDConnectInternal returns a new OpenIDConnect provider.
// It is meant to be used by structs that embed OpenIDConnect.
func newOpenIDConnectInternal(providerType string, providerMetadata ProviderMetadata, opts NewOpenIDConnectOptions, endpoints OAuth2Endpoints) (*OpenIDConnect, error) {
	if opts.ClientID == "" {
		return nil, fmt.Errorf("value for clientId is required in config for auth with provider '%s'", providerType)
	}
	if opts.ClientSecret == "" && !opts.skipClientSecretValidation {
		return nil, fmt.Errorf("value for clientSecret is required in config for auth with provider '%s'", providerType)
	}

	oauth2, err := NewOAuth2(providerType, providerMetadata, NewOAuth2Options{
		Config: OAuth2Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
		},

		RequestTimeout:   opts.RequestTimeout,
		TokenIssuer:      opts.TokenIssuer,
		PKCEKey:          opts.PKCEKey,
		TLSSkipVerify:    opts.TLSSkipVerify,
		TLSCACertificate: opts.TLSCACertificate,

		skipClientSecretValidation:      opts.skipClientSecretValidation,
		tokenExchangeParametersModifier: opts.tokenExchangeParametersModifier,
	})
	if err != nil {
		return nil, err
	}

	err = oauth2.SetEndpoints(endpoints)
	if err != nil {
		return nil, err
	}

	return &OpenIDConnect{
		oAuth2:          oauth2,
		profileModifier: opts.profileModifier,
	}, nil
}

func (a *OpenIDConnect) OAuth2RetrieveProfile(ctx context.Context, at OAuth2AccessToken) (profile *user.Profile, err error) {
	if at.AccessToken == "" {
		return nil, errors.New("missing parameter at")
	}

	// Check if we have an ID token to get the profile from
	if at.IDToken != "" && a.tokenIssuer != "" {
		// We do not verify the JWT's signature since we just retrieved it from the identity server
		// We limit ourselves to parsing it
		token, err := jwt.Parse(
			[]byte(at.IDToken),
			jwt.WithIssuer(a.tokenIssuer),
			jwt.WithAudience(a.config.ClientID),
			jwt.WithVerify(false),
			jwt.WithToken(openid.New()),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ID token: %w", err)
		}
		oidToken, ok := token.(openid.Token)
		if !ok {
			return nil, errors.New("failed to parse ID token: included claims cannot be cast to openid.Token")
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

// Compile-time interface assertion
var _ OAuth2Provider = &OpenIDConnect{}
