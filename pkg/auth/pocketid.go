package auth

import (
	"errors"
	"strings"
	"time"
)

// PocketID manages authentication with Pocket ID.
// It is based on the OpenIDConnect provider.
type PocketID struct {
	*OpenIDConnect
}

// NewPocketIDOptions is the options for NewPocketID
type NewPocketIDOptions struct {
	// Server endpoint
	Endpoint string
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
	// Scopes for requesting the token
	// This is optional and defaults to "openid profile email groups"
	Scopes string
	// Key for generating PKCE code verifiers
	// Enables the use of PKCE if non-empty
	PKCEKey []byte
	// Client assertion option
	ClientAssertion string
	// Skip validating TLS certificates when connecting to the Identity Provider
	TLSSkipVerify bool
	// Optional, PEM-encoded CA certificate used when connecting to the Identity Provider
	TLSCACertificate []byte
	// Server's hostname
	Hostname string
	// Server's base path (could be empty)
	BasePath string
}

func (o NewPocketIDOptions) ToNewOpenIDConnectOptions() NewOpenIDConnectOptions {
	return NewOpenIDConnectOptions{
		ClientID:         o.ClientID,
		ClientSecret:     o.ClientSecret,
		RequestTimeout:   o.RequestTimeout,
		Scopes:           o.Scopes,
		TokenIssuer:      o.Endpoint,
		PKCEKey:          o.PKCEKey,
		ClientAssertion:  o.ClientAssertion,
		TLSSkipVerify:    o.TLSSkipVerify,
		TLSCACertificate: o.TLSCACertificate,
		Hostname:         o.Hostname,
		BasePath:         o.BasePath,

		// When there's a client assertion, use the endpoint as audience for the tokens
		clientAssertionAudience: o.Endpoint,
	}
}

// NewPocketID returns a new PocketID provider
func NewPocketID(opts NewPocketIDOptions) (*PocketID, error) {
	// Remove the trailing slash if present
	opts.Endpoint = strings.TrimRight(opts.Endpoint, "/")

	if opts.Endpoint == "" {
		return nil, errors.New("value for endpoint is required in config for auth with provider 'pocket-id'")
	}
	if opts.ClientID == "" {
		return nil, errors.New("value for clientID is required in config for auth with provider 'pocket-id'")
	}
	if opts.ClientSecret == "" && opts.ClientAssertion == "" {
		return nil, errors.New("value for either clientSecret or clientAssertion is required in config for auth with provider 'pocket-id'")
	}

	oidcOpts := opts.ToNewOpenIDConnectOptions()
	// Set default scopes if not specified
	if oidcOpts.Scopes == "" {
		oidcOpts.Scopes = "openid profile email groups"
	}

	const providerType = "pocketid"
	metadata := ProviderMetadata{
		DisplayName: "Pocket ID",
		Name:        providerType,
		Icon:        "pocketid",
		Color:       "zinc",
	}
	oidc, err := newOpenIDConnectInternal(providerType, metadata, oidcOpts, OAuth2Endpoints{
		Authorization: opts.Endpoint + "/authorize",
		Token:         opts.Endpoint + "/api/oidc/token",
		UserInfo:      opts.Endpoint + "/api/oidc/userinfo",
	})
	if err != nil {
		return nil, err
	}

	a := &PocketID{
		OpenIDConnect: oidc,
	}

	return a, nil
}

// Compile-time interface assertion
var _ OAuth2Provider = &PocketID{}
