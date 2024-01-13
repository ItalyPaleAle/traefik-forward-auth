package auth

import (
	"time"
)

// Google manages authentication with Google Identity.
// It is based on the OpenIDConnect provider.
type Google struct {
	OpenIDConnect
}

// NewGoogleOptions is the options for NewGoogle
type NewGoogleOptions struct {
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

func (o NewGoogleOptions) ToNewOpenIDConnectOptions() NewOpenIDConnectOptions {
	return NewOpenIDConnectOptions{
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		RequestTimeout: o.RequestTimeout,
		TokenIssuer:    "https://accounts.google.com",
	}
}

// NewGoogle returns a new Google provider
func NewGoogle(opts NewGoogleOptions) (p Google, err error) {
	oidc, err := newOpenIDConnectInternal("google", opts.ToNewOpenIDConnectOptions(), OAuth2Endpoints{
		Authorization: "https://accounts.google.com/o/oauth2/v2/auth",
		Token:         "https://oauth2.googleapis.com/token",
		UserInfo:      "https://www.googleapis.com/oauth2/v1/userinfo",
	})
	if err != nil {
		return p, err
	}

	return Google{
		OpenIDConnect: oidc,
	}, nil
}

// Compile-time interface assertion
var _ OAuth2Provider = Google{}
