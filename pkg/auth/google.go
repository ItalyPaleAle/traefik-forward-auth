package auth

import (
	"errors"
	"time"
)

// Google manages authentication with Google Identity.
// It is based on the OAuth 2 provider.
type Google struct {
	OAuth2
}

// NewGoogleOptions is the options for NewGoogle
type NewGoogleOptions struct {
	BaseURL string
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

// NewGoogle returns a new Google provider
func NewGoogle(opts NewGoogleOptions) (p Google, err error) {
	if opts.ClientID == "" {
		return p, errors.New("value for clientId is required in config for auth with provider 'google'")
	}
	if opts.ClientSecret == "" {
		return p, errors.New("value for clientSecret is required in config for auth with provider 'google'")
	}

	oauth2, err := NewOAuth2(NewOAuth2Options{
		BaseURL: opts.BaseURL,
		Config: OAuth2Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
		},
		ProviderName: "google",
		Endpoints: OAuth2Endpoints{
			Authorization: "https://accounts.google.com/o/oauth2/v2/auth",
			Token:         "https://oauth2.googleapis.com/token",
			UserInfo:      "https://www.googleapis.com/oauth2/v1/userinfo",
		},
		RequestTimeout: opts.RequestTimeout,
		TokenIssuer:    "https://accounts.google.com",
	})
	if err != nil {
		return p, err
	}

	return Google{
		OAuth2: oauth2,
	}, nil
}
