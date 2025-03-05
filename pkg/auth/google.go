package auth

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// Google manages authentication with Google Identity.
// It is based on the OpenIDConnect provider.
type Google struct {
	*OpenIDConnect
	allowedDomains []string
}

// NewGoogleOptions is the options for NewGoogle
type NewGoogleOptions struct {
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// If non-empty, allows these user accounts only (matching the internal user ID)
	AllowedUsers []string
	// If non-empty, allows users with these email addresses only
	AllowedEmails []string
	// If non-empty, allows these domains only
	AllowedDomains []string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

func (o NewGoogleOptions) ToNewOpenIDConnectOptions() NewOpenIDConnectOptions {
	return NewOpenIDConnectOptions{
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		RequestTimeout: o.RequestTimeout,
		AllowedEmails:  o.AllowedEmails,
		AllowedUsers:   o.AllowedUsers,
		TokenIssuer:    "https://accounts.google.com",
	}
}

// NewGoogle returns a new Google provider
func NewGoogle(opts NewGoogleOptions) (p *Google, err error) {
	oidc, err := newOpenIDConnectInternal("google", opts.ToNewOpenIDConnectOptions(), OAuth2Endpoints{
		Authorization: "https://accounts.google.com/o/oauth2/v2/auth",
		Token:         "https://oauth2.googleapis.com/token",
		UserInfo:      "https://www.googleapis.com/oauth2/v1/userinfo",
	})
	if err != nil {
		return p, err
	}

	return &Google{
		OpenIDConnect:  oidc,
		allowedDomains: opts.AllowedDomains,
	}, nil
}

func (a *Google) UserAllowed(profile *user.Profile) error {
	// Call the implementation in the OpenIDConnect struct that checks for allowed user IDs and emails
	err := a.OpenIDConnect.UserAllowed(profile)
	if err != nil {
		return err
	}

	// Check the domain
	if len(a.allowedDomains) > 0 {
		email := profile.GetEmail()
		if email == "" {
			return errors.New("profile does not contain an email address")
		}
		idx := strings.IndexRune(email, '@')
		if idx < 0 {
			return errors.New("user's email address is invalid")
		}
		if !slices.Contains(a.allowedDomains, email[idx+1:]) {
			return errors.New("user is part of a domain that is not allowed")
		}
	}

	return nil
}

// Compile-time interface assertion
var _ OAuth2Provider = &Google{}
