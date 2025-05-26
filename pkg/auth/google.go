package auth

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwt/openid"
	"github.com/spf13/cast"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

const googleClaimDomain = "hd"

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

		// Profile modifier functions that add the "hd" claim
		// This is set by Google on accounts that belong to an organization and indicates the domain of the org
		// https://developers.google.com/identity/openid-connect/openid-connect
		profileModifier: profileModifierFn{
			Token: func(token openid.Token, profile *user.Profile) error {
				var v string
				if token.Get(googleClaimDomain, &v) == nil && v != "" {
					profile.SetAdditionalClaim(googleClaimDomain, v)
				}
				return nil
			},
			Claims: func(claims map[string]any, profile *user.Profile) error {
				v := cast.ToString(claims[googleClaimDomain])
				if v != "" {
					profile.SetAdditionalClaim(googleClaimDomain, v)
				}
				return nil
			},
		},
	}
}

// NewGoogle returns a new Google provider
func NewGoogle(opts NewGoogleOptions) (*Google, error) {
	const providerType = "google"
	metadata := ProviderMetadata{
		DisplayName: "Google",
		Name:        providerType,
		Icon:        "google",
		Color:       "red-to-yellow",
	}
	oidc, err := newOpenIDConnectInternal(providerType, metadata, opts.ToNewOpenIDConnectOptions(), OAuth2Endpoints{
		Authorization: "https://accounts.google.com/o/oauth2/v2/auth",
		Token:         "https://oauth2.googleapis.com/token",
		UserInfo:      "https://www.googleapis.com/oauth2/v1/userinfo",
	})
	if err != nil {
		return nil, err
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

func (a *Google) PopulateAdditionalClaims(token jwt.Token, setClaimFn func(key, val string)) {
	var val string

	if token.Get(googleClaimDomain, &val) == nil && val != "" {
		setClaimFn(googleClaimDomain, val)
	}
}

// Compile-time interface assertion
var _ OAuth2Provider = &Google{}
