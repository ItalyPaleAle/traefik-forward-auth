package auth

import (
	"errors"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// MicrosoftEntraID manages authentication with Microsoft Entra ID.
// It is based on the OAuth 2 provider.
type MicrosoftEntraID struct {
	OAuth2
}

// NewMicrosoftEntraIDOptions is the options for NewMicrosoftEntraID
type NewMicrosoftEntraIDOptions struct {
	// Tenant ID
	TenantID string
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

// NewMicrosoftEntraID returns a new MicrosoftEntraID provider
func NewMicrosoftEntraID(opts NewMicrosoftEntraIDOptions) (p MicrosoftEntraID, err error) {
	if opts.TenantID == "" {
		return p, errors.New("value for clientId is required in config for auth with provider 'microsoft-entra-id'")
	}
	if opts.ClientID == "" {
		return p, errors.New("value for clientId is required in config for auth with provider 'microsoft-entra-id'")
	}
	if opts.ClientSecret == "" {
		return p, errors.New("value for clientSecret is required in config for auth with provider 'microsoft-entra-id'")
	}

	oauth2, err := NewOAuth2("microsoftentraid", NewOAuth2Options{
		Config: OAuth2Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
		},
		Endpoints: OAuth2Endpoints{
			Authorization: "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/authorize",
			Token:         "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/token",
			UserInfo:      "https://graph.microsoft.com/oidc/userinfo",
		},
		RequestTimeout: opts.RequestTimeout,
		TokenIssuer:    "https://login.microsoftonline.com/" + opts.TenantID + "/v2.0",
	})
	if err != nil {
		return p, err
	}

	return MicrosoftEntraID{
		OAuth2: oauth2,
	}, nil
}

func (a MicrosoftEntraID) UserIDFromProfile(profile *user.Profile) string {
	if profile.Email != nil && profile.Email.Value != "" {
		return profile.Email.Value
	}
	return profile.ID
}

// Compile-time interface assertion
var _ OAuth2Provider = MicrosoftEntraID{}
