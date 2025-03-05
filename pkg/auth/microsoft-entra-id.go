package auth

import (
	"errors"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// MicrosoftEntraID manages authentication with Microsoft Entra ID.
// It is based on the OpenIDConnect provider.
type MicrosoftEntraID struct {
	*OpenIDConnect
}

// NewMicrosoftEntraIDOptions is the options for NewMicrosoftEntraID
type NewMicrosoftEntraIDOptions struct {
	// Tenant ID
	TenantID string
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// If non-empty, allows these user accounts only (matching the internal user ID)
	AllowedUsers []string
	// If non-empty, allows users with these email addresses only
	AllowedEmails []string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

func (o NewMicrosoftEntraIDOptions) ToNewOpenIDConnectOptions() NewOpenIDConnectOptions {
	return NewOpenIDConnectOptions{
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		RequestTimeout: o.RequestTimeout,
		AllowedEmails:  o.AllowedEmails,
		AllowedUsers:   o.AllowedUsers,
		TokenIssuer:    "https://login.microsoftonline.com/" + o.TenantID + "/v2.0",
	}
}

// NewMicrosoftEntraID returns a new MicrosoftEntraID provider
func NewMicrosoftEntraID(opts NewMicrosoftEntraIDOptions) (p *MicrosoftEntraID, err error) {
	if opts.TenantID == "" {
		return p, errors.New("value for clientId is required in config for auth with provider 'microsoft-entra-id'")
	}

	oidc, err := newOpenIDConnectInternal("microsoftentraid", opts.ToNewOpenIDConnectOptions(), OAuth2Endpoints{
		Authorization: "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/authorize",
		Token:         "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/token",
		UserInfo:      "https://graph.microsoft.com/oidc/userinfo",
	})
	if err != nil {
		return p, err
	}

	return &MicrosoftEntraID{
		OpenIDConnect: oidc,
	}, nil
}

func (a *MicrosoftEntraID) UserIDFromProfile(profile *user.Profile) string {
	if profile.Email != nil && profile.Email.Value != "" {
		return profile.Email.Value
	}
	return profile.ID
}

// Compile-time interface assertion
var _ OAuth2Provider = &MicrosoftEntraID{}
