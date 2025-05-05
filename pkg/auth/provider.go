package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// Provider is the interface that represents an auth provider.
type Provider interface {
	// GetProviderType returns the type of the provider
	GetProviderType() string
	// UserIDFromProfile returns the ID of the user, picking the appropriate value from the profile
	UserIDFromProfile(profile *user.Profile) string
	// ValidateRequestClaims validates that claims are valid for the incoming request from the client.
	ValidateRequestClaims(r *http.Request, profile *user.Profile) error
	// PopulateAdditionalClaims allows a provider to populate the AdditionalClaims property of a Profile object.
	PopulateAdditionalClaims(token jwt.Token, setClaimFn func(key, val string))
	// UserAllowed checks if the user can authenticate based on allowlists and other rules.
	UserAllowed(profile *user.Profile) error

	// SetProviderMetadata sets the metadata for the provider.
	SetProviderMetadata(m ProviderMetadata)
	// GetProviderName returns the provider name.
	GetProviderName() string
	// GetProviderDisplayName returns the provider display name.
	GetProviderDisplayName() string
	// GetProviderIcon returns the provider icon.
	GetProviderIcon() string
	// GetProviderColor returns the provider color.
	GetProviderColor() string
}

// ProviderMetadata includes metadata info for the auth provider.
type ProviderMetadata struct {
	Name        string
	DisplayName string
	Icon        string
	Color       string
}

// SeamlessProvider is the interface that represents an auth provider that performs authentication based on flows that do not require user action, such as network.
type SeamlessProvider interface {
	Provider

	// SeamlessAuth performs seamless authentication for the HTTP request.
	SeamlessAuth(r *http.Request) (*user.Profile, error)
}

// OAuth2Provider is the interface that represents an auth provider that is based on OAuth2.
type OAuth2Provider interface {
	Provider

	// OAuth2AuthorizeURL returns the URL where to redirect users to for authorization.
	OAuth2AuthorizeURL(state string, redirectURL string) (string, error)
	// OAuth2ExchangeCode an authorization code for an access token
	OAuth2ExchangeCode(ctx context.Context, state string, code string, redirectURL string) (OAuth2AccessToken, error)
	// OAuth2RetrieveProfile retrieves the user's profile, using the id_token (if present) or requesting it from the user info endpoint.
	OAuth2RetrieveProfile(ctx context.Context, at OAuth2AccessToken) (*user.Profile, error)
}

// OAuth2AccessToken is a struct that represents an access token.
type OAuth2AccessToken struct {
	Provider     string
	AccessToken  string
	Expires      time.Time
	IDToken      string
	RefreshToken string
	Scopes       []string
}

// AuthenticatedUserFromProfile returns the user information to include in the "X-Authenticated-User" header
func AuthenticatedUserFromProfile(provider Provider, profile *user.Profile) string {
	userID, _ := json.Marshal(provider.UserIDFromProfile(profile))
	// The provider name is already guaranteed to not include characters that must be escaped as JSON
	return `{"provider":"` + provider.GetProviderName() + `","user":` + string(userID) + `}`
}
