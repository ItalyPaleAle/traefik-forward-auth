package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// Provider is the interface that represents an auth provider.
type Provider interface {
	// GetProviderName returns the name of the provider
	GetProviderName() string
	// UserIDFromProfile returns the user ID to include in the "X-Forwarded-User" header, picking the appropriate value from the profile
	UserIDFromProfile(profile *user.Profile) string
	// ValidateRequestClaims validates that claims are valid for the incoming request from the client.
	ValidateRequestClaims(r *http.Request, profile *user.Profile) error
	// PopulateAdditionalClaims allows a provider to populate the AdditionalClaims property of a Profile object.
	PopulateAdditionalClaims(claims map[string]any, setClaimFn func(key, val string))
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
	OAuth2ExchangeCode(ctx context.Context, code string, redirectURL string) (OAuth2AccessToken, error)
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
