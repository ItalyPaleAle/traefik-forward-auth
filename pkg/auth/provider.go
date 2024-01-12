package auth

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// Provider is an interface that represents an auth provider.
type Provider interface {
	// GetProviderName returns the name of the provider
	GetProviderName() string
	// AuthorizeURL returns the URL where to redirect users to for authorization.
	AuthorizeURL(state string, redirectURL string) (string, error)
	// ExchangeCode an authorization code for an access token
	ExchangeCode(ctx context.Context, code string, redirectURL string) (AccessToken, error)
	// RetrieveProfile retrieves the user's profile, using the id_token (if present) or requesting it from the user info endpoint.
	RetrieveProfile(ctx context.Context, at AccessToken) (user.Profile, error)
	// ValidateRequestClaims validates that claims are valid for the incoming request from the client.
	ValidateRequestClaims(c *gin.Context, claims map[string]any) error
}

// AccessToken is a struct that represents an access token.
type AccessToken struct {
	Provider     string
	AccessToken  string
	Expires      time.Time
	IDToken      string
	RefreshToken string
	Scopes       []string
}
