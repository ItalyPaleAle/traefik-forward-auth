//nolint:revive
package config

import (
	"context"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

// ProviderConfig_GitHub is the configuration for the GitHub provider
// +name github
// +displayName GitHub
type ProviderConfig_GitHub struct {
	// Name of the authentication provider
	// Defaults to the name of the provider type
	// +example "my-github-auth"
	Name string `yaml:"name"`
	// Optional display name for the provider
	// Defaults to the standard display name for the provider
	// +example "GitHub"
	DisplayName string `yaml:"displayName"`
	// Client ID for the GitHub auth application
	// +required
	// +example "your-client-id"
	ClientID string `yaml:"clientID"`
	// Client secret for the GitHub application
	// One of `clientSecret` and `clientSecretFile` is required.
	// +required
	// +example "your-client-secret"
	ClientSecret string `yaml:"clientSecret"`
	// File containing the client secret for the GitHub application
	// This is an alternative to passing the secret as `clientSecret`
	// One of `clientSecret` and `clientSecretFile` is required.
	// +example "/var/run/secrets/traefik-forward-auth/github/client-secret"
	ClientSecretFile string `yaml:"clientSecretFile"`
	// Timeout for network requests for GitHub auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "github"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Allowed values include all color schemes available in Tailwind 4
	// Defaults to the standard color for the provider
	// +example "emerald"
	Color string `yaml:"color"`
}

func (p *ProviderConfig_GitHub) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewGitHub(auth.NewGitHubOptions{
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		RequestTimeout: p.RequestTimeout,
	})
}

func (p *ProviderConfig_GitHub) SetConfigObject(_ *Config) {
	// Nop for this provider
}

func (p *ProviderConfig_GitHub) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}
