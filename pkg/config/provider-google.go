//nolint:revive
package config

import (
	"context"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

// ProviderConfig_Google is the configuration for the Google provider
// +name google
// +displayName Google
type ProviderConfig_Google struct {
	// Name of the authentication provider
	// Defaults to the name of the provider type
	// +example "my-google-auth"
	Name string `yaml:"name"`
	// Optional display name for the provider
	// Defaults to the standard display name for the provider
	// +example "Google"
	DisplayName string `yaml:"displayName"`
	// Client ID for the Google auth application
	// +required
	// +example "your-google-client-id.apps.googleusercontent.com"
	ClientID string `yaml:"clientID"`
	// Client secret for the Google auth application
	// One of `clientSecret` and `clientSecretFile` is required.
	// +required
	// +example "your-client-secret"
	ClientSecret string `yaml:"clientSecret"`
	// File containing the client secret for the Google auth application
	// This is an alternative to passing the secret as `clientSecret`
	// One of `clientSecret` and `clientSecretFile` is required.
	// +example "/var/run/secrets/traefik-forward-auth/google/client-secret"
	ClientSecretFile string `yaml:"clientSecretFile"`
	// Timeout for network requests for Google auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// OAuth2 scopes to request
	// +default "openid profile email"
	Scopes string `yaml:"scopes"`
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "google"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Allowed values include all color schemes available in Tailwind 4
	// Defaults to the standard color for the provider
	// +example "yellow"
	Color string `yaml:"color"`

	config *Config
}

func (p *ProviderConfig_Google) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	opts := auth.NewGoogleOptions{
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		RequestTimeout: p.RequestTimeout,
		Scopes:         p.Scopes,
		Hostname:       p.config.Server.Hostname,
		BasePath:       p.config.Server.BasePath,
	}
	err := populateSecretFromFile(&opts.ClientSecret, p.ClientSecretFile)
	if err != nil {
		return nil, err
	}

	return auth.NewGoogle(opts)
}

func (p *ProviderConfig_Google) SetConfigObject(c *Config) {
	p.config = c
}

func (p *ProviderConfig_Google) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}
