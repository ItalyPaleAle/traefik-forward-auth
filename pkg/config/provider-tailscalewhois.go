//nolint:revive
package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/validators"
)

// ProviderConfig_TailscaleWhois is the configuration for the Tailscale Whois provider
// +name tailscalewhois
// +displayName Tailscale Whois
type ProviderConfig_TailscaleWhois struct {
	// Name of the authentication provider
	// Defaults to the name of the provider type
	// +example "my-tailscale-whois-auth"
	Name string `yaml:"name"`
	// Optional display name for the provider
	// Defaults to the standard display name for the provider
	// +example "Tailscale Whois"
	DisplayName string `yaml:"displayName"`
	// If non-empty, requires the Tailnet of the user to match this value
	// +example "yourtailnet.ts.net"
	AllowedTailnet string `yaml:"allowedTailnet"`
	// Timeout for network requests for Tailscale Whois auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// Names of capabilities to read from Tailscale peer capabilities.
	// Each capability name must be a URL-like string with a hostname and path (e.g., "example.com/capability").
	// If a capability has an https:// prefix, it will be removed. http:// prefixes are not allowed.
	// +default ["italypaleale.me/traefik-forward-auth"]
	CapabilityNames []string `yaml:"capabilityNames"`
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "tailscale"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Allowed values include all color schemes available in Tailwind 4
	// Defaults to the standard color for the provider
	// +example "slate"
	Color string `yaml:"color"`
}

func (p *ProviderConfig_TailscaleWhois) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	// Set default capability names if not provided
	capabilityNames := p.CapabilityNames
	if len(capabilityNames) == 0 {
		capabilityNames = []string{"italypaleale.me/traefik-forward-auth"}
	}

	// Validate and normalize capability names
	for i, capName := range capabilityNames {
		normalized, err := validateAndNormalizeCapabilityName(capName)
		if err != nil {
			return nil, fmt.Errorf("invalid capability name at index %d: %w", i, err)
		}
		capabilityNames[i] = normalized
	}

	return auth.NewTailscaleWhois(auth.NewTailscaleWhoisOptions{
		AllowedTailnet:  p.AllowedTailnet,
		RequestTimeout:  p.RequestTimeout,
		CapabilityNames: capabilityNames,
	})
}

func (p *ProviderConfig_TailscaleWhois) SetConfigObject(_ *Config) {
	// Nop for this provider
}

func (p *ProviderConfig_TailscaleWhois) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}

// validateAndNormalizeCapabilityName validates a capability name and normalizes it.
// It removes https:// prefix if present, returns error if http:// prefix is present,
// and validates the format is a URL with hostname and path.
func validateAndNormalizeCapabilityName(name string) (string, error) {
	// Check for and remove https:// prefix
	name = strings.TrimPrefix(name, "https://")

	// Check for http:// prefix (not allowed)
	if strings.HasPrefix(name, "http://") {
		return "", errors.New("capability name must not have http:// prefix; use https:// or omit the protocol")
	}

	// Validate the capability name format (hostname + path)
	if !validators.IsTailscaleCapabilityName(name) {
		return "", fmt.Errorf("capability name '%s' must be a URL with a hostname and path (e.g., 'example.com/capability')", name)
	}

	return name, nil
}
