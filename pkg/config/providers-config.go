//nolint:revive
package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

var testProviderConfigFactory map[string]func() ProviderConfig

type ProviderConfig interface {
	GetAuthProvider(ctx context.Context) (auth.Provider, error)
	SetConfigObject(c *Config)
	GetProviderMetadata() auth.ProviderMetadata
}

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
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "google"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Defaults to the standard color for the provider
	// +example "yellow"
	Color string `yaml:"color"`
}

func (p *ProviderConfig_Google) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	opts := auth.NewGoogleOptions{
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		RequestTimeout: p.RequestTimeout,
	}
	err := populateSecretFromFile(&opts.ClientSecret, p.ClientSecretFile)
	if err != nil {
		return nil, err
	}

	return auth.NewGoogle(opts)
}

func (p *ProviderConfig_Google) SetConfigObject(_ *Config) {
	// Nop for this provider
}

func (p *ProviderConfig_Google) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}

// ProviderConfig_MicrosoftEntraID is the configuration for the Microsoft Entra ID provider
// +name microsoftentraid
// +displayName Microsoft Entra ID
type ProviderConfig_MicrosoftEntraID struct {
	// Name of the authentication provider
	// Defaults to the name of the provider type
	// +example "my-microsoft-entra-id-auth"
	Name string `yaml:"name"`
	// Optional display name for the provider
	// Defaults to the standard display name for the provider
	// +example "Microsoft Entra ID"
	DisplayName string `yaml:"displayName"`
	// Tenant ID for the Microsoft Entra ID auth application
	// +required
	// +example
	TenantID string `yaml:"tenantID"`
	// Client ID for the Microsoft Entra ID auth application
	// +required
	// +example "your-client-id"
	ClientID string `yaml:"clientID"`
	// Client secret for the Microsoft Entra ID auth application
	// Required when not using Federated Identity Credentials
	// +example "your-client-secret"
	ClientSecret string `yaml:"clientSecret"`
	// File containing the client secret for the Microsoft Entra ID application.
	// This is an alternative to passing the secret as `clientSecret`
	// +example "/var/run/secrets/traefik-forward-auth/microsoft-entra-id/client-secret"
	ClientSecretFile string `yaml:"clientSecretFile"`
	// Enables the usage of Federated Identity Credentials to obtain assertions for confidential clients for Microsoft Entra ID applications.
	// This is an alternative to using client secrets, when the application is running in Azure in an environment that supports Managed Identity, or in an environment that supports Workload Identity Federation with Microsoft Entra ID.
	// Currently, these values are supported:
	//
	// - `ManagedIdentity`: uses a system-assigned managed identity
	// - `ManagedIdentity=client-id`: uses a user-assigned managed identity with client id "client-id" (e.g. "ManagedIdentity=00000000-0000-0000-0000-000000000000")
	// - `WorkloadIdentity`: uses workload identity, e.g. for Kubernetes
	AzureFederatedIdentity string `yaml:"azureFederatedIdentity"`
	// Timeout for network requests for Microsoft Entra ID auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "microsoft"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Defaults to the standard color for the provider
	// +example "cyan"
	Color string `yaml:"color"`

	config *Config
}

func (p *ProviderConfig_MicrosoftEntraID) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	opts := auth.NewMicrosoftEntraIDOptions{
		TenantID:               p.TenantID,
		ClientID:               p.ClientID,
		ClientSecret:           p.ClientSecret,
		AzureFederatedIdentity: p.AzureFederatedIdentity,
		RequestTimeout:         p.RequestTimeout,
		PKCEKey:                p.config.internal.pkceKey,
	}
	err := populateSecretFromFile(&opts.ClientSecret, p.ClientSecretFile)
	if err != nil {
		return nil, err
	}

	return auth.NewMicrosoftEntraID(opts)
}

func (p *ProviderConfig_MicrosoftEntraID) SetConfigObject(c *Config) {
	p.config = c
}

func (p *ProviderConfig_MicrosoftEntraID) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}

// ProviderConfig_OpenIDConnect is the configuration for the OpenID Connect provider
// +name openidconnect
// +displayName OpenID Connect
type ProviderConfig_OpenIDConnect struct {
	// Name of the authentication provider
	// Defaults to the name of the provider type
	// +example "my-openid-auth"
	Name string `yaml:"name"`
	// Optional display name for the provider
	// Defaults to the standard display name for the provider
	// +example "OpenID Connect"
	DisplayName string `yaml:"displayName"`
	// Client ID for the OpenID Connect application
	// +required
	// +example "your-client-id"
	ClientID string `yaml:"clientID"`
	// Client secret for the OpenID Connect application
	// +required
	// +example "your-client-secret"
	ClientSecret string `yaml:"clientSecret"`
	// File containing the client secret for the OpenID Connect application
	// This is an alternative to passing the secret as `clientSecret`
	// +example "/var/run/secrets/traefik-forward-auth/openidconnect/client-secret"
	ClientSecretFile string `yaml:"clientSecretFile"`
	// OpenID Connect token issuer
	// The OpenID Connect configuration document will be fetched at `<token-issuer>/.well-known/openid-configuration`
	// +required
	// +example "https://id.external-example.com"
	TokenIssuer string `yaml:"tokenIssuer"`
	// Timeout for network requests for OpenID Connect auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// If true, enables the use of PKCE during the code exchange.
	// +default false
	EnablePKCE bool `yaml:"enablePKCE"`
	// If true, skips validating TLS certificates when connecting to the OpenID Connect Identity Provider.
	// +default false
	TLSInsecureSkipVerify bool `yaml:"tlsInsecureSkipVerify"`
	// Optional PEM-encoded CA certificate to trust when connecting to the OpenID Connect Identity Provider.
	TLSCACertificatePEM string `yaml:"tlsCACertificatePEM"`
	// Optional path to a CA certificate to trust when connecting to the OpenID Connect Identity Provider.
	TLSCACertificatePath string `yaml:"tlsCACertificatePath"`
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "openid"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Defaults to the standard color for the provider
	// +example "pink"
	Color string `yaml:"color"`

	config *Config
}

func (p *ProviderConfig_OpenIDConnect) GetAuthProvider(ctx context.Context) (auth.Provider, error) {
	var pkceKey []byte
	if p.EnablePKCE {
		pkceKey = p.config.internal.pkceKey
	}

	var (
		tlsCACertificate []byte
		err              error
	)
	switch {
	case p.TLSCACertificatePEM != "" && p.TLSCACertificatePath != "":
		return nil, errors.New("cannot pass both 'authOpenIDConnect_tlsCACertificatePEM' and 'authOpenIDConnect_tlsCACertificatePath'")
	case p.TLSCACertificatePEM != "":
		tlsCACertificate = []byte(p.TLSCACertificatePEM)
	case p.TLSCACertificatePath != "":
		tlsCACertificate, err = os.ReadFile(p.TLSCACertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLS CA certificate from '%s': %w", p.TLSCACertificatePath, err)
		}
	}

	opts := auth.NewOpenIDConnectOptions{
		ClientID:         p.ClientID,
		ClientSecret:     p.ClientSecret,
		TokenIssuer:      p.TokenIssuer,
		RequestTimeout:   p.RequestTimeout,
		PKCEKey:          pkceKey,
		TLSSkipVerify:    p.TLSInsecureSkipVerify,
		TLSCACertificate: tlsCACertificate,
	}
	err = populateSecretFromFile(&opts.ClientSecret, p.ClientSecretFile)
	if err != nil {
		return nil, err
	}

	return auth.NewOpenIDConnect(ctx, opts)
}

func (p *ProviderConfig_OpenIDConnect) SetConfigObject(c *Config) {
	p.config = c
}

func (p *ProviderConfig_OpenIDConnect) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}

// ProviderConfig_PocketID is the configuration for the Pocket ID provider
// +name pocketid
// +displayName Pocket ID
type ProviderConfig_PocketID struct {
	// Name of the authentication provider
	// Defaults to the name of the provider type
	// +example "my-pocketid-auth"
	Name string `yaml:"name"`
	// Optional display name for the provider
	// Defaults to the standard display name for the provider
	// +example "Pocket ID"
	DisplayName string `yaml:"displayName"`
	// Pocket ID server endpoint
	// +required
	// +example "https://pocketidid.example.com"
	Endpoint string `yaml:"endpoint"`
	// Client ID for the client application
	// +required
	// +example "your-client-id"
	ClientID string `yaml:"clientID"`
	// Client secret for the client application
	// +required
	// +example "your-client-secret"
	ClientSecret string `yaml:"clientSecret"`
	// File containing the client secret for the client application
	// This is an alternative to passing the secret as `clientSecret`
	// +example "/var/run/secrets/traefik-forward-auth/pocketid/client-secret"
	ClientSecretFile string `yaml:"clientSecretFile"`
	// Timeout for network requests for Pocket ID auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// If true, enables the use of PKCE during the code exchange.
	// +default false
	EnablePKCE bool `yaml:"enablePKCE"`
	// If true, skips validating TLS certificates when connecting to the Pocket ID server.
	// +default false
	TLSInsecureSkipVerify bool `yaml:"tlsInsecureSkipVerify"`
	// Optional PEM-encoded CA certificate to trust when connecting to the Pocket ID server.
	TLSCACertificatePEM string `yaml:"tlsCACertificatePEM"`
	// Optional path to a CA certificate to trust when connecting to the Pocket ID server.
	TLSCACertificatePath string `yaml:"tlsCACertificatePath"`
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "pocketid"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Defaults to the standard color for the provider
	// +example "zinc"
	Color string `yaml:"color"`

	config *Config
}

func (p *ProviderConfig_PocketID) GetAuthProvider(ctx context.Context) (auth.Provider, error) {
	var pkceKey []byte
	if p.EnablePKCE {
		pkceKey = p.config.internal.pkceKey
	}

	var (
		tlsCACertificate []byte
		err              error
	)
	switch {
	case p.TLSCACertificatePEM != "" && p.TLSCACertificatePath != "":
		return nil, errors.New("cannot pass both 'authPocketID_tlsCACertificatePEM' and 'authPocketID_tlsCACertificatePath'")
	case p.TLSCACertificatePEM != "":
		tlsCACertificate = []byte(p.TLSCACertificatePEM)
	case p.TLSCACertificatePath != "":
		tlsCACertificate, err = os.ReadFile(p.TLSCACertificatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLS CA certificate from '%s': %w", p.TLSCACertificatePath, err)
		}
	}

	opts := auth.NewPocketIDOptions{
		Endpoint:         p.Endpoint,
		ClientID:         p.ClientID,
		ClientSecret:     p.ClientSecret,
		RequestTimeout:   p.RequestTimeout,
		PKCEKey:          pkceKey,
		TLSSkipVerify:    p.TLSInsecureSkipVerify,
		TLSCACertificate: tlsCACertificate,
	}
	err = populateSecretFromFile(&opts.ClientSecret, p.ClientSecretFile)
	if err != nil {
		return nil, err
	}

	return auth.NewPocketID(opts)
}

func (p *ProviderConfig_PocketID) SetConfigObject(c *Config) {
	p.config = c
}

func (p *ProviderConfig_PocketID) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}

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
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "tailscale"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Defaults to the standard color for the provider
	// +example "slate"
	Color string `yaml:"color"`
}

func (p *ProviderConfig_TailscaleWhois) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewTailscaleWhois(auth.NewTailscaleWhoisOptions{
		AllowedTailnet: p.AllowedTailnet,
		RequestTimeout: p.RequestTimeout,
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

func populateSecretFromFile(secret *string, secretFile string) error {
	// Do nothing if the secret is already populated or if the file name is empty
	// If the secret is required, let downstream code handle that
	if *secret != "" || secretFile == "" {
		return nil
	}

	r, err := os.ReadFile(secretFile)
	if err != nil {
		return fmt.Errorf("failed to read secret file '%s': %w", secretFile, err)
	}

	if len(r) == 0 {
		return fmt.Errorf("secret file '%s' is empty", secretFile)
	}

	*secret = string(r)

	return nil
}
