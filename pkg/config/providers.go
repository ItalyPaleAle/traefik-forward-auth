package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	yaml "sigs.k8s.io/yaml/goyaml.v3"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

type ProviderConfig interface {
	GetAuthProvider(ctx context.Context) (auth.Provider, error)
	SetConfigObject(c *Config)
}

type ProviderConfig_GitHub struct {
	// Client ID for the GitHub auth application
	// +required
	ClientID string `yaml:"clientID"`
	// Client secret for the GitHub auth application
	// +required
	ClientSecret string `yaml:"clientSecret"`
	// List of allowed users for GitHub auth
	// This is a list of usernames
	AllowedUsers []string `yaml:"allowedUsers"`
	// Timeout for network requests for GitHub auth
	// +default 10s
	RequestTimeout time.Duration `yaml:"requestTimeout"`
}

func (p *ProviderConfig_GitHub) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewGitHub(auth.NewGitHubOptions{
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		AllowedUsers:   p.AllowedUsers,
		RequestTimeout: p.RequestTimeout,
	})
}

func (p *ProviderConfig_GitHub) SetConfigObject(_ *Config) {
	// Nop for this provider
}

type ProviderConfig_Google struct {
	// Client ID for the Google auth application
	// +required
	ClientID string `yaml:"clientID"`
	// Client secret for the Google auth application
	// +required
	ClientSecret string `yaml:"clientSecret"`
	// List of allowed users for Google auth
	// This is a list of user IDs
	AllowedUsers []string `yaml:"allowedUsers"`
	// List of allowed email addresses of users for Google auth
	// This is a list of email addresses
	AllowedEmails []string `yaml:"allowedEmails"`
	// List of allowed domains for Google auth
	// This is a list of domains for email addresses
	AllowedDomains []string `yaml:"allowedDomains"`
	// Timeout for network requests for Google auth
	// +default 10s
	RequestTimeout time.Duration `yaml:"requestTimeout"`
}

func (p *ProviderConfig_Google) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewGoogle(auth.NewGoogleOptions{
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		AllowedUsers:   p.AllowedUsers,
		AllowedEmails:  p.AllowedEmails,
		AllowedDomains: p.AllowedDomains,
		RequestTimeout: p.RequestTimeout,
	})
}

func (p *ProviderConfig_Google) SetConfigObject(_ *Config) {
	// Nop for this provider
}

type ProviderConfig_MicrosoftEntraID struct {
	// Tenant ID for the Microsoft Entra ID auth application
	// +required
	TenantID string `yaml:"tenantID"`
	// Client ID for the Microsoft Entra ID auth application
	// +required
	ClientID string `yaml:"clientID"`
	// Client secret for the Microsoft Entra ID auth application
	// Required when not using Federated Identity Credentials
	ClientSecret string `yaml:"clientSecret"`
	// Enables the usage of Federated Identity Credentials to obtain assertions for confidential clients for Microsoft Entra ID applications.
	// This is an alternative to using client secrets, when the application is running in Azure in an environment that supports Managed Identity, or in an environment that supports Workload Identity Federation with Microsoft Entra ID.
	// Currently, these values are supported:
	//
	// - `ManagedIdentity`: uses a system-assigned managed identity
	// - `ManagedIdentity=client-id`: uses a user-assigned managed identity with client id "client-id" (e.g. "ManagedIdentity=00000000-0000-0000-0000-000000000000")
	// - `WorkloadIdentity`: uses workload identity, e.g. for Kubernetes
	AzureFederatedIdentity string `yaml:"azureFederatedIdentity"`
	// List of allowed users for Microsoft Entra ID auth
	// This is a list of user IDs
	AllowedUsers []string `yaml:"allowedUsers"`
	// List of allowed email addresses of users for Microsoft Entra ID auth
	// This is a list of email addresses
	AllowedEmails []string `yaml:"allowedEmails"`
	// Timeout for network requests for Microsoft Entra ID auth
	// +default 10s
	RequestTimeout time.Duration `yaml:"requestTimeout"`

	config *Config
}

func (p *ProviderConfig_MicrosoftEntraID) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewMicrosoftEntraID(auth.NewMicrosoftEntraIDOptions{
		TenantID:               p.TenantID,
		ClientID:               p.ClientID,
		ClientSecret:           p.ClientSecret,
		AzureFederatedIdentity: p.AzureFederatedIdentity,
		AllowedUsers:           p.AllowedUsers,
		RequestTimeout:         p.RequestTimeout,
		PKCEKey:                p.config.internal.pkceKey,
	})
}

func (p *ProviderConfig_MicrosoftEntraID) SetConfigObject(c *Config) {
	p.config = c
}

type ProviderConfig_OpenIDConnect struct {
	// Client ID for the OpenID Connect auth application
	// +required
	ClientID string `yaml:"clientID"`
	// Client secret for the OpenID Connect auth application
	// +required
	ClientSecret string `yaml:"clientSecret"`
	// OpenID Connect token issuer
	// The OpenID Connect configuration document will be fetched at `<token-issuer>/.well-known/openid-configuration`
	// +required
	TokenIssuer string `yaml:"tokenIssuer"`
	// List of allowed users for OpenID Connect auth
	// This is a list of user IDs, as returned by the ID provider in the "sub" claim
	AllowedUsers []string `yaml:"allowedUsers"`
	// List of allowed email addresses for users for OpenID Connect auth
	// This is a list of email addresses, as returned by the ID provider in the "email" claim
	AllowedEmails []string `yaml:"allowedEmails"`
	// Timeout for network requests for OpenID Connect auth
	// +default 10s
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

	return auth.NewOpenIDConnect(ctx, auth.NewOpenIDConnectOptions{
		ClientID:         p.ClientID,
		ClientSecret:     p.ClientSecret,
		TokenIssuer:      p.TokenIssuer,
		AllowedUsers:     p.AllowedUsers,
		AllowedEmails:    p.AllowedEmails,
		RequestTimeout:   p.RequestTimeout,
		PKCEKey:          pkceKey,
		TLSSkipVerify:    p.TLSInsecureSkipVerify,
		TLSCACertificate: tlsCACertificate,
	})
}

func (p *ProviderConfig_OpenIDConnect) SetConfigObject(c *Config) {
	p.config = c
}

type ProviderConfig_TailscaleWhois struct {
	// If non-empty, requires the Tailnet of the user to match this value
	AllowedTailnet string `yaml:"allowedTailnet"`
	// List of allowed users for Tailscale Whois auth
	// This is a list of user IDs as returned by the ID provider
	AllowedUsers []string `yaml:"allowedUsers"`
	// Timeout for network requests for Tailscale Whois auth
	// +default 10s
	RequestTimeout time.Duration `yaml:"requestTimeout"`
}

func (p *ProviderConfig_TailscaleWhois) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewTailscaleWhois(auth.NewTailscaleWhoisOptions{
		AllowedTailnet: p.AllowedTailnet,
		AllowedUsers:   p.AllowedUsers,
		RequestTimeout: p.RequestTimeout,
	})
}

func (p *ProviderConfig_TailscaleWhois) SetConfigObject(_ *Config) {
	// Nop for this provider
}

func ApplyProviderConfig(props map[string]any, dest any) error {
	if len(props) == 0 {
		return nil
	}

	// Re-encode provider config to YAML
	enc, err := yaml.Marshal(props)
	if err != nil {
		return fmt.Errorf("failed to re-encode provider config to YAML: %w", err)
	}

	// Unmarshal into p
	err = yaml.Unmarshal(enc, dest)
	if err != nil {
		return fmt.Errorf("failed to decode provider config: %w", err)
	}

	return nil
}
