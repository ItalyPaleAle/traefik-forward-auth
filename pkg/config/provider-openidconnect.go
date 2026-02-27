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
	// This is required when not using client assertions.
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
	// Enables the usage of client assertions (also known as "Federated Identity Credentials" or "Federated Workload Credentials") to obtain assertions for OpenID Connect clients.
	// This is an alternative to using client secrets, when the application is running in an environment that supports other ways to obtain federated credentials.
	// Currently, these values are supported:
	//
	// - `AzureManagedIdentity`: uses Azure Managed Identity with a system-assigned identity
	// - `AzureManagedIdentity=client-id`: uses Azure Managed Identity with a user-assigned identity whose client id is "client-id" (e.g. "AzureManagedIdentity=00000000-0000-0000-0000-000000000000")
	// - `AzureWorkloadIdentity`: uses Azure Workload Identity, e.g. in Kubernetes
	// - `tsiam=endpoint`: uses tsiam to obtain Workload Identity from nodes that use Tailscale. Specify the endpoint of tsiam as value, e.g. "tsiam=https://tsiam". Uses as resource name the value of `tokenIssuer`.
	ClientAssertion string `yaml:"clientAssertion"`
	// Timeout for network requests for OpenID Connect auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// OAuth2 scopes to request
	// +default "openid profile email"
	Scopes string `yaml:"scopes"`
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
	// Allowed values include all color schemes available in Tailwind 4
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
		ClientAssertion:  p.ClientAssertion,
		TokenIssuer:      p.TokenIssuer,
		RequestTimeout:   p.RequestTimeout,
		Scopes:           p.Scopes,
		PKCEKey:          pkceKey,
		TLSSkipVerify:    p.TLSInsecureSkipVerify,
		TLSCACertificate: tlsCACertificate,
		Hostname:         p.config.Server.Hostname,
		BasePath:         p.config.Server.BasePath,
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
