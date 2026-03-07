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
	// OAuth2 scopes to request
	// +default "openid profile email groups"
	Scopes string `yaml:"scopes"`
	// If true, enables the use of PKCE during the code exchange.
	// +default false
	EnablePKCE bool `yaml:"enablePKCE"`
	// Enables the usage of client assertions (also known as "Federated Identity Credentials" or "Federated Workload Credentials") to obtain assertions for client applications.
	// This is an alternative to using client secrets, when the application is running in an environment that supports other ways to obtain federated credentials.
	// Currently, these values are supported:
	//
	// - `AzureManagedIdentity`: uses Azure Managed Identity with a system-assigned identity
	// - `AzureManagedIdentity=client-id`: uses Azure Managed Identity with a user-assigned identity whose client id is "client-id" (e.g. `AzureManagedIdentity=00000000-0000-0000-0000-000000000000`)
	// - `AzureWorkloadIdentity`: uses Azure Workload Identity, e.g. in Kubernetes
	// - `KubernetesServiceAccountToken=path`: uses a token read from a Kubernetes service account token file. If `path` is omitted, defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`.
	// - `tsiam=endpoint`: uses tsiam to obtain Workload Identity from nodes that use Tailscale. Specify the endpoint of tsiam as value, e.g. `tsiam=https://tsiam`. Uses as resource name the value of `endpoint`.
	ClientAssertion string `yaml:"clientAssertion"`
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
	// Allowed values include all color schemes available in Tailwind 4
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
		Scopes:           p.Scopes,
		PKCEKey:          pkceKey,
		ClientAssertion:  p.ClientAssertion,
		TLSSkipVerify:    p.TLSInsecureSkipVerify,
		TLSCACertificate: tlsCACertificate,
		Hostname:         p.config.Server.Hostname,
		BasePath:         p.config.Server.BasePath,
	}

	// Only load client secret from file when not using client assertions and when a client secret has not already been provided directly
	if opts.ClientAssertion == "" && opts.ClientSecret == "" {
		err = populateSecretFromFile(&opts.ClientSecret, p.ClientSecretFile)
		if err != nil {
			return nil, err
		}
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
