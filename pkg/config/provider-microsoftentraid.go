//nolint:revive
package config

import (
	"context"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

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
	// Enables the usage of client assertions (also known as "Federated Identity Credentials" or "Federated Workload Credentials") to obtain assertions for Microsoft Entra ID applications.
	// This is an alternative to using client secrets, when the application is running in an environment that supports other ways to obtain federated credentials.
	// Currently, these values are supported:
	//
	// - `AzureManagedIdentity`: uses Azure Managed Identity with a system-assigned identity
	// - `AzureManagedIdentity=client-id`: uses Azure Managed Identity with a user-assigned identity whose client id is "client-id" (e.g. `AzureManagedIdentity=00000000-0000-0000-0000-000000000000`)
	// - `AzureWorkloadIdentity`: uses Azure Workload Identity, e.g. in Kubernetes
	// - `KubernetesServiceAccountToken=path`: uses a token read from a Kubernetes service account token file. If `path` is omitted, defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`.
	// - `tsiam=endpoint`: uses tsiam to obtain Workload Identity from nodes that use Tailscale. Specify the endpoint of tsiam as value, e.g. `tsiam=https://tsiam`. Uses as resource name the constant value `api://AzureADTokenExchange`.
	ClientAssertion string `yaml:"clientAssertion"`
	// Timeout for network requests for Microsoft Entra ID auth
	// +default "10s"
	RequestTimeout time.Duration `yaml:"requestTimeout"`
	// OAuth2 scopes to request
	// +default "openid profile email"
	Scopes string `yaml:"scopes"`
	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example "microsoft"
	Icon string `yaml:"icon"`
	// Optional color scheme for the provider
	// Allowed values include all color schemes available in Tailwind 4
	// Defaults to the standard color for the provider
	// +example "cyan"
	Color string `yaml:"color"`

	// Deprecated: Use `clientAssertion` instead. This is preserved for backwards-compatibility
	// Enables the usage of Federated Identity Credentials to obtain assertions for confidential clients for Microsoft Entra ID applications.
	// This is an alternative to using client secrets, when the application is running in Azure in an environment that supports Managed Identity, or in an environment that supports Workload Identity Federation with Microsoft Entra ID.
	// Currently, these values are supported:
	//
	// - `ManagedIdentity`: uses a system-assigned managed identity
	// - `ManagedIdentity=client-id`: uses a user-assigned managed identity with client id "client-id" (e.g. "ManagedIdentity=00000000-0000-0000-0000-000000000000")
	// - `WorkloadIdentity`: uses workload identity, e.g. for Kubernetes
	AzureFederatedIdentity string `yaml:"azureFederatedIdentity" deprecated:"true"`

	config *Config
}

func (p *ProviderConfig_MicrosoftEntraID) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	// Migrate legacy AzureFederatedIdentity to ClientAssertions
	if p.AzureFederatedIdentity != "" && p.ClientAssertion == "" {
		// We need to add the "Azure" prefix
		p.ClientAssertion = "Azure" + p.AzureFederatedIdentity
		p.AzureFederatedIdentity = ""
	}

	opts := auth.NewMicrosoftEntraIDOptions{
		TenantID:        p.TenantID,
		ClientID:        p.ClientID,
		ClientSecret:    p.ClientSecret,
		ClientAssertion: p.ClientAssertion,
		RequestTimeout:  p.RequestTimeout,
		Scopes:          p.Scopes,
		PKCEKey:         p.config.internal.pkceKey,
		Hostname:        p.config.Server.Hostname,
		BasePath:        p.config.Server.BasePath,
	}

	// Only load client secret from file when not using client assertions and when a client secret has not already been provided directly
	if opts.ClientAssertion == "" && opts.ClientSecret == "" {
		err := populateSecretFromFile(&opts.ClientSecret, p.ClientSecretFile)
		if err != nil {
			return nil, err
		}
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
