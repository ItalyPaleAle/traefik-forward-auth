package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// MicrosoftEntraID manages authentication with Microsoft Entra ID.
// It is based on the OpenIDConnect provider.
type MicrosoftEntraID struct {
	*OpenIDConnect
}

// NewMicrosoftEntraIDOptions is the options for NewMicrosoftEntraID
type NewMicrosoftEntraIDOptions struct {
	// Tenant ID
	TenantID string
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// Enables the use of Federated Identity Credentials
	AzureFederatedIdentity string
	// If non-empty, allows these user accounts only (matching the internal user ID)
	AllowedUsers []string
	// If non-empty, allows users with these email addresses only
	AllowedEmails []string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
	// Key for generating PKCE code verifiers
	// Enables the use of PKCE if non-empty
	PKCEKey []byte
}

func (o NewMicrosoftEntraIDOptions) ToNewOpenIDConnectOptions() NewOpenIDConnectOptions {
	return NewOpenIDConnectOptions{
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		RequestTimeout: o.RequestTimeout,
		AllowedEmails:  o.AllowedEmails,
		AllowedUsers:   o.AllowedUsers,
		TokenIssuer:    "https://login.microsoftonline.com/" + o.TenantID + "/v2.0",
		PKCEKey:        o.PKCEKey,
	}
}

// NewMicrosoftEntraID returns a new MicrosoftEntraID provider
func NewMicrosoftEntraID(opts NewMicrosoftEntraIDOptions) (*MicrosoftEntraID, error) {
	if opts.TenantID == "" {
		return nil, errors.New("value for clientId is required in config for auth with provider 'microsoft-entra-id'")
	}

	fic, err := getFederatedIdentity(opts.AzureFederatedIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Federated Identity Credentials for auth provider 'microsoft-entra-id': %w", err)
	}

	oidcOpts := opts.ToNewOpenIDConnectOptions()
	if fic == nil && opts.ClientSecret == "" {
		return nil, errors.New("value for clientSecret is required in config for auth with provider 'microsoft-entra-id' when not using Federated Identity Credentials")
	} else if fic != nil {
		oidcOpts.skipClientSecretValidation = true
		oidcOpts.tokenExchangeParametersModifier = func(ctx context.Context, data url.Values) error {
			// Get the client assertion
			clientAssertion, err := fic.GetToken(ctx, policy.TokenRequestOptions{
				// This is a constant value
				Scopes: []string{"api://AzureADTokenExchange"},
			})
			if err != nil {
				return fmt.Errorf("failed to obtain client assertion: %w", err)
			}

			// This is a constant value
			data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			data.Set("client_assertion", clientAssertion.Token)

			// Delete the client secret
			data.Del("client_secret")

			return nil
		}
	}

	oidc, err := newOpenIDConnectInternal("microsoftentraid", oidcOpts, OAuth2Endpoints{
		Authorization: "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/authorize",
		Token:         "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/token",
		UserInfo:      "https://graph.microsoft.com/oidc/userinfo",
	})
	if err != nil {
		return nil, err
	}

	a := &MicrosoftEntraID{
		OpenIDConnect: oidc,
	}

	return a, nil
}

func (a *MicrosoftEntraID) UserIDFromProfile(profile *user.Profile) string {
	if profile.Email != nil && profile.Email.Value != "" {
		return profile.Email.Value
	}
	return profile.ID
}

func (a *MicrosoftEntraID) FullNameFromProfile(profile *user.Profile) string {
	if profile.Name.FullName != "" {
		return profile.Name.FullName
	}
	return ""
}

func getFederatedIdentity(afi string) (fic azcore.TokenCredential, err error) {
	// Crete the federated identity credential object depending on the kind of federated identity
	afi = strings.ToLower(afi)
	switch {
	case afi == "":
		// If federated identity is disabled, return
		return nil, nil
	case strings.HasPrefix(afi, "managedidentity="):
		// User-assigned managed identity
		fic, err = azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(afi[len("managedidentity="):]),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create managed identity credential object: %w", err)
		}
	case afi == "managedidentity":
		// System-assigned managed identity
		fic, err = azidentity.NewManagedIdentityCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create managed identity credential object: %w", err)
		}
	case afi == "workloadidentity":
		// Workload Identity
		fic, err = azidentity.NewWorkloadIdentityCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create workload identity credential object: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid value for configuration option 'azureFederatedIdentity': '%s'", afi)
	}

	return fic, nil
}

// Compile-time interface assertion
var _ OAuth2Provider = &MicrosoftEntraID{}
