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
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwt/openid"
	"github.com/spf13/cast"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

const (
	microsoftEntraIDClaimOid  = "oid"
	microsoftEntraIDClaimTid  = "tid"
	microsoftEntraIDClaimWids = "wids"
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
		TokenIssuer:    "https://login.microsoftonline.com/" + o.TenantID + "/v2.0",
		PKCEKey:        o.PKCEKey,

		// Profile modifier functions that add these claims:
		// - id: uses "oid" instead of "sub"
		// - "tid": tenant ID
		// - "wids": list of roles in the directory) and "tid" (tenant ID)
		// https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
		profileModifier: profileModifierFn{
			Token: func(token openid.Token, profile *user.Profile) error {
				var str string
				if token.Get(microsoftEntraIDClaimOid, &str) == nil && str != "" {
					profile.ID = str
				}
				if token.Get(microsoftEntraIDClaimTid, &str) == nil && str != "" {
					profile.SetAdditionalClaim(microsoftEntraIDClaimTid, str)
				}

				var v any
				if token.Get(microsoftEntraIDClaimWids, &v) == nil {
					wids := cast.ToStringSlice(v)
					if len(wids) > 0 {
						profile.SetAdditionalClaim(microsoftEntraIDClaimWids, wids)
					}
				}
				return nil
			},
			Claims: func(claims map[string]any, profile *user.Profile) error {
				var str string
				str = cast.ToString(claims[microsoftEntraIDClaimOid])
				if str != "" {
					profile.ID = str
				}
				str = cast.ToString(claims[microsoftEntraIDClaimTid])
				if str != "" {
					profile.SetAdditionalClaim(microsoftEntraIDClaimTid, str)
				}

				if v, ok := claims[microsoftEntraIDClaimWids]; ok {
					wids := cast.ToStringSlice(v)
					if len(wids) > 0 {
						profile.SetAdditionalClaim(microsoftEntraIDClaimWids, wids)
					}
				}
				return nil
			},
		},
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

	const providerType = "microsoftentraid"
	metadata := ProviderMetadata{
		DisplayName: "Microsoft Entra ID",
		Name:        providerType,
		Icon:        "microsoft",
		Color:       "teal-to-lime",
	}
	oidc, err := newOpenIDConnectInternal(providerType, metadata, oidcOpts, OAuth2Endpoints{
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

func (a *MicrosoftEntraID) PopulateAdditionalClaims(token jwt.Token, setClaimFn func(key string, val any)) {
	var val any
	if token.Get(microsoftEntraIDClaimTid, &val) == nil {
		setClaimFn(microsoftEntraIDClaimTid, val)
	}
	if token.Get(microsoftEntraIDClaimWids, &val) == nil {
		setClaimFn(microsoftEntraIDClaimWids, val)
	}
}

// Compile-time interface assertion
var _ OAuth2Provider = &MicrosoftEntraID{}
