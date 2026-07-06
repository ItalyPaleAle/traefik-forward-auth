package auth

import (
	"context"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
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
	// Enables the use of client assertions
	ClientAssertion string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
	// Scopes for requesting the token
	// This is optional and defaults to "openid profile email"
	Scopes string
	// Key for generating PKCE code verifiers
	// Enables the use of PKCE if non-empty
	PKCEKey []byte
}

func (o NewMicrosoftEntraIDOptions) ToNewOpenIDConnectOptions() NewOpenIDConnectOptions {
	return NewOpenIDConnectOptions{
		ClientID:        o.ClientID,
		ClientSecret:    o.ClientSecret,
		ClientAssertion: o.ClientAssertion,
		RequestTimeout:  o.RequestTimeout,
		Scopes:          o.Scopes,
		TokenIssuer:     "https://login.microsoftonline.com/" + o.TenantID + "/v2.0",
		PKCEKey:         o.PKCEKey,

		// Profile modifier functions that add these claims:
		// - id: uses "oid" instead of "sub"
		// - "tid": tenant ID
		// - "wids": list of roles in the directory) and "tid" (tenant ID)
		// https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
		profileModifier: profileModifierFn{
			Token: func(token openid.Token, profile *user.Profile) error {
				oid, err := jwt.Get[string](token, microsoftEntraIDClaimOid)
				if err == nil && oid != "" {
					profile.ID = oid
				}
				tid, err := jwt.Get[string](token, microsoftEntraIDClaimTid)
				if err == nil && tid != "" {
					profile.SetAdditionalClaim(microsoftEntraIDClaimTid, tid)
				}

				v, ok := token.Field(microsoftEntraIDClaimWids)
				if ok {
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

				v, ok := claims[microsoftEntraIDClaimWids]
				if ok {
					wids := cast.ToStringSlice(v)
					if len(wids) > 0 {
						profile.SetAdditionalClaim(microsoftEntraIDClaimWids, wids)
					}
				}
				return nil
			},
		},

		// When requesting tokens for client assertions, the audience is hardcoded as "api://AzureADTokenExchange"
		clientAssertionAudience: "api://AzureADTokenExchange",
	}
}

// NewMicrosoftEntraID returns a new MicrosoftEntraID provider
func NewMicrosoftEntraID(ctx context.Context, opts NewMicrosoftEntraIDOptions) (*MicrosoftEntraID, error) {
	if opts.TenantID == "" {
		return nil, errors.New("value for tenantId is required in config for auth with provider 'microsoft-entra-id'")
	}
	if opts.ClientSecret == "" && opts.ClientAssertion == "" {
		return nil, errors.New("value for clientSecret is required in config for auth with provider 'microsoft-entra-id' when not using client assertions")
	}

	oidcOpts := opts.ToNewOpenIDConnectOptions()
	// Set default scopes if not specified
	if oidcOpts.Scopes == "" {
		oidcOpts.Scopes = "openid profile email"
	}

	const providerType = "microsoftentraid"
	metadata := ProviderMetadata{
		DisplayName: "Microsoft Entra ID",
		Name:        providerType,
		Icon:        "microsoft",
		Color:       "cyan",
	}
	oidc, err := newOpenIDConnectInternal(ctx, providerType, metadata, oidcOpts, OAuth2Endpoints{
		Authorization: "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/authorize",
		Token:         "https://login.microsoftonline.com/" + opts.TenantID + "/oauth2/v2.0/token",
		UserInfo:      "https://graph.microsoft.com/oidc/userinfo",
		JWKSUri:       "https://login.microsoftonline.com/" + opts.TenantID + "/discovery/v2.0/keys",
	})
	if err != nil {
		return nil, err
	}

	a := &MicrosoftEntraID{
		OpenIDConnect: oidc,
	}

	return a, nil
}

func (a *MicrosoftEntraID) PopulateAdditionalClaims(token jwt.Token, setClaimFn func(key string, val any)) {
	tid, ok := token.Field(microsoftEntraIDClaimTid)
	if ok {
		setClaimFn(microsoftEntraIDClaimTid, tid)
	}
	wids, ok := token.Field(microsoftEntraIDClaimWids)
	if ok {
		setClaimFn(microsoftEntraIDClaimWids, wids)
	}
}

// Compile-time interface assertion
var _ OAuth2Provider = &MicrosoftEntraID{}
