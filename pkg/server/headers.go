package server

import (
	"encoding/json"

	"github.com/spf13/cast"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

type AuthenticatedHeader interface {
	GetName() string
	GetValue(portal Portal, provider auth.Provider, profile *user.Profile) string
}

type authenticatedClaimHeader struct {
	name  string
	claim string
}

func (h authenticatedClaimHeader) GetName() string {
	return h.name
}

func (h authenticatedClaimHeader) GetValue(portal Portal, provider auth.Provider, profile *user.Profile) string {
	return cast.ToString(profile.Get(h.claim))
}

type builtinAuthenticatedUserHeader struct{}

func (h builtinAuthenticatedUserHeader) GetName() string {
	return headerXAuthenticatedUser
}

// Returns the user information to include in the "X-Authenticated-User" header
func (h builtinAuthenticatedUserHeader) GetValue(portal Portal, provider auth.Provider, profile *user.Profile) string {
	userID, _ := json.Marshal(profile.ID)
	// Provider and portal names is already guaranteed to not include characters that must be escaped as JSON
	return `{"provider":"` + provider.GetProviderName() + `","portal":"` + portal.Name + `","user":` + string(userID) + `}`
}

func getHeadersConfig(p config.ConfigPortal) []AuthenticatedHeader {
	if p.Headers == nil {
		// Returns the default X-Forwarded-User, X-Authenticated-User, X-Forwarded-Displayname headers
		return []AuthenticatedHeader{
			authenticatedClaimHeader{name: headerXForwardedUser, claim: "id"},
			builtinAuthenticatedUserHeader{},
			authenticatedClaimHeader{name: headerXForwardedDisplayName, claim: "name"},
		}
	}

	headers := make([]AuthenticatedHeader, len(*p.Headers))
	for i, h := range *p.Headers {
		headers[i] = authenticatedClaimHeader{name: h.Name, claim: h.Claim}
	}
	return headers
}
