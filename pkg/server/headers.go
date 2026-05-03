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

type authenticatedPropertyHeader struct {
	name     string
	property string
}

func (h authenticatedPropertyHeader) GetName() string {
	return h.name
}

func (h authenticatedPropertyHeader) GetValue(portal Portal, provider auth.Provider, profile *user.Profile) string {
	switch h.property {
	case config.PropertyPortalName:
		return portal.Name
	case config.PropertyProviderName:
		return provider.GetProviderName()
	default:
		return ""
	}
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

	headers := []AuthenticatedHeader{}
	for _, h := range *p.Headers {
		if h.Claim != "" {
			headers = append(headers, authenticatedClaimHeader{name: h.Name, claim: h.Claim})
		} else if h.Property != "" {
			headers = append(headers, authenticatedPropertyHeader{name: h.Name, property: h.Property})
		}
	}
	return headers
}
