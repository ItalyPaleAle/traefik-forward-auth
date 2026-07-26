package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

type AuthenticatedHeader interface {
	GetName() string
	GetValue(portal *Portal, provider auth.Provider, profile *user.Profile) string
}

type authenticatedClaimHeader struct {
	name  string
	claim string
}

func (h authenticatedClaimHeader) GetName() string {
	return h.name
}

func (h authenticatedClaimHeader) GetValue(portal *Portal, provider auth.Provider, profile *user.Profile) string {
	switch h.claim {
	case "groups", "roles":
		v, ok := user.GetAs[[]string](profile, h.claim)
		if !ok || len(v) == 0 {
			return ""
		}
		return strings.Join(v, " ")
	default:
		v, _ := user.GetAs[string](profile, h.claim)
		return v
	}
}

type authenticatedPropertyHeader struct {
	name     string
	property string
}

func (h authenticatedPropertyHeader) GetName() string {
	return h.name
}

func (h authenticatedPropertyHeader) GetValue(portal *Portal, provider auth.Provider, profile *user.Profile) string {
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
func (h builtinAuthenticatedUserHeader) GetValue(portal *Portal, provider auth.Provider, profile *user.Profile) string {
	// Provider and portal names is already guaranteed to not include characters that must be escaped as JSON
	return `{"provider":"` + provider.GetProviderName() + `","portal":"` + portal.Name + `","user":` + jsonQuoteString(profile.ID) + `}`
}

// jsonQuoteString returns val as a quoted JSON string, identically to json.Marshal
func jsonQuoteString(val string) string {
	// User IDs very rarely contain characters that need escaping, so the common case is quoting the value directly
	// Fall back to the JSON encoder if we find anything that would require encoding
	for i := range len(val) {
		c := val[i]
		// Fall back for control characters, for the characters encoding/json escapes, and for anything non-ASCII (which may need escaping as UTF-8)
		if c < 0x20 || c > 0x7E || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			enc, err := json.Marshal(val)
			if err != nil {
				// Marshaling a string cannot fail, but return a valid JSON string rather than something malformed if it ever does
				return `""`
			}
			return string(enc)
		}
	}

	return `"` + val + `"`
}

func getHeadersConfig(p config.ConfigPortal) []AuthenticatedHeader {
	// When the headers property is unset:
	// Returns the default X-Forwarded-User, X-Authenticated-User, X-Forwarded-Displayname headers
	if p.Headers == nil {
		return []AuthenticatedHeader{
			authenticatedClaimHeader{name: headerXForwardedUser, claim: "id"},
			builtinAuthenticatedUserHeader{},
			authenticatedClaimHeader{name: headerXForwardedDisplayName, claim: "name"},
		}
	}

	// Add the custom headers
	// Names are canonicalized here so that setting them on a response doesn't have to canonicalize them on every request
	headers := make([]AuthenticatedHeader, len(*p.Headers))
	for i, h := range *p.Headers {
		name := http.CanonicalHeaderKey(h.Name)
		if h.Claim != "" {
			headers[i] = authenticatedClaimHeader{name: name, claim: h.Claim}
		} else if h.Property != "" {
			headers[i] = authenticatedPropertyHeader{name: name, property: h.Property}
		}
	}
	return headers
}
