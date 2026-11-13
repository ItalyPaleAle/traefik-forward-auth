package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

type AuthenticatedHeader interface {
	GetName() string
	GetValue(portal *Portal, provider auth.Provider, profile *user.Profile) string
}

// setAuthenticatedHeaders adds the portal's authenticated headers to the response
func setAuthenticatedHeaders(c *gin.Context, portal *Portal, provider auth.Provider, profile *user.Profile) {
	if len(portal.Headers) == 0 {
		return
	}

	h := c.Writer.Header()

	// Capacity is fixed up front so appending never reallocates and never invalidates a slice already handed to the header map
	values := make([]string, 0, len(portal.Headers))

	for _, header := range portal.Headers {
		// Header names are canonicalized when the portal configuration is loaded, so they can be set without canonicalizing them again per request
		name := header.GetName()

		value := validateHeaderValue(header.GetValue(portal, provider, profile))
		if value == "" {
			// An empty value removes the header, matching the behavior of gin's Context.Header
			delete(h, name)
			continue
		}

		values = append(values, value)
		// Capping the slice at its length means anything that later adds to this header allocates its own array instead of writing into ours
		h[name] = values[len(values)-1 : len(values) : len(values)]
	}
}

// validateHeaderValue returns the value to use for a response header, or an empty string if the header should not be set
func validateHeaderValue(value string) string {
	// Limit the value to 1KB
	const maxLen = 1 << 10

	if len(value) > maxLen {
		return ""
	}

	// Control characters are removed because Go HTTP clients (including Traefik) reject a response whose headers contain them, which would break every request for that user
	// Invalid UTF-8 is removed because apps reading the header expect text
	// Fast path: nearly every value is printable ASCII, which is returned as-is without allocating
	for i := range len(value) {
		ch := value[i]
		if ch < 0x20 || ch >= 0x7f {
			return sanitizeHeaderValue(value)
		}
	}

	return value
}

// sanitizeHeaderValue removes control characters and invalid UTF-8 from a header value
// Tabs are kept because they're allowed in HTTP header values
func sanitizeHeaderValue(value string) string {
	var sb strings.Builder
	sb.Grow(len(value))

	for i := 0; i < len(value); {
		ch := value[i]

		// ASCII: keep printable characters and tabs, drop C0 control characters and DEL
		if ch < utf8.RuneSelf {
			if (ch >= 0x20 && ch != 0x7f) || ch == '\t' {
				sb.WriteByte(ch)
			}
			i++
			continue
		}

		// Multi-byte sequence: drop invalid UTF-8 (reported as RuneError with size 1) and C1 control characters
		// A literal U+FFFD in the input decodes as RuneError with size 3 and is kept
		r, size := utf8.DecodeRuneInString(value[i:])
		invalid := r == utf8.RuneError && size == 1
		if !invalid && !unicode.IsControl(r) {
			sb.WriteString(value[i : i+size])
		}
		i += size
	}

	return sb.String()
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
