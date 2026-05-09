package config

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/validators"
)

// Allowed properties for custom headers
const (
	// PropertyPortalName is the portal name
	PropertyPortalName = "portal.name"
	// PropertyProviderName is the provider name
	PropertyProviderName = "provider.name"
)

// Config is the struct containing configuration
type Config struct {
	// Configuration for the application's server
	Server ConfigServer `yaml:"server"`

	// Cookies configuration
	Cookies ConfigCookies `yaml:"cookies"`

	// Tokens configuration
	Tokens ConfigTokens `yaml:"tokens"`

	// Logs configuration
	Logs ConfigLogs `yaml:"logs"`

	// If set to the name of a portal defined in "portals", it makes the portal available on the root endpoint, without the `portals/<name>/` prefix
	// +example "myportal"
	DefaultPortal string `yaml:"defaultPortal"`

	// List of portals
	// At least one configured portal and provider is required
	// +required
	Portals []ConfigPortal `yaml:"portals"`

	// Dev is meant for development only; it's undocumented
	Dev ConfigDev `yaml:"dev" ignoredocs:"true"`

	// Internal keys
	internal internal `yaml:"-"`
}

type ConfigServer struct {
	// Hostname for Traefik Forward Auth itself
	// This is deprecated: it is only honored as a fallback `authHost` when migrating from the legacy `cookies.domain` option, and is ignored otherwise
	// Use `server.domains[].authHost` instead to indicate the public hostname of Traefik Forward Auth for a given domain
	Hostname string `yaml:"hostname" deprecated:"true"`

	// Domains served by Traefik Forward Auth
	// Each entry sets the cookie domain for matching requests, and optionally the public hostname where Traefik Forward Auth is reachable for that domain (`authHost`)
	// `authHost` is only required when running in "dedicated sub-domain" mode (where Traefik Forward Auth is served on a different host than the apps); in "sub-path" mode the request host is used and `authHost` can be omitted
	// `authHost` must be the same as, or a sub-domain of, `domain`. If omitted, it defaults to `domain`
	// +recommended
	Domains []ConfigServerDomain `yaml:"domains"`

	// Port to bind to.
	// +default 4181
	Port int `yaml:"port"`

	// Address/interface to bind to.
	// +default "0.0.0.0"
	Bind string `yaml:"bind"`

	// Base path for all routes.
	// Set this if Traefik is forwarding requests to traefik-forward-auth for specific paths only.
	// Note: this does not apply to /healthz routes
	// +example "/auth"
	BasePath string `yaml:"basePath"`

	// Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem` (and optionally `tls-ca.pem`).
	// The server watches for changes in this folder and automatically reloads the TLS certificates when they're updated.
	// If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.
	// +default Folder where the `config.yaml` file is located
	TLSPath string `yaml:"tlsPath"`

	// Full, PEM-encoded TLS certificate.
	// Using `server.tlsCertPEM` and `server.tlsKeyPEM` is an alternative method of passing TLS certificates than using `server.tlsPath`.
	TLSCertPEM string `yaml:"tlsCertPEM"`

	// Full, PEM-encoded TLS key.
	// Using `server.tlsCertPEM` and `server.tlsKeyPEM` is an alternative method of passing TLS certificates than using `server.tlsPath`.
	TLSKeyPEM string `yaml:"tlsKeyPEM"`

	// Full, PEM-encoded TLS CA certificate, used for TLS client authentication (mTLS).
	// This is an alternative method of passing the CA certificate than using `tlsPath`.
	// Note that this is ignored unless `server.tlsClientAuth` is set to `true`.
	TLSCAPEM string `yaml:"tlsCAPEM"`

	// If true, enables mTLS for client authentication.
	// Requests to the root endpoint (normally used by Traefik) must have a valid client certificate signed by the CA.
	// +default false
	TLSClientAuth bool `yaml:"tlsClientAuth"`

	// String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.
	// Common values include:
	//
	// - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id) that's vendor agnostic
	// - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)
	//
	// If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
	// +example "X-Request-ID"
	TrustedRequestIdHeader string `yaml:"trustedRequestIdHeader"`

	// Favicon for the app.
	// If this starts with "http://" or "https://", it's treated as a URL and fetched when the server starts up.
	// Otherwise, it's treated as base64-encoded image data.
	// The favicon must be an ICO, PNG, or SVG image.
	Favicon string `yaml:"favicon"`
}

// ConfigServerDomain configures a domain served by Traefik Forward Auth
type ConfigServerDomain struct {
	// Domain name used when setting cookies, and matched against the request hostname
	// +required
	// +example "example.com"
	Domain string `yaml:"domain"`

	// Public hostname where Traefik Forward Auth is reachable for this domain
	// Used for OAuth2 callback URLs and redirects to the sign-in page when running in "dedicated sub-domain" mode
	// Must be the same as, or a sub-domain of, `domain`
	// If omitted, defaults to the value of `domain` (which is appropriate when running in "sub-path" mode)
	// +example "auth.example.com"
	AuthHost string `yaml:"authHost"`
}

type ConfigCookies struct {
	// Domain name for setting cookies
	// This is deprecated: use `server.domains` instead
	// +example "auth.example.com"
	Domain string `yaml:"domain" deprecated:"true"`

	// Prefix for the cookies used to store the sessions.
	// +default "tf_sess"
	NamePrefix string `yaml:"namePrefix"`

	// If true, sets cookies as "insecure", which are served on HTTP endpoints too.
	// By default, this is false and cookies are sent on HTTPS endpoints only.
	// +default false
	Insecure bool `yaml:"insecure"`
}

func (c ConfigCookies) CookieName(portalName string) string {
	return c.NamePrefix + "_" + portalName
}

// DomainForHost returns the cookie domain and the public auth host that best match `host`
// `cookieDomain` is the value to use for the Set-Cookie Domain attribute (empty for a host-only cookie when host is an IP)
// `authHost` is the public hostname of Traefik Forward Auth for that domain, used when building OAuth2 callbacks and sign-in redirects
// `ok` is false when none of the configured domains match the request host
func (s ConfigServer) DomainForHost(host string) (cookieDomain string, authHost string, ok bool) {
	// Normalize the request host so callers can pass either Host or X-Forwarded-Host values
	host = NormalizeHostname(host)
	if host == "" {
		return "", "", false
	}

	// Browsers do not accept a cookie Domain attribute set to an IP address
	// Returning an empty cookie domain tells the caller to set a host-only cookie instead
	// The auth host falls back to the request host so redirects target the same address
	if validators.IsIP(host) {
		return "", host, true
	}

	// With no configured domains, trust the request host and set a host-scoped cookie
	// This is the "sub-path" mode where Traefik Forward Auth shares each app's host
	if len(s.Domains) == 0 {
		return host, host, true
	}

	// Multiple configured domains can overlap, so prefer the longest match
	// This makes apps.example.com win over example.com for foo.apps.example.com
	bestIdx := -1
	for i, d := range s.Domains {
		if !utils.IsSubDomain(d.Domain, host) {
			continue
		}

		if bestIdx < 0 || len(d.Domain) > len(s.Domains[bestIdx].Domain) {
			bestIdx = i
		}
	}

	// If none of the configured domains match, the request should not receive auth cookies
	if bestIdx < 0 {
		return "", "", false
	}

	return s.Domains[bestIdx].Domain, s.Domains[bestIdx].AuthHost, true
}

// NormalizeHostname normalizes a hostname or host:port value for comparisons
func NormalizeHostname(host string) string {
	// Remove incidental whitespace and casing differences before comparing hostnames
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}

	// Accept Host header style values that include a port
	// SplitHostPort returns the host without IPv6 brackets
	splitHost, splitPort, err := net.SplitHostPort(host)
	switch {
	case err == nil && splitHost != "" && splitPort != "":
		host = splitHost
	case len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']':
		// Bracketed IPv6 literal without a port: strip both brackets only when balanced
		host = host[1 : len(host)-1]
	}

	// Treat fully-qualified DNS names and ordinary hostnames as equivalent for matching
	host = strings.TrimSuffix(host, ".")

	return host
}

type ConfigLogs struct {
	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default "info"
	Level string `yaml:"level"`

	// If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.
	// +default true
	OmitHealthChecks bool `yaml:"omitHealthChecks"`

	// If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.
	// Defaults to false if a TTY is attached (e.g. in development); true otherwise.
	JSON bool `yaml:"json"`
}

type ConfigTokens struct {
	// Lifetime for sessions after a successful authentication.
	// This can be overridden on each portal.
	// +default "2h"
	SessionLifetime time.Duration `yaml:"sessionLifetime"`

	// String used as key to sign state tokens.
	// Can be generated for example with `openssl rand -base64 32`
	// If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).
	SigningKey string `yaml:"signingKey"`

	// File containing the key used to sign state tokens.
	// This is an alternative to specifying `signingKey` tokens.directly.
	SigningKeyFile string `yaml:"signingKeyFile"`

	// Value for the audience claim to expect in session tokens used by Traefik Forward Auth.
	// Defaults to a value based on the current environment, which is appropriate for the majority of cases. Most users should rely on the default value.
	SessionTokenAudience string `yaml:"sessionTokenAudience"`
}

type ConfigPortal struct {
	// Name of the portal, as used in the URL.
	// +required
	// +example "main"
	Name string `yaml:"name"`

	// Optional display name.
	// Defaults to the `name` property if not set.
	// +example "My auth portal"
	DisplayName string `yaml:"displayName"`

	// If true, always shows the providers selection page, even when there's a single provider configured.
	// Has no effect when there's more than one provider configured.
	// +default false
	AlwaysShowProvidersPage bool `yaml:"alwaysShowProvidersPage"`

	// Timeout for authenticating with the authentication provider.
	// +default 5m
	AuthenticationTimeout time.Duration `yaml:"authenticationTimeout"`

	// Lifetime for sessions after a successful authentication for the portal.
	// If set, this overrides the default value configured in the `tokens` section for this portal.
	SessionLifetime time.Duration `yaml:"sessionLifetime"`

	// URL to override the background image for the portal, size medium.
	// The recommended size is 720x1080.
	BackgroundMedium string `yaml:"backgroundMedium"`

	// URL to override the background image for the portal, size large.
	// The recommended size is 940x1410.
	BackgroundLarge string `yaml:"backgroundLarge"`

	// List of HTTP headers to add to the response.
	Headers *[]ConfigPortalHeader `yaml:"headers"`

	// List of allowed authentication providers.
	// At least one provider is required.
	// +required
	Providers []ConfigPortalProvider `yaml:"providers"`
}

type ConfigPortalProvider struct {
	// Use GitHub as authentication provider
	GitHub *ProviderConfig_GitHub `yaml:"github"`
	// Use Google as authentication provider
	Google *ProviderConfig_Google `yaml:"google"`
	// Use MicrosoftEntraID as authentication provider
	MicrosoftEntraID *ProviderConfig_MicrosoftEntraID `yaml:"microsoftEntraID"`
	// Use OpenIDConnect as authentication provider
	OpenIDConnect *ProviderConfig_OpenIDConnect `yaml:"openIDConnect"`
	// Use TailscaleWhois as authentication provider
	TailscaleWhois *ProviderConfig_TailscaleWhois `yaml:"tailscaleWhois"`
	// Use PocketID as authentication provider
	PocketID *ProviderConfig_PocketID `yaml:"pocketID"`
	// Name of a test provider; used in tests only
	TestProvider *string `yaml:"testProvider" ignoredocs:"true"`

	// Parsed config object - internal
	configParsed ProviderConfig
}

type ConfigPortalHeader struct {
	// Name of the header.
	// +required
	// +example "X-Forwarded-User"
	Name string `yaml:"name"`
	// ID token claim to use as the header's value.
	// Only scalar values (strings, numbers, and booleans) are supported for the moment.
	// +example "email"
	Claim string `yaml:"claim"`
	// Property to use as the header's value.
	// Supported properties are `portal.name` and `provider.name`.
	// +example "portal.name"
	Property string `yaml:"property"`
}

// ConfigDev includes options using during development only
type ConfigDev struct {
	// If true, disables caching on the client
	DisableClientCache bool `yaml:"disableClientCache" ignoredocs:"true"`
}

// Internal properties
type internal struct {
	instanceID       string
	configFileLoaded string // Path to the config file that was loaded
	tokenSigningKey  jwk.Key
	pkceKey          []byte
}

// String implements fmt.Stringer and prints out the config for debugging
func (c *Config) String() string {
	enc, _ := json.Marshal(c)
	return string(enc)
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c *Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// SetLoadedConfigPath sets the path to the config file that was loaded
func (c *Config) SetLoadedConfigPath(filePath string) {
	c.internal.configFileLoaded = filePath
}

// GetTokenSigningKey returns the (parsed) token signing key
func (c *Config) GetTokenSigningKey() jwk.Key {
	return c.internal.tokenSigningKey
}

// GetInstanceID returns the instance ID.
func (c *Config) GetInstanceID() string {
	return c.internal.instanceID
}

// GetTokenAudienceClaim returns the value of the "aud" claim for the session token
func (c *Config) GetTokenAudienceClaim(cookieDomain string) string {
	if c.Tokens.SessionTokenAudience != "" {
		return c.Tokens.SessionTokenAudience
	}

	if cookieDomain == "" {
		// Could be empty in some test cases
		return "traefik-forward-auth" + c.Server.BasePath
	}

	return cookieDomain + c.Server.BasePath
}

// Process the configuration
func (c *Config) Process(log *slog.Logger) (err error) {
	// Check required variables
	err = c.Validate(log)
	if err != nil {
		return err
	}

	// Ensures the token signing key is present
	err = c.SetTokenSigningKey(log)
	if err != nil {
		return err
	}

	return nil
}

// Validate the configuration and performs some sanitization
func (c *Config) Validate(logger *slog.Logger) error {
	// Migrate the deprecated cookies.domain into the new server.domains structure
	// server.hostname is also deprecated and only honored as the auth host when migrating from cookies.domain
	err := c.migrateLegacyDomainConfig(logger)
	if err != nil {
		return err
	}

	// Validate, normalize and dedupe server.domains
	err = c.validateServerDomains()
	if err != nil {
		return err
	}

	// Base path
	if c.Server.BasePath != "" && c.Server.BasePath != "/" {
		c.Server.BasePath = strings.TrimSuffix(c.Server.BasePath, "/")
		if !strings.HasPrefix(c.Server.BasePath, "/") {
			c.Server.BasePath = "/" + c.Server.BasePath
		}
	}

	// Timeouts
	if c.Tokens.SessionLifetime < time.Minute {
		return errors.New("property 'tokens.sessionLifetime' is invalid: must be at least 1 minute")
	}

	// Parse portals' configurations and validate them
	if len(c.Portals) == 0 {
		return errors.New("at least one portal must be defined")
	}
	names := make(map[string]struct{}, len(c.Portals))
	for i := range c.Portals {
		err := c.Portals[i].Parse(c)
		if err != nil {
			if c.Portals[i].Name == "" {
				return fmt.Errorf("invalid portal at index %d: %w", i, err)
			}
			return fmt.Errorf("invalid portal '%s' (at index %d): %w", c.Portals[i].Name, i, err)
		}

		_, ok := names[c.Portals[i].Name]
		if ok {
			return fmt.Errorf("duplicate portal '%s' found", c.Portals[i].Name)
		}
		names[c.Portals[i].Name] = struct{}{}
	}

	// If there's a default portal, ensure it exists
	if c.DefaultPortal != "" {
		_, ok := names[c.DefaultPortal]
		if !ok {
			return fmt.Errorf("default portal '%s' does not exist in the configuration", c.DefaultPortal)
		}
	}

	return nil
}

// migrateLegacyDomainConfig handles the deprecated `cookies.domain` and `server.hostname` options
// `cookies.domain` is migrated into a single-element `server.domains` (using `server.hostname` as the auth host when set)
// `server.hostname` outside of the legacy migration path is ignored with a warning
func (c *Config) migrateLegacyDomainConfig(logger *slog.Logger) error {
	c.Cookies.Domain = NormalizeHostname(c.Cookies.Domain)
	c.Server.Hostname = NormalizeHostname(c.Server.Hostname)

	switch {
	case c.Cookies.Domain == "":
		// Without legacy cookies.domain, server.hostname has no use and is ignored
		if c.Server.Hostname != "" && logger != nil {
			logger.Warn("Configuration property 'server.hostname' is deprecated and ignored unless 'cookies.domain' is also set; use 'server.domains' instead")
		}
		c.Server.Hostname = ""

	case validators.IsIP(c.Cookies.Domain):
		return errors.New("property 'cookies.domain' is invalid: must be a valid hostname")

	case !validators.IsHostname(c.Cookies.Domain):
		return errors.New("property 'cookies.domain' is invalid: must be a valid hostname")

	case len(c.Server.Domains) > 0:
		return errors.New("legacy property 'cookies.domain' cannot be combined with 'server.domains'; use 'server.domains' only")

	default:
		// Migrate cookies.domain (and optionally server.hostname) into a single server.domains entry
		authHost := c.Server.Hostname
		if authHost == "" {
			authHost = c.Cookies.Domain
		}

		if logger != nil {
			logger.Warn(
				"Configuration property 'cookies.domain' is deprecated; migrate to 'server.domains' (and remove 'server.hostname' if set)",
				slog.String("migrated_domain", c.Cookies.Domain),
				slog.String("migrated_authHost", authHost),
			)
		}

		c.Server.Domains = []ConfigServerDomain{{
			Domain:   c.Cookies.Domain,
			AuthHost: authHost,
		}}
		c.Cookies.Domain = ""
		c.Server.Hostname = ""
	}

	return nil
}

// validateServerDomains validates each entry in `server.domains`, fills in default authHost values, and dedupes by domain
func (c *Config) validateServerDomains() error {
	if len(c.Server.Domains) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(c.Server.Domains))
	out := make([]ConfigServerDomain, 0, len(c.Server.Domains))
	for i, d := range c.Server.Domains {
		domain := NormalizeHostname(d.Domain)
		if domain == "" {
			return fmt.Errorf("property 'server.domains[%d].domain' is required", i)
		}
		if !validators.IsHostname(domain) {
			return fmt.Errorf("property 'server.domains[%d].domain' is invalid: must be a valid hostname", i)
		}

		// authHost defaults to the cookie domain when omitted (suitable for "sub-path" mode)
		authHost := NormalizeHostname(d.AuthHost)
		if authHost == "" {
			authHost = domain
		} else if !validators.IsHostname(authHost) {
			return fmt.Errorf("property 'server.domains[%d].authHost' is invalid: must be a valid hostname", i)
		}

		// authHost must be the same as, or a sub-domain of, the cookie domain
		// Otherwise the browser would not accept the cookie set on the auth host for requests to the app
		if !utils.IsSubDomain(domain, authHost) {
			return fmt.Errorf("property 'server.domains[%d].authHost' is invalid: must be the same as, or a sub-domain of, 'domain'", i)
		}

		// Dedupe values
		_, dup := seen[domain]
		if dup {
			continue
		}
		seen[domain] = struct{}{}

		out = append(out, ConfigServerDomain{Domain: domain, AuthHost: authHost})
	}

	c.Server.Domains = out
	return nil
}

var (
	portalProviderNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-_\.]{1,39}$`)
	errPortalProvider       = errors.New("property 'name' is invalid: must contain letters, numbers, or '-_.' only, must be between 2 and 40 characters, and must start with a letter")
)

func (p *ConfigPortal) GetAuthProviders(ctx context.Context) ([]auth.Provider, error) {
	providers := make([]auth.Provider, len(p.Providers))
	providerNames := make(map[string]struct{}, len(p.Providers))
	for i, v := range p.Providers {
		if v.configParsed == nil {
			return nil, fmt.Errorf("method Parse was not called on portal configuration object %d", i)
		}
		ap, err := v.configParsed.GetAuthProvider(ctx)
		if err != nil {
			return nil, err
		}

		md := v.configParsed.GetProviderMetadata()
		ap.SetProviderMetadata(md)

		name := ap.GetProviderName()
		_, ok := providerNames[name]
		if ok {
			return nil, fmt.Errorf("duplicate provider '%s' found in portal '%s'", name, md.Name)
		}
		providers[i] = ap
		providerNames[name] = struct{}{}
	}

	return providers, nil
}

func (p *ConfigPortal) Parse(c *Config) error {
	// Validate and sanitize name
	if p.Name == "" {
		return errors.New("property 'name' is required")
	}
	if !portalProviderNameRegex.MatchString(p.Name) {
		return errPortalProvider
	}
	p.Name = strings.ToLower(p.Name)

	// Set display name if currently unset
	if p.DisplayName == "" {
		p.DisplayName = p.Name
	}

	// Validate authentication timeout
	if p.AuthenticationTimeout < time.Millisecond {
		// Default authentication timeout
		p.AuthenticationTimeout = 5 * time.Minute
	}
	if p.AuthenticationTimeout < 5*time.Second {
		return errors.New("property 'authenticationTimeout' is invalid: must be at least 5 seconds")
	}

	// Validate session lifetime
	// A zero or negative value means use the default for the server, so we only need to check if positive values are at least 1 minute
	if p.SessionLifetime > 0 && p.SessionLifetime < time.Minute {
		return errors.New("property 'tokens.sessionLifetime' is invalid: must be at least 1 minute (a zero or negative value uses the default for the server)")
	}

	// Ensure there's at least one provider
	if len(p.Providers) == 0 {
		return errors.New("at least one authentication provider must be configured")
	}

	// Parse the providers' config
	for i := range p.Providers {
		err := p.Providers[i].Parse(c)
		if err != nil {
			return fmt.Errorf("invalid configuration for provider %d: %w", i, err)
		}
	}

	// Parse headers' configuration
	// If the property is nil, we use the default headers
	if p.Headers != nil {
		h := *p.Headers
		for i := range h {
			err := h[i].Parse(c)
			if err != nil {
				if h[i].Name == "" {
					return fmt.Errorf("invalid header at index %d: %w", i, err)
				}

				return fmt.Errorf("invalid header '%s' (at index %d): %w", h[i].Name, i, err)
			}
		}
	}

	return nil
}

func (v *ConfigPortalProvider) Parse(c *Config) (err error) {
	// Reset configParsed before anything
	v.configParsed = nil

	// Ensure there's one and only one provider defined
	count := countSetProperties(v)
	if count == 0 {
		return errors.New("no provider type configured for the provider")
	} else if count > 1 {
		return errors.New("cannot configure more than one provider type in each provider")
	}

	// At this point, we know one and only one of the switch cases will be true
	switch {
	case v.GitHub != nil:
		v.GitHub.Name, err = sanitizeProviderName(v.GitHub.Name)
		v.configParsed = v.GitHub
	case v.Google != nil:
		v.Google.Name, err = sanitizeProviderName(v.Google.Name)
		v.configParsed = v.Google
	case v.MicrosoftEntraID != nil:
		v.MicrosoftEntraID.Name, err = sanitizeProviderName(v.MicrosoftEntraID.Name)
		v.configParsed = v.MicrosoftEntraID
	case v.OpenIDConnect != nil:
		v.OpenIDConnect.Name, err = sanitizeProviderName(v.OpenIDConnect.Name)
		v.configParsed = v.OpenIDConnect
	case v.TailscaleWhois != nil:
		v.TailscaleWhois.Name, err = sanitizeProviderName(v.TailscaleWhois.Name)
		v.configParsed = v.TailscaleWhois
	case v.PocketID != nil:
		v.PocketID.Name, err = sanitizeProviderName(v.PocketID.Name)
		v.configParsed = v.PocketID
	case v.TestProvider != nil:
		fn, ok := testProviderConfigFactory[*v.TestProvider]
		if !ok {
			return fmt.Errorf("invalid test provider '%s'", *v.TestProvider)
		}
		v.configParsed = fn()
	default:
		// Indicates a development time error
		panic("Unhandled case")
	}
	if err != nil {
		v.configParsed = nil
		return err
	}

	v.configParsed.SetConfigObject(c)

	return nil
}

func (h *ConfigPortalHeader) Parse(c *Config) (err error) {
	if h.Name == "" {
		return errors.New("property 'name' is required")
	}

	// Either claim or property must be set
	if h.Claim == "" {
		switch h.Property {
		case "":
			return errors.New("property 'claim' or 'property' is required")
		case PropertyPortalName, PropertyProviderName:
			// Allowed properties, all good
			break
		default:
			return fmt.Errorf("invalid property '%s'", h.Property)
		}
	} else if h.Property != "" {
		return errors.New("properties 'claim' and 'property' are mutually exclusive")
	}

	return nil
}

func sanitizeProviderName(name string) (string, error) {
	// Sanitize the provider name if set
	if name != "" {
		if !portalProviderNameRegex.MatchString(name) {
			return "", errPortalProvider
		}
		name = strings.ToLower(name)
	}
	return name, nil
}

// SetTokenSigningKey parses the token signing key.
// If it's empty, will generate a new one.
func (c *Config) SetTokenSigningKey(logger *slog.Logger) (err error) {
	var tokenSigningKeyRaw []byte
	b := []byte(c.Tokens.SigningKey)

	// Try reading from file if present
	if len(b) == 0 && c.Tokens.SigningKeyFile != "" {
		b, err = os.ReadFile(c.Tokens.SigningKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read token signing key from file '%s': %w", c.Tokens.SigningKeyFile, err)
		}

		if len(b) == 0 {
			return fmt.Errorf("token signing key file '%s' is empty", c.Tokens.SigningKeyFile)
		}
	}

	// Ensure that the key is at least 20-character long (although ideally it's 32 or more, but enforcing some minimum standard)
	if len(b) > 0 && len(b) < 20 {
		return errors.New("token signing key is too short: must be at least 20 characters")
	}

	if len(b) == 0 {
		if logger != nil {
			logger.Debug("No 'tokens.signingKey' found in the configuration: a random one will be generated")
		}

		// Generate 64 random bytes
		// First 32 are for the token signing key
		// Last 32 are for the PKCE key
		buf := make([]byte, 64)
		_, err = io.ReadFull(rand.Reader, buf)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}

		tokenSigningKeyRaw = buf[:32]
		c.internal.pkceKey = buf[32:]
	} else {
		// Compute a HMAC to ensure the key is 256-bit long
		// We generate two keys: one for signing tokens, and one for PKCE
		h := hmac.New(crypto.SHA256.New, b)
		h.Write([]byte("tfa-token-signing-key"))
		tokenSigningKeyRaw = h.Sum(nil)

		h = hmac.New(crypto.SHA256.New, b)
		h.Write([]byte("tfa-pkce-key"))
		c.internal.pkceKey = h.Sum(nil)
	}

	// Import the token signing key as a jwk.Key
	c.internal.tokenSigningKey, err = jwk.Import(tokenSigningKeyRaw)
	if err != nil {
		return fmt.Errorf("failed to import token signing key as jwk.Key: %w", err)
	}

	// Calculate the key ID
	_ = c.internal.tokenSigningKey.Set(jwk.KeyIDKey, computeKeyId(tokenSigningKeyRaw))

	return nil
}

// Returns the key ID from a key
func computeKeyId(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[0:12])
}

// HasTLS returns true if the server is configured with TLS
func (s ConfigServer) HasTLS() bool {
	return s.TLSCertPEM != "" || s.TLSPath != ""
}

func countSetProperties(s any) int {
	typ := reflect.TypeOf(s)
	val := reflect.ValueOf(s)

	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
		val = val.Elem()
	}
	if typ.Kind() != reflect.Struct {
		// Indicates a development-time error
		panic("param must be a struct")
	}

	var count int
	for _, field := range val.Fields() {
		if field.IsValid() && !field.IsZero() {
			count++
		}
	}

	return count
}
