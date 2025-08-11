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
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/validators"
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
	Dev ConfigDev `yaml:"-"`

	// Internal keys
	internal internal `yaml:"-"`
}

type ConfigServer struct {
	// The hostname the application is reached at.
	// This is used for setting the "redirect_uri" field for OAuth2 callbacks.
	// +required
	// +example "auth.example.com"
	Hostname string `yaml:"hostname"`

	// Port to bind to.
	// +default 4181
	Port int `yaml:"port"`

	// Address/interface to bind to.
	// +default "0.0.0.0"
	Bind string `yaml:"bind"`

	// Base path for all routes.
	// Set this if Traefik is forwarding requests to traefik-forward-auth for specific paths only.
	// Note: this does not apply to /api and /healthz routes
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
}

type ConfigCookies struct {
	// Domain name for setting cookies.
	// If empty, this is set to the value of the `hostname` property.
	// This value must either be the same as the `hostname` property, or the hostname must be a sub-domain of the cookie domain name.
	// +recommended
	// +example "auth.example.com"
	Domain string `yaml:"domain"`

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
	// Defaults to a value based on `cookies.domain` and `server.basePath` which is appropriate for the majority of cases. Most users should rely on the default value.
	SessionTokenAudience string `yaml:"sessionTokenAudience"`
}

type ConfigPortal struct {
	// Name of the portal, as used in the URL.
	// +required
	// +example "default"
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

	// List of allowed authentication providers.
	// At least one provider is required.
	// +required
	Providers []ConfigPortalProvider `yaml:"providers"`
}

type ConfigPortalProvider struct {
	// Authentication provider to use
	// +required
	// +example(github) "github"
	// +example(google) "google"
	// +example(microsoftentraid) "microsoftentraid"
	// +example(openidconnect) "openidconnect"
	// +example(tailscalewhois) "tailscalewhois"
	Provider string `yaml:"provider"`

	// Name of the authentication provider
	// Defaults to the name of the provider type
	// +example(github) "my-github-auth"
	// +example(google) "my-google-auth"
	// +example(microsoftentraid) "my-microsoft-entra-id-auth"
	// +example(openidconnect) "my-openid-auth"
	// +example(tailscalewhois) "my-tailscale-whois-auth"
	Name string `yaml:"name"`

	// Optional display name for the provider
	// Defaults to the standard display name for the provider
	// +example(github) "GitHub"
	// +example(google) "Google"
	// +example(microsoftentraid) "Microsoft Entra ID"
	// +example(openidconnect) "OpenID Connect"
	// +example(tailscalewhois) "Tailscale Whois"
	DisplayName string `yaml:"displayName"`

	// Optional icon for the provider
	// Defaults to the standard icon for the provider
	// +example(github) "github"
	// +example(google) "google"
	// +example(microsoftentraid) "microsoft"
	// +example(openidconnect) "openid"
	// +example(tailscalewhois) "tailscale"
	Icon string `yaml:"icon"`

	// Optional color scheme for the provider
	// Defaults to the standard color for the provider
	// +example(github) "green-to-blue"
	// +example(google) "red-to-yellow"
	// +example(microsoftentraid) "teal-to-lime"
	// +example(openidconnect) "purple-to-pink"
	// +example(tailscalewhois) "cyan-to-blue"
	Color string `yaml:"color"`

	// Configuration for the provider.
	// The properties depend on the provider type.
	Config map[string]any `yaml:"config"`

	// Parsed config object - internal
	configParsed ProviderConfig
}

// ConfigDev includes options using during development only
type ConfigDev struct {
	// Empty for now
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

// GetSessionTokenAudience returns the value of the "aud" claim for the session token
func (c *Config) GetTokenAudienceClaim() string {
	if c.Tokens.SessionTokenAudience != "" {
		return c.Tokens.SessionTokenAudience
	}
	return c.Server.Hostname + c.Server.BasePath
}

// Processes the configuration
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

// Validates the configuration and performs some sanitization
func (c *Config) Validate(logger *slog.Logger) error {
	// Hostname can have an optional port
	if c.Server.Hostname == "" {
		return errors.New("property 'server.hostname' is required and must be a valid hostname or IP")
	}

	host, port, err := net.SplitHostPort(c.Server.Hostname)
	if err == nil && host != "" && port != "" {
		isIP := validators.IsIP(c.Cookies.Domain)
		switch {
		case c.Cookies.Domain == "":
			c.Cookies.Domain = host
			if validators.IsIP(host) {
				// If Cookies.Domain is an IP, we must make it empty
				c.Cookies.Domain = ""
			}
		case !validators.IsHostname(c.Cookies.Domain) && !isIP:
			return errors.New("property 'cookies.domain' is invalid: must be a valid hostname or IP")
		case !isIP && !utils.IsSubDomain(c.Cookies.Domain, host):
			return errors.New("property 'server.hostname' must be a sub-domain of, or equal to, 'cookies.domain'")
		}
	} else {
		if !validators.IsHostname(c.Server.Hostname) && !validators.IsIP(c.Server.Hostname) {
			return errors.New("property 'server.hostname' is required and must be a valid hostname or IP")
		}

		isIP := validators.IsIP(c.Cookies.Domain)
		switch {
		case c.Cookies.Domain == "":
			c.Cookies.Domain = c.Server.Hostname
			if validators.IsIP(c.Server.Hostname) {
				// If the Cookies.Domain is an IP, we must make it empty
				c.Cookies.Domain = ""
			}
		case !validators.IsHostname(c.Cookies.Domain) && !isIP:
			return errors.New("property 'cookies.domain' is invalid: must be a valid hostname or IP")
		case !isIP && !utils.IsSubDomain(c.Cookies.Domain, c.Server.Hostname):
			return errors.New("property 'server.hostname' must be a sub-domain of, or equal to, 'cookies.domain'")
		}
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
		err = c.Portals[i].Parse(c)
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
		ap.SetProviderMetadata(v.GetProviderMetadata())

		name := ap.GetProviderName()
		_, ok := providerNames[name]
		if ok {
			return nil, fmt.Errorf("duplicate provider '%s' found in portal '%s'", name, v.Name)
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

	// Validate authenticatio timeout
	if p.AuthenticationTimeout < time.Millisecond {
		// Default authentication timeout
		p.AuthenticationTimeout = 5 * time.Minute
	}
	if p.AuthenticationTimeout < 5*time.Second {
		return errors.New("property 'authenticationTimeout' is invalid: must be at least 5 seconds")
	}

	// Parse the providers' config
	for i := range p.Providers {
		err := p.Providers[i].Parse(c)
		if err != nil {
			return fmt.Errorf("invalid configuration for provider %d: %w", i, err)
		}
	}

	return nil
}

func (v *ConfigPortalProvider) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        v.Name,
		DisplayName: v.DisplayName,
		Icon:        v.Icon,
		Color:       v.Color,
	}
}

func (v *ConfigPortalProvider) Parse(c *Config) error {
	// Sanitize the provider type
	v.Provider = strings.ReplaceAll(strings.ToLower(v.Provider), "-", "")
	if v.Provider == "" {
		return errors.New("property 'provider' is required")
	}

	// Sanitize the provider name if set
	if v.Name != "" {
		if !portalProviderNameRegex.MatchString(v.Name) {
			return errPortalProvider
		}
		v.Name = strings.ToLower(v.Name)
	}

	fn, ok := providerConfigFactory[v.Provider]
	if !ok {
		return fmt.Errorf("invalid value for 'provider': %s", v.Provider)
	}
	v.configParsed = fn()

	v.configParsed.SetConfigObject(c)
	err := ApplyProviderConfig(v.Config, v.configParsed)
	if err != nil {
		return fmt.Errorf("invalid config for provider '%s': %w", v.Provider, err)
	}

	return nil
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
