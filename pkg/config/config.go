package config

import (
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
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

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

	// Metrics configuration
	Metrics ConfigMetrics `yaml:"metrics"`

	// Tracing configuration
	Tracing ConfigTracing `yaml:"tracing"`

	// List of portals
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
	Hostname string `env:"SERVER_HOSTNAME" yaml:"hostname"`

	// Port to bind to.
	// +default 4181
	Port int `env:"SERVER_PORT" yaml:"port"`

	// Address/interface to bind to.
	// +default "0.0.0.0"
	Bind string `env:"SERVER_BIND" yaml:"bind"`

	// Base path for all routes.
	// Set this if Traefik is forwarding requests to traefik-forward-auth for specific paths only.
	// Note: this does not apply to /api and /healthz routes
	BasePath string `env:"SERVER_BASEPATH" yaml:"basePath"`

	// Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem` (and optionally `tls-ca.pem`).
	// The server watches for changes in this folder and automatically reloads the TLS certificates when they're updated.
	// If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.
	// +default Folder where the `config.yaml` file is located
	TLSPath string `env:"SERVER_TLSPATH" yaml:"tlsPath"`

	// Full, PEM-encoded TLS certificate.
	// Using `server.tlsCertPEM` and `server.tlsKeyPEM` is an alternative method of passing TLS certificates than using `server.tlsPath`.
	TLSCertPEM string `env:"SERVER_TLSCERTPEM" yaml:"tlsCertPEM"`

	// Full, PEM-encoded TLS key.
	// Using `server.tlsCertPEM` and `server.tlsKeyPEM` is an alternative method of passing TLS certificates than using `server.tlsPath`.
	TLSKeyPEM string `env:"SERVER_TLSKEYPEM" yaml:"tlsKeyPEM"`

	// Full, PEM-encoded TLS CA certificate, used for TLS client authentication (mTLS).
	// This is an alternative method of passing the CA certificate than using `tlsPath`.
	// Note that this is ignored unless `server.tlsClientAuth` is set to `true`.
	TLSCAPEM string `env:"SERVER_TLSCAPEM" yaml:"tlsCAPEM"`

	// If true, enables mTLS for client authentication.
	// Requests to the root endpoint (normally used by Traefik) must have a valid client certificate signed by the CA.
	// +default false
	TLSClientAuth bool `env:"SERVER_TLSCLIENTAUTH" yaml:"tlsClientAuth"`

	// String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.
	// Common values include:
	//
	// - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id) that's vendor agnostic
	// - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)
	//
	// If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
	TrustedRequestIdHeader string `env:"SERVER_TRUSTEDREQUESTIDHEADER" yaml:"trustedRequestIdHeader"`
}

type ConfigCookies struct {
	// Domain name for setting cookies.
	// If empty, this is set to the value of the `hostname` property.
	// This value must either be the same as the `hostname` property, or the hostname must be a sub-domain of the cookie domain name.
	// +recommended
	Domain string `env:"COOKIES_DOMAIN" yaml:"domain"`

	// Prefix for the cookies used to store the sessions.
	// +default "tf_sess"
	NamePrefix string `env:"COOKIES_NAME" yaml:"namePrefix"`

	// If true, sets cookies as "insecure", which are served on HTTP endpoints too.
	// By default, this is false and cookies are sent on HTTPS endpoints only.
	// +default false
	Insecure bool `env:"COOKIES_INSECURE" yaml:"insecure"`
}

type ConfigLogs struct {
	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default "info"
	Level string `env:"LOGS_LEVEL" yaml:"level"`

	// If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.
	// +default true
	OmitHealthChecks bool `env:"LOGS_OMITHEALTHCHECKS" yaml:"omitHealthChecks"`

	// If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.
	// +default false if a TTY is attached (e.g. in development); true otherwise.
	JSON bool `env:"LOGS_JSON" yaml:"json"`

	// OpenTelemetry Collector endpoint for sending logs, for example: `<http(s)>://<otel-collector-address>:<otel-collector-port>/v1/logs`.
	// If configured,logs are sent to the collector at the given address.
	// This value can also be set using the environmental variables `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` ("/v1/logs" is appended for HTTP), and optionally `OTEL_EXPORTER_OTLP_PROTOCOL` ("http/protobuf", the default, or "grpc").
	OtelCollectorEndpoint string `env:"LOGS_OTELCOLLECTORENDPOINT" yaml:"otelCollectorEndpoint"`
}

type ConfigMetrics struct {
	// Enable the metrics server, which exposes a Prometheus-compatible endpoint `/metrics`.
	// +default false
	ServerEnabled bool `env:"METRICS_SERVERENABLED" yaml:"serverEnabled"`

	// Port for the metrics server to bind to.
	// +default 2112
	ServerPort int `env:"METRICS_SERVERPORT" yaml:"serverPort"`

	// Address/interface for the metrics server to bind to.
	// +default "0.0.0.0"
	ServerBind string `env:"METRICS_SERVERBIND" yaml:"serverBind"`

	// OpenTelemetry Collector endpoint for sending metrics, for example: `<http(s)-or-grpc(s)>://<otel-collector-address>:<otel-collector-port>/v1/metrics`
	// If metrics are enabled and `metricsOtelCollectorEndpoint` is set, metrics are sent to the collector
	// This value can also be set using the environmental variables `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` ("/v1/metrics" is appended for HTTP), and optionally `OTEL_EXPORTER_OTLP_PROTOCOL` ("http/protobuf", the default, or "grpc")
	OtelCollectorEndpoint string `env:"METRICS_OTELCOLLECTORENDPOINT" yaml:"otelCollectorEndpoint"`
}

type ConfigTracing struct {
	// Sampling rate for traces, as a float.
	// The default value is 1, sampling all requests.
	// +default 1
	Sampling float64 `env:"TRACING_SAMPLING" yaml:"sampling"`

	// OpenTelemetry Collector endpoint for sending traces, for example: `<http(s)-or-grpc(s)>://<otel-collector-address>:<otel-collector-port>/v1/traces`.
	// If `tracingOtelCollectorEndpoint` is set, tracing is enabled and sent to the collector.
	// This value can also be set using the environmental variables `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` ("/v1/traces" is appended for HTTP), and optionally `OTEL_EXPORTER_OTLP_PROTOCOL` ("http/protobuf", the default, or "grpc").
	OtelCollectorEndpoint string `env:"TRACING_OTELCOLLECTORENDPOINT" yaml:"otelCollectorEndpoint"`
}

type ConfigTokens struct {
	// Lifetime for sessions after a successful authentication.
	// +default 2h
	SessionLifetime time.Duration `env:"TOKENS_SESSIONLIFETIME" yaml:"sessionLifetime"`

	// String used as key to sign state tokens.
	// Can be generated for example with `openssl rand -base64 32`
	// If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).
	SigningKey string `env:"TOKENS_SIGNINGKEY" yaml:"signingKey"`
}

type ConfigPortal struct {
	// Name of the portal, as used in the URL.
	// +required
	Name string `yaml:"name"`

	// Optional display name.
	// Defaults to the `name` property otherwise
	DisplayName string `yaml:"displayName"`

	// Authentication provider to use
	// Currently supported providers:
	//
	// - `github`
	// - `google`
	// - `microsoftentraid`
	// - `openidconnect`
	// - `tailscalewhois`
	//
	// +required
	Provider string `yaml:"provider"`

	// Configuration for the provider.
	// The properties depend on the provider type.
	Config map[string]any `yaml:"config"`

	// Parsed config object
	configParsed ProviderConfig

	// Timeout for authenticating with the authentication provider.
	// +default 5m
	AuthenticationTimeout time.Duration `yaml:"authenticationTimeout"`
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

// Validates the configuration and performs some sanitization
func (c *Config) Validate(logger *slog.Logger) error {
	// Validate tracing config
	if c.Tracing.Sampling < 0 || c.Tracing.Sampling > 1 {
		return errors.New("config key 'tracing.sampling' is invalid: must be between 0 and 1 (inclusive)")
	}

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
				// If the CookieDomain is an IP, we must make it empty
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
				// If the CookieDomain is an IP, we must make it empty
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
		err = c.Portals[i].Parse()
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

	return nil
}

var portalNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-_\.]{2,39}$`)

func (p *ConfigPortal) Parse() error {
	// Sanitize AuthProvider
	p.Provider = strings.ReplaceAll(strings.ToLower(p.Provider), "-", "")
	if p.Provider == "" {
		return errors.New("property 'provider' is required")
	}

	// Validate and sanitize name
	if p.Name == "" {
		return errors.New("property 'name' is required")
	}
	if !portalNameRegex.MatchString(p.Name) {
		return errors.New("property 'name' is invalid: must contain letters, numbers, or '-_.' only, must be between 3 and 40 characters, and must start with a letter")
	}
	p.Name = strings.ToLower(p.Name)

	// Validate authenticatio timeout
	if p.AuthenticationTimeout < time.Millisecond {
		// Default authentication timeout
		p.AuthenticationTimeout = 5 * time.Minute
	}
	if p.AuthenticationTimeout < 5*time.Second {
		return errors.New("property 'authenticationTimeout' is invalid: must be at least 5 seconds")
	}

	// Parse the provider's config
	switch p.Provider {
	case "github":
		p.configParsed = &ProviderConfig_GitHub{}
		err := ApplyProviderConfig(p.Config, p.configParsed)
		if err != nil {
			return fmt.Errorf("invalid config for provider 'github': %w", err)
		}
	case "google":
		p.configParsed = &ProviderConfig_Google{}
		err := ApplyProviderConfig(p.Config, p.configParsed)
		if err != nil {
			return fmt.Errorf("invalid config for provider 'google': %w", err)
		}
	case "microsoftentraid", "azuread", "aad", "entraid":
		p.configParsed = &ProviderConfig_MicrosoftEntraID{}
		err := ApplyProviderConfig(p.Config, p.configParsed)
		if err != nil {
			return fmt.Errorf("invalid config for provider 'microsoftentraid': %w", err)
		}
	case "openidconnect", "oidc":
		p.configParsed = &ProviderConfig_OpenIDConnect{}
		err := ApplyProviderConfig(p.Config, p.configParsed)
		if err != nil {
			return fmt.Errorf("invalid config for provider 'openidconnect': %w", err)
		}
	case "tailscalewhois", "tailscale":
		p.configParsed = &ProviderConfig_TailscaleWhois{}
		err := ApplyProviderConfig(p.Config, p.configParsed)
		if err != nil {
			return fmt.Errorf("invalid config for provider 'tailscalewhois': %w", err)
		}
	default:
		return fmt.Errorf("invalid value for 'provider': %s", p.Provider)
	}

	return nil
}

// SetTokenSigningKey parses the token signing key.
// If it's empty, will generate a new one.
func (c *Config) SetTokenSigningKey(logger *slog.Logger) (err error) {
	var tokenSigningKeyRaw []byte
	b := []byte(c.Tokens.SigningKey)
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
	c.internal.tokenSigningKey, err = jwk.FromRaw(tokenSigningKeyRaw)
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
