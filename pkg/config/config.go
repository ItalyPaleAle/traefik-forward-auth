package config

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/validators"
	"github.com/rs/zerolog"
)

// Config is the struct containing configuration
type Config struct {
	// The hostname the application is reached at.
	// This is used for setting the "redirect_uri" field for OAuth2 callbacks.
	// +required
	Hostname string `env:"HOSTNAME" yaml:"hostname"`

	// Domain name for setting cookies.
	// If empty, this is set to the value of the `hostname` property.
	// This value must either be the same as the `hostname` property, or the hostname must be a sub-domain of the cookie domain name.
	CookieDomain string `env:"COOKIEDOMAIN" yaml:"cookieDomain"`

	// Port to bind to.
	// +default 4181
	Port int `env:"PORT" yaml:"port"`

	// Address/interface to bind to.
	// +default "0.0.0.0"
	Bind string `env:"BIND" yaml:"bind"`

	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default info
	LogLevel string `env:"LOGLEVEL" yaml:"logLevel"`

	// Enable the metrics server, which exposes a Prometheus-compatible endpoint `/metrics`.
	// +default false
	EnableMetrics bool `env:"ENABLEMETRICS" yaml:"enableMetrics"`

	// Port for the metrics server to bind to.
	// +default 2112
	MetricsPort int `env:"METRICSPORT" yaml:"metricsPort"`

	// Address/interface for the metrics server to bind to.
	// +default "0.0.0.0"
	MetricsBind string `env:"METRICSBIND" yaml:"metricsBind"`

	// If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.
	// +default false
	OmitHealthCheckLogs bool `env:"OMITHEALTHCHECKLOGS" yaml:"omitHealthCheckLogs"`

	// String used as key to sign state tokens.
	// Can be generated for example with `openssl rand -base64 32`
	// If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).
	TokenSigningKey string `env:"TOKENSIGNINGKEY" yaml:"tokenSigningKey"`

	// Authentication method to use
	// Currently supported auth methods:
	//
	// - github
	// - google
	// - microsoft-entra-id
	// - oauth2
	//
	// +required
	AuthMethod string `env:"AUTHMETHOD" yaml:"authMethod"`

	// Client ID for the Google auth application
	// Ignored if `authMethod` is not `google`
	// +required
	AuthGoogleClientID string `env:"AUTHGOOGLE_CLIENTID" yaml:"authGoogle_clientID"`
	// Client secret for the Google auth application
	// Ignored if `authMethod` is not `google`
	// +required
	AuthGoogleClientSecret string `env:"AUTHGOOGLE_CLIENTSECRET" yaml:"authGoogle_clientSecret"`
	// Timeout for network requests for Google auth
	// Ignored if `authMethod` is not `google`
	// +default 10s
	AuthGoogleRequestTimeout time.Duration `env:"AUTHGOOGLE_REQUESTTIMEOUT" yaml:"authGoogle_requestTimeout"`

	// Client ID for the GitHub auth application
	// Ignored if `authMethod` is not `github`
	AuthGitHubClientID string `env:"AUTHGITHUB_CLIENTID" yaml:"authGitHub_clientID"`
	// Client secret for the GitHub auth application
	// Ignored if `authMethod` is not `github`
	AuthGitHubClientSecret string `env:"AUTHGITHUB_CLIENTSECRET" yaml:"authGitHub_clientSecret"`
	// Timeout for network requests for GitHub auth
	// Ignored if `authMethod` is not `github`
	// +default 10s
	AuthGitHubRequestTimeout time.Duration `env:"AUTHGITHUB_REQUESTTIMEOUT" yaml:"authGitHub_requestTimeout"`

	// Tenant ID for the Microsoft Entra ID auth application
	// Ignored if `authMethod` is not `microsoftentraid`
	AuthMicrosoftEntraIDTenantID string `env:"AUTHMICROSOFTENTRAID_TENANTID" yaml:"authMicrosoftEntraID_tenantID"`
	// Client ID for the Microsoft Entra ID auth application
	// Ignored if `authMethod` is not `microsoftentraid`
	AuthMicrosoftEntraIDClientID string `env:"AUTHMICROSOFTENTRAID_CLIENTID" yaml:"authMicrosoftEntraID_clientID"`
	// Client secret for the Microsoft Entra ID auth application
	// Ignored if `authMethod` is not `microsoftentraid`
	AuthMicrosoftEntraIDClientSecret string `env:"AUTHMICROSOFTENTRAID_CLIENTSECRET" yaml:"authMicrosoftEntraID_clientSecret"`
	// Timeout for network requests for Microsoft Entra ID auth
	// Ignored if `authMethod` is not `microsoftentraid`
	// +default 10s
	AuthMicrosoftEntraIDRequestTimeout time.Duration `env:"AUTHMICROSOFTENTRAID_REQUESTTIMEOUT" yaml:"authMicrosoftEntraID_requestTimeout"`

	// Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem`.
	// Vault watches for changes in this folder and automatically reloads the TLS certificates when they're updated.
	// If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.
	// +default Folder where the `config.yaml` file is located
	TLSPath string `env:"TLSPATH" yaml:"tlsPath"`

	// Full, PEM-encoded TLS certificate.
	// Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.
	TLSCertPEM string `env:"TLSCERTPEM" yaml:"tlsCertPEM"`

	// Full, PEM-encoded TLS key.
	// Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.
	TLSKeyPEM string `env:"TLSKEYPEM" yaml:"tlsKeyPEM"`

	// String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.
	// Common values include:
	//
	// - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id) that's vendor agnostic
	// - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)
	//
	// If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
	TrustedRequestIdHeader string `env:"TRUSTEDREQUESTIDHEADER" yaml:"trustedRequestIdHeader"`

	// Dev is meant for development only; it's undocumented
	Dev Dev `yaml:"-"`

	// Internal keys
	internal internal `yaml:"-"`
}

// Dev includes options using during development only
type Dev struct {
	// Empty for now
}

// Internal properties
type internal struct {
	configFileLoaded string // Path to the config file that was loaded
	tokenSigningKey  []byte
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// SetLoadedConfigPath sets the path to the config file that was loaded
func (c *Config) SetLoadedConfigPath(filePath string) {
	c.internal.configFileLoaded = filePath
}

// GetTokenSigningKey returns the (parsed) token signing key
func (c Config) GetTokenSigningKey() []byte {
	return c.internal.tokenSigningKey
}

// Validates the configuration and performs some sanitization
func (c *Config) Validate(log *zerolog.Logger) error {
	// Check required variables
	if c.Hostname == "" || (!validators.IsHostname(c.Hostname) && !validators.IsIP(c.Hostname)) {
		return errors.New("property 'hostname' is required and must be a valid hostname or IP")
	}

	c.AuthMethod = strings.ToLower(c.AuthMethod)
	if c.AuthMethod == "" {
		return errors.New("property 'authMethod' is required")
	}

	// Check for invalid values
	if c.CookieDomain == "" {
		c.CookieDomain = c.Hostname
	} else if !validators.IsHostname(c.CookieDomain) && !validators.IsIP(c.CookieDomain) {
		return errors.New("property 'cookieDomain' is invalid: must be a valid hostname or IP")
	} else if !utils.IsSubDomain(c.CookieDomain, c.Hostname) {
		return errors.New("property 'hostname' must be a sub-domain of, or equal to, 'cookieName'")
	}

	return nil
}

// SetTokenSigningKey parses the token signing key.
// If it's empty, will generate a new one.
func (c *Config) SetTokenSigningKey(logger *zerolog.Logger) (err error) {
	b := []byte(c.TokenSigningKey)
	if len(b) == 0 {
		if logger != nil {
			logger.Debug().Msg("No 'tokenSigningKey' found in the configuration: a random one will be generated")
		}

		c.internal.tokenSigningKey = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, c.internal.tokenSigningKey)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
		return nil
	}

	// Compute a HMAC to ensure the key is 256-bit long
	h := hmac.New(crypto.SHA256.New, b)
	h.Write([]byte("revaulter-token-signing-key"))
	c.internal.tokenSigningKey = h.Sum(nil)

	return nil
}
