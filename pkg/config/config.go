package config

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Config is the struct containing configuration
type Config struct {
	// Port to bind to.
	// +default 4181
	Port int `yaml:"port"`

	// Address/interface to bind to.
	// +default "0.0.0.0"
	Bind string `yaml:"bind"`

	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default info
	LogLevel string `yaml:"logLevel"`

	// Enable the metrics server, which exposes a Prometheus-compatible endpoint `/metrics`.
	// +default false
	EnableMetrics bool `yaml:"enableMetrics"`

	// Port for the metrics server to bind to.
	// +default 2112
	MetricsPort int `yaml:"metricsPort"`

	// Address/interface for the metrics server to bind to.
	// +default "0.0.0.0"
	MetricsBind string `yaml:"metricsBind"`

	// If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.
	// +default false
	OmitHealthCheckLogs bool `yaml:"omitHealthCheckLogs"`

	// String used as key to sign state tokens.
	// Can be generated for example with `openssl rand -base64 32`
	// If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).
	TokenSigningKey string `yaml:"tokenSigningKey"`

	// Authentication method to use
	// Currently supported auth methods:
	//
	// - github
	// - google
	// - microsoft-entra-id
	// - oauth2
	//
	// +required
	AuthMethod string `yaml:"authMethod"`

	// Configuration for the Google auth method
	// Ignored if `authMethod` is not `google`
	Google struct {
		// Client ID for the application
		// +required
		ClientID string `yaml:"clientID"`
		// Client secret for the application
		// +required
		ClientSecret string `yaml:"clientSecret"`
		// Timeout for network requests
		// +default 10s
		RequestTimeout time.Duration `yaml:"requestTimeout"`
	} `yaml:"google"`

	// Configuration for the GitHub auth method
	// Ignored if `authMethod` is not `github`
	GitHub struct {
		// Client ID for the application
		// +required
		ClientID string `yaml:"clientID"`
		// Client secret for the application
		// +required
		ClientSecret string `yaml:"clientSecret"`
		// Timeout for network requests
		// +default 10s
		RequestTimeout time.Duration `yaml:"requestTimeout"`
	} `yaml:"github"`

	// Configuration for the Microsoft Entra ID auth method
	// Ignored if `authMethod` is not `microsoftentraid`
	MicrosoftEntraID struct {
		// Tenant ID for the application
		// +required
		TenantID string `yaml:"tenantID"`
		// Client ID for the application
		// +required
		ClientID string `yaml:"clientID"`
		// Client secret for the application
		// +required
		ClientSecret string `yaml:"clientSecret"`
		// Timeout for network requests
		// +default 10s
		RequestTimeout time.Duration `yaml:"requestTimeout"`
	} `yaml:"microsoftEntraID"`

	// String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.
	// Common values include:
	//
	// - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id) that's vendor agnostic
	// - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)
	//
	// If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
	TrustedRequestIdHeader string `yaml:"trustedRequestIdHeader"`

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
	c.AuthMethod = strings.ToLower(c.AuthMethod)
	if c.AuthMethod == "" {
		return fmt.Errorf("property 'authMethod' is required")
	}

	// Check for invalid values
	// TODO

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
