package config

import (
	"github.com/rs/zerolog"
)

// Config is the struct containing configuration
type Config struct {
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
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// SetLoadedConfigPath sets the path to the config file that was loaded
func (c *Config) SetLoadedConfigPath(filePath string) {
	c.internal.configFileLoaded = filePath
}

// Validates the configuration and performs some sanitization
func (c *Config) Validate(log *zerolog.Logger) (err error) {
	// Check required variables
	// TODO

	// Check for invalid values
	// TODO

	return nil
}
