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
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/validators"
)

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
	AuthProvider string `env:"AUTHPROVIDER" yaml:"authProvider"`

	// Client ID for the Google auth application
	// Ignored if `authProvider` is not `google`
	AuthGoogleClientID string `env:"AUTHGOOGLE_CLIENTID" yaml:"authGoogle_clientID"`
	// Client secret for the Google auth application
	// Ignored if `authProvider` is not `google`
	AuthGoogleClientSecret string `env:"AUTHGOOGLE_CLIENTSECRET" yaml:"authGoogle_clientSecret"`
	// List of allowed users for Google auth
	// This is a list of user IDs
	// Ignored if `authProvider` is not `google`
	AuthGoogleAllowedUsers []string `env:"AUTHGOOGLE_ALLOWEDUSERS" yaml:"authGoogle_allowedUsers"`
	// List of allowed email addresses of users for Google auth
	// This is a list of email addresses
	// Ignored if `authProvider` is not `google`
	AuthGoogleAllowedEmails []string `env:"AUTHGOOGLE_ALLOWEDEMAILS" yaml:"authGoogle_allowedEmails"`
	// List of allowed domains for Google auth
	// This is a list of domains for email addresses
	// Ignored if `authProvider` is not `google`
	AuthGoogleAllowedDomains []string `env:"AUTHGOOGLE_ALLOWEDDOMAINS" yaml:"authGoogle_allowedDomains"`
	// Timeout for network requests for Google auth
	// Ignored if `authProvider` is not `google`
	// +default 10s
	AuthGoogleRequestTimeout time.Duration `env:"AUTHGOOGLE_REQUESTTIMEOUT" yaml:"authGoogle_requestTimeout"`

	// Client ID for the GitHub auth application
	// Ignored if `authProvider` is not `github`
	AuthGitHubClientID string `env:"AUTHGITHUB_CLIENTID" yaml:"authGitHub_clientID"`
	// Client secret for the GitHub auth application
	// Ignored if `authProvider` is not `github`
	AuthGitHubClientSecret string `env:"AUTHGITHUB_CLIENTSECRET" yaml:"authGitHub_clientSecret"`
	// List of allowed users for GitHub auth
	// This is a list of usernames
	// Ignored if `authProvider` is not `github`
	AuthGitHubAllowedUsers []string `env:"AUTHGITHUB_ALLOWEDUSERS" yaml:"authGitHub_allowedUsers"`
	// Timeout for network requests for GitHub auth
	// Ignored if `authProvider` is not `github`
	// +default 10s
	AuthGitHubRequestTimeout time.Duration `env:"AUTHGITHUB_REQUESTTIMEOUT" yaml:"authGitHub_requestTimeout"`

	// Tenant ID for the Microsoft Entra ID auth application
	// Ignored if `authProvider` is not `microsoftentraid`
	AuthMicrosoftEntraIDTenantID string `env:"AUTHMICROSOFTENTRAID_TENANTID" yaml:"authMicrosoftEntraID_tenantID"`
	// Client ID for the Microsoft Entra ID auth application
	// Ignored if `authProvider` is not `microsoftentraid`
	AuthMicrosoftEntraIDClientID string `env:"AUTHMICROSOFTENTRAID_CLIENTID" yaml:"authMicrosoftEntraID_clientID"`
	// Client secret for the Microsoft Entra ID auth application
	// Ignored if `authProvider` is not `microsoftentraid`
	AuthMicrosoftEntraIDClientSecret string `env:"AUTHMICROSOFTENTRAID_CLIENTSECRET" yaml:"authMicrosoftEntraID_clientSecret"`
	// Enables the usage of Federated Identity Credentials to obtain assertions for confidential clients for Microsoft Entra ID applications.
	// This is an alternative to using client secrets, when the application is running in Azure in an environment that supports Managed Identity, or in an environment that supports Workload Identity Federation with Microsoft Entra ID.
	// Currently, these values are supported:
	//
	// - `ManagedIdentity`: uses a system-assigned managed identity
	// - `ManagedIdentity=client-id`: uses a user-assigned managed identity with client id "client-id" (e.g. "ManagedIdentity=00000000-0000-0000-0000-000000000000")
	// - `WorkloadIdentity`: uses workload identity, e.g. for Kubernetes
	AuthMicrosoftEntraIDAzureFederatedIdentity string `env:"AUTHMICROSOFTENTRAID_AZUREFEDERATEDIDENTITY" yaml:"authMicrosoftEntraID_azureFederatedIdentity"`
	// List of allowed users for Microsoft Entra ID auth
	// This is a list of user IDs
	// Ignored if `authProvider` is not `microsoftentraid`
	AuthMicrosoftEntraIDAllowedUsers []string `env:"AUTHMICROSOFTENTRAID_ALLOWEDUSERS" yaml:"authMicrosoftEntraID_allowedUsers"`
	// List of allowed email addresses of users for Microsoft Entra ID auth
	// This is a list of email addresses
	// Ignored if `authProvider` is not `microsoftentraid`
	AuthMicrosoftEntraIDAllowedEmails []string `env:"AUTHMICROSOFTENTRAID_ALLOWEDEMAILS" yaml:"authMicrosoftEntraID_allowedEmails"`
	// Timeout for network requests for Microsoft Entra ID auth
	// Ignored if `authProvider` is not `microsoftentraid`
	// +default 10s
	AuthMicrosoftEntraIDRequestTimeout time.Duration `env:"AUTHMICROSOFTENTRAID_REQUESTTIMEOUT" yaml:"authMicrosoftEntraID_requestTimeout"`

	// Client ID for the OpenID Connect auth application
	// Ignored if `authProvider` is not `openidconnect`
	AuthOpenIDConnectClientID string `env:"AUTHOPENIDCONNECT_CLIENTID" yaml:"authOpenIDConnect_clientID"`
	// Client secret for the OpenID Connect auth application
	// Ignored if `authProvider` is not `openidconnect`
	AuthOpenIDConnectClientSecret string `env:"AUTHOPENIDCONNECT_CLIENTSECRET" yaml:"authOpenIDConnect_clientSecret"`
	// OpenID Connect token issuer
	// The OpenID Connect configuration document will be fetched at `<token-issuer>/.well-known/openid-configuration`
	// Ignored if `authProvider` is not `openidconnect`
	AuthOpenIDConnectTokenIssuer string `env:"AUTHOPENIDCONNECT_TOKENISSUER" yaml:"authOpenIDConnect_tokenIssuer"`
	// List of allowed users for OpenID Connect auth
	// This is a list of user IDs, as returned by the ID provider in the "sub" claim
	// Ignored if `authProvider` is not `openidconnect`
	AuthOpenIDConnectAllowedUsers []string `env:"AUTHOPENIDCONNECT_ALLOWEDUSERS" yaml:"authOpenIDConnect_allowedUsers"`
	// List of allowed email addresses for users for OpenID Connect auth
	// This is a list of email addresses, as returned by the ID provider in the "email" claim
	// Ignored if `authProvider` is not `openidconnect`
	AuthOpenIDConnectAllowedEmails []string `env:"AUTHOPENIDCONNECT_ALLOWEDEMAILS" yaml:"authOpenIDConnect_allowedEmails"`
	// Timeout for network requests for OpenID Connect auth
	// Ignored if `authProvider` is not `openidconnect`
	// +default 10s
	AuthOpenIDConnectRequestTimeout time.Duration `env:"AUTHOPENIDCONNECT_REQUESTTIMEOUT" yaml:"authOpenIDConnect_requestTimeout"`
	// If true, enables the use of PKCE during the code exchange.
	// Ignored if `authProvider` is not `openidconnect`
	// +default false
	AuthOpenIDConnectEnablePKCE bool `env:"AUTHOPENIDCONNECT_ENABLEPKCE" yaml:"authOpenIDConnect_enablePKCE"`

	// If non-empty, requires the Tailnet of the user to match this value
	// Ignored if `authProvider` is not `tailscalewhois`
	AuthTailscaleWhoisAllowedTailnet string `env:"AUTHTAILSCALEWHOIS_ALLOWEDTAILNET" yaml:"authTailscaleWhois_allowedTailnet"`
	// List of allowed users for Tailscale Whois auth
	// This is a list of user IDs as returned by the ID provider
	// Ignored if `authProvider` is not `tailscalewhois`
	AuthTailscaleConnectAllowedUsers []string `env:"AUTHTAILSCALECONNECT_ALLOWEDUSERS" yaml:"authTailscaleConnect_allowedUsers"`
	// Timeout for network requests for Tailscale Whois auth
	// Ignored if `authProvider` is not `tailscalewhois`
	// +default 10s
	AuthTailscaleWhoisRequestTimeout time.Duration `env:"AUTHTAILSCALEWHOIS_REQUESTTIMEOUT" yaml:"authTailscaleWhois_requestTimeout"`

	// Timeout for authenticating with the authentication provider.
	// +default 5m
	AuthenticationTimeout time.Duration `env:"AUTHENTICATIONTIMEOUT" yaml:"authenticationTimeout"`

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
	// Sanitize AuthProvider
	c.AuthProvider = strings.ReplaceAll(strings.ToLower(c.AuthProvider), "-", "")
	if c.AuthProvider == "" {
		return errors.New("property 'authProvider' is required")
	}

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
	if c.AuthenticationTimeout < 5*time.Second {
		return errors.New("property 'authenticationTimeout' is invalid: must be at least 5 seconds")
	}

	return nil
}

// GetProvider returns the auth provider.
func (c *Config) GetAuthProvider() (auth.Provider, error) {
	switch c.AuthProvider {
	case "github":
		return auth.NewGitHub(auth.NewGitHubOptions{
			ClientID:       c.AuthGitHubClientID,
			ClientSecret:   c.AuthGitHubClientSecret,
			AllowedUsers:   c.AuthGitHubAllowedUsers,
			RequestTimeout: c.AuthGitHubRequestTimeout,
		})
	case "google":
		return auth.NewGoogle(auth.NewGoogleOptions{
			ClientID:       c.AuthGoogleClientID,
			ClientSecret:   c.AuthGoogleClientSecret,
			AllowedUsers:   c.AuthGoogleAllowedUsers,
			AllowedEmails:  c.AuthGoogleAllowedEmails,
			AllowedDomains: c.AuthGoogleAllowedDomains,
			RequestTimeout: c.AuthGoogleRequestTimeout,
		})
	case "microsoftentraid", "azuread", "aad", "entraid":
		return auth.NewMicrosoftEntraID(auth.NewMicrosoftEntraIDOptions{
			TenantID:               c.AuthMicrosoftEntraIDTenantID,
			ClientID:               c.AuthMicrosoftEntraIDClientID,
			ClientSecret:           c.AuthMicrosoftEntraIDClientSecret,
			AzureFederatedIdentity: c.AuthMicrosoftEntraIDAzureFederatedIdentity,
			AllowedUsers:           c.AuthMicrosoftEntraIDAllowedUsers,
			RequestTimeout:         c.AuthMicrosoftEntraIDRequestTimeout,
			PKCEKey:                c.internal.pkceKey,
		})
	case "openidconnect", "oidc":
		var pkceKey []byte
		if c.AuthOpenIDConnectEnablePKCE {
			pkceKey = c.internal.pkceKey
		}
		return auth.NewOpenIDConnect(auth.NewOpenIDConnectOptions{
			ClientID:       c.AuthOpenIDConnectClientID,
			ClientSecret:   c.AuthOpenIDConnectClientSecret,
			TokenIssuer:    c.AuthOpenIDConnectTokenIssuer,
			AllowedUsers:   c.AuthOpenIDConnectAllowedUsers,
			AllowedEmails:  c.AuthOpenIDConnectAllowedEmails,
			RequestTimeout: c.AuthOpenIDConnectRequestTimeout,
			PKCEKey:        pkceKey,
		})
	case "tailscalewhois", "tailscale":
		return auth.NewTailscaleWhois(auth.NewTailscaleWhoisOptions{
			AllowedTailnet: c.AuthTailscaleWhoisAllowedTailnet,
			AllowedUsers:   c.AuthTailscaleConnectAllowedUsers,
			RequestTimeout: c.AuthTailscaleWhoisRequestTimeout,
		})
	default:
		return nil, fmt.Errorf("invalid value for 'authProvider': %s", c.AuthProvider)
	}
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
