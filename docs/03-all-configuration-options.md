# 📖 All configuration options

<!-- BEGIN CONFIG TABLE -->
## Root configuration object

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-server-hostname"></a>`server.hostname` | string | The hostname the application is reached at.<br>This is used for setting the "redirect_uri" field for OAuth2 callbacks.| **Required** |
| <a id="config-opt-server-port"></a>`server.port` | number | Port to bind to.| Default: _4181_ |
| <a id="config-opt-server-bind"></a>`server.bind` | string | Address/interface to bind to.| Default: _"0.0.0.0"_ |
| <a id="config-opt-server-basepath"></a>`server.basePath` | string | Base path for all routes.<br>Set this if Traefik is forwarding requests to traefik-forward-auth for specific paths only.<br>Note: this does not apply to /api and /healthz routes|  |
| <a id="config-opt-server-tlspath"></a>`server.tlsPath` | string | Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem` (and optionally `tls-ca.pem`).<br>The server watches for changes in this folder and automatically reloads the TLS certificates when they're updated.<br>If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.| Default: _Folder where the `config.yaml` file is located_ |
| <a id="config-opt-server-tlscertpem"></a>`server.tlsCertPEM` | string | Full, PEM-encoded TLS certificate.<br>Using `server.tlsCertPEM` and `server.tlsKeyPEM` is an alternative method of passing TLS certificates than using `server.tlsPath`.|  |
| <a id="config-opt-server-tlskeypem"></a>`server.tlsKeyPEM` | string | Full, PEM-encoded TLS key.<br>Using `server.tlsCertPEM` and `server.tlsKeyPEM` is an alternative method of passing TLS certificates than using `server.tlsPath`.|  |
| <a id="config-opt-server-tlscapem"></a>`server.tlsCAPEM` | string | Full, PEM-encoded TLS CA certificate, used for TLS client authentication (mTLS).<br>This is an alternative method of passing the CA certificate than using `tlsPath`.<br>Note that this is ignored unless `server.tlsClientAuth` is set to `true`.|  |
| <a id="config-opt-server-tlsclientauth"></a>`server.tlsClientAuth` | boolean | If true, enables mTLS for client authentication.<br>Requests to the root endpoint (normally used by Traefik) must have a valid client certificate signed by the CA.| Default: _false_ |
| <a id="config-opt-server-trustedrequestidheader"></a>`server.trustedRequestIdHeader` | string | String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.<br>Common values include:<br><br>- `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id) that's vendor agnostic<br>- `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)<br><br>If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.|  |
| <a id="config-opt-cookies-domain"></a>`cookies.domain` | string | Domain name for setting cookies.<br>If empty, this is set to the value of the `hostname` property.<br>This value must either be the same as the `hostname` property, or the hostname must be a sub-domain of the cookie domain name.| Recommended |
| <a id="config-opt-cookies-nameprefix"></a>`cookies.namePrefix` | string | Prefix for the cookies used to store the sessions.| Default: _"tf_sess"_ |
| <a id="config-opt-cookies-insecure"></a>`cookies.insecure` | boolean | If true, sets cookies as "insecure", which are served on HTTP endpoints too.<br>By default, this is false and cookies are sent on HTTPS endpoints only.| Default: _false_ |
| <a id="config-opt-tokens-sessionlifetime"></a>`tokens.sessionLifetime` | duration | Lifetime for sessions after a successful authentication.| Default: _"2h"_ |
| <a id="config-opt-tokens-signingkey"></a>`tokens.signingKey` | string | String used as key to sign state tokens.<br>Can be generated for example with `openssl rand -base64 32`<br>If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).|  |
| <a id="config-opt-tokens-signingkeyfile"></a>`tokens.signingKeyFile` | string | File containing the key used to sign state tokens.<br>This is an alternative to specifying `signingKey` tokens.directly.|  |
| <a id="config-opt-tokens-sessiontokenaudience"></a>`tokens.sessionTokenAudience` | string | Value for the audience claim to expect in session tokens used by Traefik Forward Auth.<br>Defaults to a value based on `cookies.domain` and `server.basePath` which is appropriate for the majority of cases. Most users should rely on the default value.|  |
| <a id="config-opt-logs-level"></a>`logs.level` | string | Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.| Default: _"info"_ |
| <a id="config-opt-logs-omithealthchecks"></a>`logs.omitHealthChecks` | boolean | If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.| Default: _true_ |
| <a id="config-opt-logs-json"></a>`logs.json` | boolean | If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.<br>Defaults to false if a TTY is attached (e.g. in development); true otherwise.|  |
| <a id="config-opt-defaultportal"></a>`defaultPortal` | string | If set to the name of a portal defined in "portals", it makes the portal available on the root endpoint, without the `portals/<name>/` prefix|  |
| <a id="config-opt-portals"></a>`portals`| list of [portal configurations](#portal-configuration) | List of portals.<br>See the [portal configuration](#portal-configuration) section for more details. | **Required**<br>At least one configured portal and provider is required |

## Portal configuration

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-portals-name"></a>`name` | string | Name of the portal, as used in the URL.| **Required** |
| <a id="config-opt-portals-displayname"></a>`displayName` | string | Optional display name.<br>Defaults to the `name` property if not set.|  |
| <a id="config-opt-portals-alwaysshowproviderspage"></a>`alwaysShowProvidersPage` | boolean | If true, always shows the providers selection page, even when there's a single provider configured.<br>Has no effect when there's more than one provider configured.| Default: _false_ |
| <a id="config-opt-portals-authenticationtimeout"></a>`authenticationTimeout` | duration | Timeout for authenticating with the authentication provider.| Default: _5m_ |
| <a id="config-opt-providers"></a>`providers`| list of [provider configurations](#provider-configuration) | List of allowed authentication providers<br>See the [provider configuration](#provider-configuration) section for more details. | **Required**<br>At least one provider is required. |

## Provider configuration

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-providers-provider"></a>`provider` | string | Authentication provider to use<br>Currently supported providers:<br><br>- `github`<br>- `google`<br>- `microsoftentraid`<br>- `openidconnect`<br>- `tailscalewhois`| **Required** |
| <a id="config-opt-providers-name"></a>`name` | string | Name of the authentication provider<br>If empty, this defaults to the provider type (e.g. `google`)<br>Defaults to the name of the provider type|  |
| <a id="config-opt-providers-displayname"></a>`displayName` | string | Optional display name for the provider<br>Defaults to the standard display name for the provider|  |
| <a id="config-opt-providers-icon"></a>`icon` | string | Optional icon for the provider<br>Defaults to the standard icon for the provider|  |
| <a id="config-opt-providers-color"></a>`color` | string | Optional color scheme for the provider<br>Defaults to the standard color for the provider|  |
| <a id="config-opt-providers-config"></a>`config` | map | Configuration for the provider.<br>The properties depend on the provider type.|  |

<!-- END CONFIG TABLE -->
