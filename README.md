# Traefik Forward Auth

A minimal service that provides authentication and SSO with OAuth2, OpenID Connect, and Tailscale Whois, for the [Traefik](https://github.com/traefik/traefik) reverse proxy.

> This project began as a fork of [thomseddon/traefik-forward-auth](https://github.com/italypaleale/traefik-forward-auth). Since version 3, it has been completely rewritten and is not compatible with the upstream project anymore.

## Highlights

- Supports authentication with Google, Microsoft Entra ID (formerly Azure AD), GitHub, and generic OpenID Connect providers (including Auth0, Okta, etc).
- Single Sign-On with Tailscale Whois (similarly to Tailscale's [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth))
- Protect multiple Traefik services with a single instance of traefik-forward-auth.

## Releases

The Docker image is available on GitHub Packages. Container images are multi-arch and run on `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.

Using the `3` tag is recommended:

```text
ghcr.io/italypaleale/traefik-forward-auth:3
```

You can also pin to the latest patch release as found in the [Releases page](https://github.com/ItalyPaleAle/traefik-forward-auth/releases):

```text
ghcr.io/italypaleale/traefik-forward-auth:3.x.x
```

## Quickstart

This example uses Docker Compose to add Google authentication to an application.

```yaml
# docker-compose.yaml
version: '3'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  traefik-forward-auth:
    image: ghcr.io/italypaleale/traefik-forward-auth:3
    environment:
      # Hostname where the application can be reached at externally
      - TFA_HOSTNAME=auth.example.com
      # Domain for setting cookies
      - TFA_COOKIEDOMAIN=example.com
      # Configure authentication with Google
      - TFA_AUTHPROVIDER=google
      - TFA_AUTHGOOGLE_CLIENTID=...
      - TFA_AUTHGOOGLE_CLIENTSECRET=...
    labels:
      - "traefik.enable=true"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"
      - "traefik.http.routers.traefik-forward-auth.rule=Host(`auth.example.com`)"
      - "traefik.http.routers.traefik-forward-auth.entrypoints=websecure"
      - "traefik.http.routers.traefik-forward-auth.tls=true"

  whoami:
    image: containous/whoami
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
      - "traefik.http.services.whoami.loadbalancer.server.port=4545"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
```

## Configuration

### All configuration options

<!-- BEGIN CONFIG TABLE -->
| YAML option | Environmental variable | Type | Description | |
| --- | --- | --- | --- | --- |
| <a id="config-opt-hostname"></a>`hostname` | `TFA_HOSTNAME` | string | The hostname the application is reached at.<br>This is used for setting the "redirect_uri" field for OAuth2 callbacks.| **Required** |
| <a id="config-opt-cookiedomain"></a>`cookieDomain` | `TFA_COOKIEDOMAIN` | string | Domain name for setting cookies.<br>If empty, this is set to the value of the `hostname` property.<br>This value must either be the same as the `hostname` property, or the hostname must be a sub-domain of the cookie domain name.| Recommended |
| <a id="config-opt-cookiename"></a>`cookieName` | `TFA_COOKIENAME` | string | Name of the cookie used to store the session.| Default: _"tf_sess"_ |
| <a id="config-opt-cookieinsecure"></a>`cookieInsecure` | `TFA_COOKIEINSECURE` | boolean | If true, sets cookies as "insecure", which are served on HTTP endpoints too.<br>By default, this is false and cookies are sent on HTTPS endpoints only.| Default: _false_ |
| <a id="config-opt-sessionlifetime"></a>`sessionLifetime` | `TFA_SESSIONLIFETIME` | duration | Lifetime for sessions after a successful authentication.| Default: _2h_ |
| <a id="config-opt-port"></a>`port` | `TFA_PORT` | number | Port to bind to.| Default: _4181_ |
| <a id="config-opt-bind"></a>`bind` | `TFA_BIND` | string | Address/interface to bind to.| Default: _"0.0.0.0"_ |
| <a id="config-opt-basepath"></a>`basePath` | `TFA_BASEPATH` | string | Base path for all routes.<br>Set this if Traefik is forwarding requests to traefik-forward-auth for specific paths only.<br>Note: this does not apply to /api and /healthz routes|  |
| <a id="config-opt-loglevel"></a>`logLevel` | `TFA_LOGLEVEL` | string | Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.| Default: _info_ |
| <a id="config-opt-enablemetrics"></a>`enableMetrics` | `TFA_ENABLEMETRICS` | boolean | Enable the metrics server, which exposes a Prometheus-compatible endpoint `/metrics`.| Default: _false_ |
| <a id="config-opt-metricsport"></a>`metricsPort` | `TFA_METRICSPORT` | number | Port for the metrics server to bind to.| Default: _2112_ |
| <a id="config-opt-metricsbind"></a>`metricsBind` | `TFA_METRICSBIND` | string | Address/interface for the metrics server to bind to.| Default: _"0.0.0.0"_ |
| <a id="config-opt-omithealthchecklogs"></a>`omitHealthCheckLogs` | `TFA_OMITHEALTHCHECKLOGS` | boolean | If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.| Default: _false_ |
| <a id="config-opt-tokensigningkey"></a>`tokenSigningKey` | `TFA_TOKENSIGNINGKEY` | string | String used as key to sign state tokens.<br>Can be generated for example with `openssl rand -base64 32`<br>If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).|  |
| <a id="config-opt-authprovider"></a>`authProvider` | `TFA_AUTHPROVIDER` | string | Authentication provider to use<br>Currently supported providers:<br><br>- `github`<br>- `google`<br>- `microsoftentraid`<br>- `openidconnect`<br>- `tailscalewhois`| **Required** |
| <a id="config-opt-authgoogle_clientid"></a>`authGoogle_clientID` | `TFA_AUTHGOOGLE_CLIENTID` | string | Client ID for the Google auth application<br>Ignored if `authMethod` is not `google`|  |
| <a id="config-opt-authgoogle_clientsecret"></a>`authGoogle_clientSecret` | `TFA_AUTHGOOGLE_CLIENTSECRET` | string | Client secret for the Google auth application<br>Ignored if `authMethod` is not `google`|  |
| <a id="config-opt-authgoogle_requesttimeout"></a>`authGoogle_requestTimeout` | `TFA_AUTHGOOGLE_REQUESTTIMEOUT` | duration | Timeout for network requests for Google auth<br>Ignored if `authMethod` is not `google`| Default: _10s_ |
| <a id="config-opt-authgithub_clientid"></a>`authGitHub_clientID` | `TFA_AUTHGITHUB_CLIENTID` | string | Client ID for the GitHub auth application<br>Ignored if `authMethod` is not `github`|  |
| <a id="config-opt-authgithub_clientsecret"></a>`authGitHub_clientSecret` | `TFA_AUTHGITHUB_CLIENTSECRET` | string | Client secret for the GitHub auth application<br>Ignored if `authMethod` is not `github`|  |
| <a id="config-opt-authgithub_requesttimeout"></a>`authGitHub_requestTimeout` | `TFA_AUTHGITHUB_REQUESTTIMEOUT` | duration | Timeout for network requests for GitHub auth<br>Ignored if `authMethod` is not `github`| Default: _10s_ |
| <a id="config-opt-authmicrosoftentraid_tenantid"></a>`authMicrosoftEntraID_tenantID` | `TFA_AUTHMICROSOFTENTRAID_TENANTID` | string | Tenant ID for the Microsoft Entra ID auth application<br>Ignored if `authMethod` is not `microsoftentraid`|  |
| <a id="config-opt-authmicrosoftentraid_clientid"></a>`authMicrosoftEntraID_clientID` | `TFA_AUTHMICROSOFTENTRAID_CLIENTID` | string | Client ID for the Microsoft Entra ID auth application<br>Ignored if `authMethod` is not `microsoftentraid`|  |
| <a id="config-opt-authmicrosoftentraid_clientsecret"></a>`authMicrosoftEntraID_clientSecret` | `TFA_AUTHMICROSOFTENTRAID_CLIENTSECRET` | string | Client secret for the Microsoft Entra ID auth application<br>Ignored if `authMethod` is not `microsoftentraid`|  |
| <a id="config-opt-authmicrosoftentraid_requesttimeout"></a>`authMicrosoftEntraID_requestTimeout` | `TFA_AUTHMICROSOFTENTRAID_REQUESTTIMEOUT` | duration | Timeout for network requests for Microsoft Entra ID auth<br>Ignored if `authMethod` is not `microsoftentraid`| Default: _10s_ |
| <a id="config-opt-authopenidconnect_clientid"></a>`authOpenIDConnect_clientID` | `TFA_AUTHOPENIDCONNECT_CLIENTID` | string | Client ID for the OpenID Connect auth application<br>Ignored if `authMethod` is not `openidconnect`|  |
| <a id="config-opt-authopenidconnect_clientsecret"></a>`authOpenIDConnect_clientSecret` | `TFA_AUTHOPENIDCONNECT_CLIENTSECRET` | string | Client secret for the OpenID Connect auth application<br>Ignored if `authMethod` is not `openidconnect`|  |
| <a id="config-opt-authopenidconnect_tokenissuer"></a>`authOpenIDConnect_tokenIssuer` | `TFA_AUTHOPENIDCONNECT_TOKENISSUER` | string | OpenID Connect token issuer<br>The OpenID Connect configuration document will be fetched at `<token-issuer>/.well-known/openid-configuration`<br>Ignored if `authMethod` is not `openidconnect`|  |
| <a id="config-opt-authopenidconnect_requesttimeout"></a>`authOpenIDConnect_requestTimeout` | `TFA_AUTHOPENIDCONNECT_REQUESTTIMEOUT` | duration | Timeout for network requests for OpenID Connect auth<br>Ignored if `authMethod` is not `openidconnect`| Default: _10s_ |
| <a id="config-opt-authtailscalewhois_expectedtailnet"></a>`authTailscaleWhois_expectedTailnet` | `TFA_AUTHTAILSCALEWHOIS_EXPECTEDTAILNET` | string | If non-empty, requires the Tailnet of the user to match this value<br>Ignored if `authMethod` is not `tailscalewhois`|  |
| <a id="config-opt-authtailscalewhois_requesttimeout"></a>`authTailscaleWhois_requestTimeout` | `TFA_AUTHTAILSCALEWHOIS_REQUESTTIMEOUT` | duration | Timeout for network requests for Tailscale Whois auth<br>Ignored if `authMethod` is not `tailscalewhois`| Default: _10s_ |
| <a id="config-opt-authenticationtimeout"></a>`authenticationTimeout` | `TFA_AUTHENTICATIONTIMEOUT` | duration | Timeout for authenticating with the authentication provider.| Default: _5m_ |
| <a id="config-opt-tlspath"></a>`tlsPath` | `TFA_TLSPATH` | string | Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem` (and optionally `tls-ca.pem`).<br>Vault watches for changes in this folder and automatically reloads the TLS certificates when they're updated.<br>If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.| Default: _Folder where the `config.yaml` file is located_ |
| <a id="config-opt-tlscertpem"></a>`tlsCertPEM` | `TFA_TLSCERTPEM` | string | Full, PEM-encoded TLS certificate.<br>Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.|  |
| <a id="config-opt-tlskeypem"></a>`tlsKeyPEM` | `TFA_TLSKEYPEM` | string | Full, PEM-encoded TLS key.<br>Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.|  |
| <a id="config-opt-tlscapem"></a>`tlsCAPEM` | `TFA_TLSCAPEM` | string | Full, PEM-encoded TLS CA certificate, used for TLS client authentication (mTLS).<br>This is an alternative method of passing the CA certificate than using `tlsPath`.<br>Note that this is ignored unless `tlsClientAuth` is set to `true`.|  |
| <a id="config-opt-tlsclientauth"></a>`tlsClientAuth` | `TFA_TLSCLIENTAUTH` | boolean | If true, enables mTLS for client authentication.<br>Requests to the root endpoint (normally used by Traefik) must have a valid client certificate signed by the CA.| Default: _false_ |
| <a id="config-opt-trustedrequestidheader"></a>`trustedRequestIdHeader` | `TFA_TRUSTEDREQUESTIDHEADER` | string | String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.<br>Common values include:<br><br>- `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id) that's vendor agnostic<br>- `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)<br><br>If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.|  |

<!-- END CONFIG TABLE -->

aaaa
