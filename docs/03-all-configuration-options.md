# 📖 All configuration options

<!-- BEGIN CONFIG TABLE -->
## Root configuration object

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-server-hostname"></a>`server.hostname` | string | The hostname the application is reached at.<br>This is used for setting the "redirect_uri" field for OAuth2 callbacks.| **Required** |
| <a id="config-opt-server-port"></a>`server.port` | number | Port to bind to.| Default: _4181_ |
| <a id="config-opt-server-bind"></a>`server.bind` | string | Address/interface to bind to.| Default: _"0.0.0.0"_ |
| <a id="config-opt-server-basepath"></a>`server.basePath` | string | Base path for all routes.<br>Set this if Traefik is forwarding requests to traefik-forward-auth for specific paths only.<br>Note: this does not apply to /healthz routes|  |
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

## Portal configuration

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-portals-portals-$-name"></a>`portals.$.name` | string | Name of the portal, as used in the URL.| **Required** |
| <a id="config-opt-portals-portals-$-displayname"></a>`portals.$.displayName` | string | Optional display name.<br>Defaults to the `name` property if not set.|  |
| <a id="config-opt-portals-portals-$-alwaysshowproviderspage"></a>`portals.$.alwaysShowProvidersPage` | boolean | If true, always shows the providers selection page, even when there's a single provider configured.<br>Has no effect when there's more than one provider configured.| Default: _false_ |
| <a id="config-opt-portals-portals-$-authenticationtimeout"></a>`portals.$.authenticationTimeout` | duration | Timeout for authenticating with the authentication provider.| Default: _5m_ |
| <a id="config-opt-providers"></a>`providers`| list of [provider configurations](#provider-configuration) | List of allowed authentication providers<br>See the [provider configuration](#provider-configuration) section for more details. | **Required**<br>At least one provider is required. |

## Provider Configuration

The configuration depends on the kind of provider used. Currently, the following providers are supported:

- [GitHub](#using-github)
- [Google](#using-google)
- [Microsoft Entra ID](#using-microsoft-entra-id)
- [OpenID Connect](#using-openid-connect)
- [Tailscale Whois](#using-tailscale-whois)

### Using GitHub

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-name"></a>`portals.$.providers.$.github.name` | string | Name of the authentication provider<br>Defaults to the name of the provider type|  |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-displayname"></a>`portals.$.providers.$.github.displayName` | string | Optional display name for the provider<br>Defaults to the standard display name for the provider|  |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientid"></a>`portals.$.providers.$.github.clientID` | string | Client ID for the GitHub auth application| **Required** |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientsecret"></a>`portals.$.providers.$.github.clientSecret` | string | Client secret for the GitHub application<br>One of `clientSecret` and `clientSecretFile` is required.| **Required** |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientsecretfile"></a>`portals.$.providers.$.github.clientSecretFile` | string | File containing the client secret for the GitHub application<br>This is an alternative to passing the secret as `clientSecret`<br>One of `clientSecret` and `clientSecretFile` is required.|  |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-requesttimeout"></a>`portals.$.providers.$.github.requestTimeout` | duration | Timeout for network requests for GitHub auth| Default: _"10s"_ |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-icon"></a>`portals.$.providers.$.github.icon` | string | Optional icon for the provider<br>Defaults to the standard icon for the provider|  |
| <a id="config-opt-portals.$.providers.$-github-portals-$-providers-$-github-color"></a>`portals.$.providers.$.github.color` | string | Optional color scheme for the provider<br>Defaults to the standard color for the provider|  |

Example:

```yaml
portals:
  name: "default"
  providers:
    -
        github:
          #name: "my-github-auth"
          #displayName: "GitHub"
          clientID: "your-client-id"
          clientSecret: "your-client-secret"
          #clientSecretFile: "/var/run/secrets/traefik-forward-auth/github/client-secret"
          ## Default: "10s"
          #requestTimeout: "10s"
          #icon: "github"
          #color: "green-to-blue"
```

### Using Google

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-name"></a>`portals.$.providers.$.google.name` | string | Name of the authentication provider<br>Defaults to the name of the provider type|  |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-displayname"></a>`portals.$.providers.$.google.displayName` | string | Optional display name for the provider<br>Defaults to the standard display name for the provider|  |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-clientid"></a>`portals.$.providers.$.google.clientID` | string | Client ID for the Google auth application| **Required** |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-clientsecret"></a>`portals.$.providers.$.google.clientSecret` | string | Client secret for the Google auth application<br>One of `clientSecret` and `clientSecretFile` is required.| **Required** |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-clientsecretfile"></a>`portals.$.providers.$.google.clientSecretFile` | string | File containing the client secret for the Google auth application<br>This is an alternative to passing the secret as `clientSecret`<br>One of `clientSecret` and `clientSecretFile` is required.|  |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-requesttimeout"></a>`portals.$.providers.$.google.requestTimeout` | duration | Timeout for network requests for Google auth| Default: _"10s"_ |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-icon"></a>`portals.$.providers.$.google.icon` | string | Optional icon for the provider<br>Defaults to the standard icon for the provider|  |
| <a id="config-opt-portals.$.providers.$-google-portals-$-providers-$-google-color"></a>`portals.$.providers.$.google.color` | string | Optional color scheme for the provider<br>Defaults to the standard color for the provider|  |

Example:

```yaml
portals:
  name: "default"
  providers:
    -
        google:
          #name: "my-google-auth"
          #displayName: "Google"
          clientID: "your-google-client-id.apps.googleusercontent.com"
          clientSecret: "your-client-secret"
          #clientSecretFile: "/var/run/secrets/traefik-forward-auth/google/client-secret"
          ## Default: "10s"
          #requestTimeout: "10s"
          #icon: "google"
          #color: "red-to-yellow"
```

### Using Microsoft Entra ID

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-name"></a>`portals.$.providers.$.microsoftEntraID.name` | string | Name of the authentication provider<br>Defaults to the name of the provider type|  |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-displayname"></a>`portals.$.providers.$.microsoftEntraID.displayName` | string | Optional display name for the provider<br>Defaults to the standard display name for the provider|  |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-tenantid"></a>`portals.$.providers.$.microsoftEntraID.tenantID` | string | Tenant ID for the Microsoft Entra ID auth application<br>+example| **Required** |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientid"></a>`portals.$.providers.$.microsoftEntraID.clientID` | string | Client ID for the Microsoft Entra ID auth application| **Required** |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientsecret"></a>`portals.$.providers.$.microsoftEntraID.clientSecret` | string | Client secret for the Microsoft Entra ID auth application<br>Required when not using Federated Identity Credentials|  |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientsecretfile"></a>`portals.$.providers.$.microsoftEntraID.clientSecretFile` | string | File containing the client secret for the Microsoft Entra ID application.<br>This is an alternative to passing the secret as `clientSecret`|  |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-azurefederatedidentity"></a>`portals.$.providers.$.microsoftEntraID.azureFederatedIdentity` | string | Enables the usage of Federated Identity Credentials to obtain assertions for confidential clients for Microsoft Entra ID applications.<br>This is an alternative to using client secrets, when the application is running in Azure in an environment that supports Managed Identity, or in an environment that supports Workload Identity Federation with Microsoft Entra ID.<br>Currently, these values are supported:<br><br>- `ManagedIdentity`: uses a system-assigned managed identity<br>- `ManagedIdentity=client-id`: uses a user-assigned managed identity with client id "client-id" (e.g. "ManagedIdentity=00000000-0000-0000-0000-000000000000")<br>- `WorkloadIdentity`: uses workload identity, e.g. for Kubernetes|  |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-requesttimeout"></a>`portals.$.providers.$.microsoftEntraID.requestTimeout` | duration | Timeout for network requests for Microsoft Entra ID auth| Default: _"10s"_ |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-icon"></a>`portals.$.providers.$.microsoftEntraID.icon` | string | Optional icon for the provider<br>Defaults to the standard icon for the provider|  |
| <a id="config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-color"></a>`portals.$.providers.$.microsoftEntraID.color` | string | Optional color scheme for the provider<br>Defaults to the standard color for the provider|  |

Example:

```yaml
portals:
  name: "default"
  providers:
    -
        microsoftEntraID:
          #name: "my-microsoft-entra-id-auth"
          #displayName: "Microsoft Entra ID"
          tenantID: ""
          clientID: "your-client-id"
          #clientSecret: "your-client-secret"
          #clientSecretFile: "/var/run/secrets/traefik-forward-auth/client-secret"
          #azureFederatedIdentity: ""
          ## Default: "10s"
          #requestTimeout: "10s"
          #icon: "microsoft"
          #color: "teal-to-lime"
```

### Using OpenID Connect

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-name"></a>`portals.$.providers.$.openIDConnect.name` | string | Name of the authentication provider<br>Defaults to the name of the provider type|  |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-displayname"></a>`portals.$.providers.$.openIDConnect.displayName` | string | Optional display name for the provider<br>Defaults to the standard display name for the provider|  |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-clientid"></a>`portals.$.providers.$.openIDConnect.clientID` | string | Client ID for the OpenID Connect application| **Required** |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-clientsecret"></a>`portals.$.providers.$.openIDConnect.clientSecret` | string | Client secret for the OpenID Connect application| **Required** |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-clientsecretfile"></a>`portals.$.providers.$.openIDConnect.clientSecretFile` | string | File containing the client secret for the OpenID Connect application<br>This is an alternative to passing the secret as `clientSecret`|  |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tokenissuer"></a>`portals.$.providers.$.openIDConnect.tokenIssuer` | string | OpenID Connect token issuer<br>The OpenID Connect configuration document will be fetched at `<token-issuer>/.well-known/openid-configuration`| **Required** |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-requesttimeout"></a>`portals.$.providers.$.openIDConnect.requestTimeout` | duration | Timeout for network requests for OpenID Connect auth| Default: _"10s"_ |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-enablepkce"></a>`portals.$.providers.$.openIDConnect.enablePKCE` | boolean | If true, enables the use of PKCE during the code exchange.| Default: _false_ |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlsinsecureskipverify"></a>`portals.$.providers.$.openIDConnect.tlsInsecureSkipVerify` | boolean | If true, skips validating TLS certificates when connecting to the OpenID Connect Identity Provider.| Default: _false_ |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlscacertificatepem"></a>`portals.$.providers.$.openIDConnect.tlsCACertificatePEM` | string | Optional PEM-encoded CA certificate to trust when connecting to the OpenID Connect Identity Provider.|  |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlscacertificatepath"></a>`portals.$.providers.$.openIDConnect.tlsCACertificatePath` | string | Optional path to a CA certificate to trust when connecting to the OpenID Connect Identity Provider.|  |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-icon"></a>`portals.$.providers.$.openIDConnect.icon` | string | Optional icon for the provider<br>Defaults to the standard icon for the provider|  |
| <a id="config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-color"></a>`portals.$.providers.$.openIDConnect.color` | string | Optional color scheme for the provider<br>Defaults to the standard color for the provider|  |

Example:

```yaml
portals:
  name: "default"
  providers:
    -
        openIDConnect:
          #name: "my-openid-auth"
          #displayName: "OpenID Connect"
          clientID: "your-client-id"
          clientSecret: "your-client-secret"
          #clientSecretFile: "/var/run/secrets/traefik-forward-auth/openidconnect/client-secret"
          tokenIssuer: "https://id.external-example.com"
          ## Default: "10s"
          #requestTimeout: "10s"
          ## Default: false
          #enablePKCE: false
          ## Default: false
          #tlsInsecureSkipVerify: false
          #tlsCACertificatePEM: ""
          #tlsCACertificatePath: ""
          #icon: "openid"
          #color: "purple-to-pink"
```

### Using Tailscale Whois

| Name | Type | Description | |
| --- | --- | --- | --- |
| <a id="config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-name"></a>`portals.$.providers.$.tailscaleWhois.name` | string | Name of the authentication provider<br>Defaults to the name of the provider type|  |
| <a id="config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-displayname"></a>`portals.$.providers.$.tailscaleWhois.displayName` | string | Optional display name for the provider<br>Defaults to the standard display name for the provider|  |
| <a id="config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-allowedtailnet"></a>`portals.$.providers.$.tailscaleWhois.allowedTailnet` | string | If non-empty, requires the Tailnet of the user to match this value|  |
| <a id="config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-requesttimeout"></a>`portals.$.providers.$.tailscaleWhois.requestTimeout` | duration | Timeout for network requests for Tailscale Whois auth| Default: _"10s"_ |
| <a id="config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-icon"></a>`portals.$.providers.$.tailscaleWhois.icon` | string | Optional icon for the provider<br>Defaults to the standard icon for the provider|  |
| <a id="config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-color"></a>`portals.$.providers.$.tailscaleWhois.color` | string | Optional color scheme for the provider<br>Defaults to the standard color for the provider|  |

Example:

```yaml
portals:
  name: "default"
  providers:
    -
        tailscaleWhois:
          #name: "my-tailscale-whois-auth"
          #displayName: "Tailscale Whois"
          #allowedTailnet: "yourtailnet.ts.net"
          ## Default: "10s"
          #requestTimeout: "10s"
          #icon: "tailscale"
          #color: "cyan-to-blue"
```

<!-- END CONFIG TABLE -->
