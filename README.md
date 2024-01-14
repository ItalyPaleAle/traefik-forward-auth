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

### Authenticate with Google

This example uses Docker Compose to add Google authentication to an application exposed via Traefik.

In this example, your OAuth2 application should be configured to redirect users to `https://auth.example.com/oauth2/callback`.

```yaml
# docker-compose.yaml
version: '3'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
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
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"
      - "traefik.http.routers.traefik-forward-auth.rule=Host(`auth.example.com`)"
      - "traefik.http.routers.traefik-forward-auth.entrypoints=websecure"
      - "traefik.http.routers.traefik-forward-auth.tls=true"

  whoami:
    image: ghcr.io/traefik/whoami:latest
    environment:
      - WHOAMI_PORT_NUMBER=4545
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
      - "traefik.http.services.whoami.loadbalancer.server.port=4545"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
```

### Authenticate with Tailscale

This example uses Docker Compose to expose an application via Traefik. Users who access the Traefik endpoint through Tailscale are automatically authenticated. This example assumes Tailscale is running on the container host, not inside a container.

```yaml
# docker-compose.yaml
version: '3'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  traefik-forward-auth:
    image: ghcr.io/italypaleale/traefik-forward-auth:3
    volumes:
      # Note the Tailscale socket must be mounted in the container
      - /var/run/tailscale/:/var/run/tailscale
    environment:
      # Hostname where the application can be reached at externally
      - TFA_HOSTNAME=auth.example.com
      # Domain for setting cookies
      - TFA_COOKIEDOMAIN=example.com
      # Configure authentication with Tailscale
      - TFA_AUTHPROVIDER=tailscalewhois
    labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.routers.traefik-forward-auth.rule=Host(`auth.example.com`)"
      - "traefik.http.routers.traefik-forward-auth.entrypoints=websecure"
      - "traefik.http.routers.traefik-forward-auth.tls=true"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"

  whoami:
    image: ghcr.io/traefik/whoami:latest
    environment:
      - WHOAMI_PORT_NUMBER=4545
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
      - "traefik.http.services.whoami.loadbalancer.server.port=4545"
```

## Configuration

### Configuring Traefik Forward Auth

Traefik Forward Auth can be configured in two ways:

1. Mount a YAML configuration file into the container at the path `/etc/traefik-forward-auth/config.yaml`.
   In your `docker-compose.yaml` you can mount the configuration file similar to this:

   ```yaml
   services:
    traefik-forward-auth:
      image: ghcr.io/italypaleale/traefik-forward-auth:3
      volumes:
        - `/path/on/host/config.yaml:/etc/traefik-forward-auth/config.yaml:ro`
   ```

2. Using environmental variables.
   In your `docker-compose.yaml`, this is done listing each variable in the `environment` section:

   ```yaml
   services:
    traefik-forward-auth:
      image: ghcr.io/italypaleale/traefik-forward-auth:3
      environment:
        - `TFA_HOSTNAME=auth.example.com`
   ```

You can find the list of [all configuration options](#all-configuration-options) in the section below.

> Environmental variables take precedence over values set in the configuration file.

### Exposing Traefik Forward Auth

In order to use Traefik Forward Auth, it needs to be reachable through a Traefik router. You can configure it in 2 ways:

1. [**Using a dedicated sub-domain**](#using-a-dedicated-sub-domain)  
   This is most commonly used when all the apps you want to protect are served under the same domain (e.g. `example.com`). Traefik Forward Auth is exposed through its own sub-domain (for example, `https://auth.example.com`), while your apps are served through the parent domain (`https://example.com`) or other sub-domains (`https://myapp.example.com`).  
   This scenario is the most convenient one when you need to protect multiple applications at once using the same Traefik Forward Auth instance.
2. [**Using a sub-path**](#using-a-sub-path)  
   In this scenario you do not need a dedicated sub-domain for Traefik Forward Auth, which is instead exposed in a sub-path. For example, if your app is reachable at `https://example.com`, Traefik is configured to route requests to Traefik Forward Auth at `https://example.com/auth`.

> Although Traefik Forward Auth doesn't need to be reachable from the public Internet, your clients must be able to have a route to it (for example, within the LAN or using a VPN)  
> Additionally, many OAuth2 identity providers (including Google and Microsoft Entra ID) require the callback URL to be served via HTTPS/TLS (even if using a self-signed certificate).

#### Using a dedicated sub-domain

Using a dedicated sub-domain is the most convenient way to protect multiple apps, as long as they are all served under sub-domains of the same domain name (e.g. `example.com`).

In this example:

- Applications are hosted on `https://example.com` and/or subdomains such as `https://myapp.example.com`.
- Traefik Forward Auth is served on `https://auth.example.com`.

To configure Traefik and Traefik Forward Auth in this scenario:

1. If using a provider based on OAuth2 (including Google, Microsoft Entra ID, GitHub, and OpenID Connect providers), configure your authentication callback to: `https://auth.example.com/oauth2/callback`
2. Configure Traefik Forward Auth with:

   - [`hostname`](#config-opt-hostname) (env: `TFA_HOSTNAME`): `auth.example.com`
   - [`cookieDomain`](#config-opt-cookiedomain) (env: `TFA_COOKIEDOMAIN`): `example.com`

3. Create a Traefik middleware of type `forwardauth` with:

   - `address`: `http://traefik-forward-auth:4181`  
      This is the address of the `traefik-forward-auth` container within your Docker network. In this example, we are assuming the container/service is named `traefik-forward-auth`. Also note that the internal communication happens over HTTP by default.
   - `authResponseHeaders`: `X-Forwarded-User`  
      This is optional, but allows your application to read the ID of the authenticated user through the request header `X-Forwarded-User`.

4. Configure Traefik to expose your applications, including:

   - Traefik Forward Auth at `auth.example.com`, using the "websecure" entry point (which is enabled for HTTPS/TLS).
   - Your applications at `example.com` or other sub-domains such as `myapp.example.com`

Full example using Docker Compose:

```yaml
# docker-compose.yaml
version: '3'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
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
      # Add other options
      - ...
    labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"
      - "traefik.http.routers.traefik-forward-auth.rule=Host(`auth.example.com`)"
      - "traefik.http.routers.traefik-forward-auth.entrypoints=websecure"
      - "traefik.http.routers.traefik-forward-auth.tls=true"

  whoami:
    image: ghcr.io/traefik/whoami:latest
    environment:
      - WHOAMI_PORT_NUMBER=4545
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
      - "traefik.http.services.whoami.loadbalancer.server.port=4545"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
```

#### Using a sub-path

Using a sub-path does not require the use of sub-domains, but it is generally harder to implement when you want to protect more than one application.

In this example:

- Your application is hosted at `https://example.com`.
- Traefik Forward Auth is served on `https://example.com/auth`.

To configure Traefik and Traefik Forward Auth in this scenario:

1. If using a provider based on OAuth2 (including GitHub, Google, Microsoft Entra ID, and OpenID Connect providers), configure your authentication callback to: `https://example.com/auth/oauth2/callback`
2. Configure Traefik Forward Auth with:

   - [`hostname`](#config-opt-hostname) (env: `TFA_HOSTNAME`): `example.com`
   - [`basePath`](#config-opt-basepath) (env: `TFA_BASEPATH`): `/auth`

3. Create a Traefik middleware of type `forwardauth` with:

   - `address`: `http://traefik-forward-auth:4181/auth`  
      This is the address of the `traefik-forward-auth` container within your Docker network. In this example, we are assuming the container/service is named `traefik-forward-auth`. Also note that the internal communication happens over HTTP by default.
   - `authResponseHeaders`: `X-Forwarded-User`  
      This is optional, but allows your application to read the ID of the authenticated user through the request header `X-Forwarded-User`.

4. Configure Traefik to expose your applications, including:

   - Traefik Forward Auth at `example.com/auth`, using the rule ``PathPrefix(`/auth`)`` the "websecure" entry point (which is enabled for HTTPS/TLS).
   - Your application at `example.com`.

Full example using Docker Compose:

```yaml
# docker-compose.yaml
version: '3'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  traefik-forward-auth:
    image: ghcr.io/italypaleale/traefik-forward-auth:3
    environment:
      # Hostname where the application can be reached at externally
      - TFA_HOSTNAME=example.com
      # Base path
      - TFA_BASEPATH=/auth
      # Add other options
      - ...
    labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181/auth"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"
      - "traefik.http.routers.traefik-forward-auth.rule=Host(`example.com`) && PathPrefix(`/auth`)"
      - "traefik.http.routers.traefik-forward-auth.entrypoints=websecure"
      - "traefik.http.routers.traefik-forward-auth.tls=true"

  whoami:
    image: ghcr.io/traefik/whoami:latest
    environment:
      - WHOAMI_PORT_NUMBER=4545
    labels:
      - "traefik.http.routers.whoami.rule=Host(`example.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
      - "traefik.http.services.whoami.loadbalancer.server.port=4545"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
```

### Authentication providers

#### GitHub

To use GitHub for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `github`
- [`authGithub_clientID`](#config-opt-authgithub_clientid) (env: `TFA_AUTHGITHUB_CLIENTID`): OAuth2 client ID of your application
- [`authGithub_clientSecret`](#config-opt-authgithub_clientsecret) (env: `TFA_AUTHGITHUB_CLIENTSECRET`): OAuth2 client secret of your application

#### Google

To use Google for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `google`
- [`authGoogle_clientID`](#config-opt-authgoogle_clientid) (env: `TFA_AUTHGOOGLE_CLIENTID`): OAuth2 client ID of your application
- [`authGoogle_clientSecret`](#config-opt-authgoogle_clientsecret) (env: `TFA_AUTHGOOGLE_CLIENTSECRET`): OAuth2 client secret of your application

#### Microsoft Entra ID

To use Microsoft Entra ID (formerly Azure AD) for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `microsoftentraid`
- [`authMicrosoftEntraID_tenantID`](#config-opt-authmicrosoftentraid_tenantid) (env: `TFA_AUTHMICROSOFTENTRAID_TENANTID`): ID of the tenant where your application resides
- [`authMicrosoftEntraID_clientID`](#config-opt-authmicrosoftentraid_clientid) (env: `TFA_AUTHMICROSOFTENTRAID_CLIENTID`): Client ID of your application
- [`authMicrosoftEntraID_clientSecret`](#config-opt-authmicrosoftentraid_clientsecret) (env: `TFA_AUTHMICROSOFTENTRAID_CLIENTSECRET`): Client secret of your application

#### Other OpenID Connect providers

Traefik Forward Auth support generic OpenID Connect providers. This includes Auth0, Okta, etc.

To use an OpenID Connect provider for user authentication, create an application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `openidconnect`
- [`authOpenIDConnect_tokenIssuer`](#config-opt-authopenidconnect_tokenissuer) (env: `TFA_AUTHOPENIDCONNECT_TOKENISSUER`): Token issuer  
   This is generally a URL like `https://tenant.identityprovider.com/`.  
   Traefik Forward Auth will try to fetch the OpenID Configuration document at `<tokenIssuer>/.well-known/openid-configuration`; in this example, `https://tenant.identityprovider.com/.well-known/openid-configuration`.
- [`authOpenIDConnect_clientID`](#config-opt-authopenidconnect_clientid) (env: `TFA_AUTHOPENIDCONNECT_CLIENTID`): Client ID of your application
- [`authOpenIDConnect_clientSecret`](#config-opt-authopenidconnect_clientsecret) (env: `TFA_AUTHOPENIDCONNECT_CLIENTSECRET`): Client secret of your application

#### Tailscale Whois

You can configure Single Sign-On (SSO) for clients that access your Traefik server through [Tailscale](https://tailscale.com/). Users will be automatically authenticated when the request comes through the Tailscale network.

This offers a similar behavior to the Tailscale [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth) component.

1. Your container host must be joined to a Tailnet, and you must have the Tailscale service running on the host.
2. Make sure that the socket `/var/run/tailscale/` is mounted into the `traefik-forward-auth` container.  
3. Configure Traefik Forward Auth with:

   - [`authProvider`](#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `tailscalewhois`

Example using Docker Compose (unrelated configuration options and labels omitted):

```yaml
services:
  traefik-forward-auth:
    image: ghcr.io/italypaleale/traefik-forward-auth:3
    volumes:
      - /var/run/tailscale/:/var/run/tailscale
    environment:
      - TFA_AUTHPROVIDER=tailscalewhois
```

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
| <a id="config-opt-omithealthchecklogs"></a>`omitHealthCheckLogs` | `TFA_OMITHEALTHCHECKLOGS` | boolean | If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.| Default: _true_ |
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

## Advanced

### Configure health checks

Traefik Forward Auth supports health checks on the `/healthz` endpoint, which can be used to configure health checks in your platform. This endpoint returns a response with a `200` status code to indicate the application is healthy.

Calls to the `/healthz` endpoint do not appear in access logs unless the configuration option [`omitHealthCheckLogs`](#config-opt-omithealthchecklogs) is set to `false` (default is `true`).

> The `/healthz` endpoint is unchanged regardless of the value of the [`basePath`](#config-opt-basepath) configuration.

### Metrics

Traefik Forward Auth can expose metrics in a Prometheus-compatible format on a separate endpoint.

The metrics server is disabled by default. To enable it, set [`enableMetrics`](#config-opt-enablemetrics) (env: `TFA_ENABLEMETRICS`) to `true`.

The metrics server listens on port `2112` by default, which can be configured with [`metricsPort`](#config-opt-metricsport) (env: `TFA_METRICSPORT`). Metrics are exposed on the `/metrics` path. For example: `http://<endpoint>:2112/metrics`.

### Token signing keys

Traefik Forward Auth issues JWT tokens which are signed with HMAC-SHA256 (HS256), an operation which requires a "signing key".

The signing key is randomly generated when Traefik Forward Auth starts. For most users, relaying on the default behavior is sufficient—and recommended.

However, when a JWT is signed with a randomly-generated token, they are invalidated when the Traefik Forward Auth process that issued them is restarted, or if the request hits a separate replica.

In certain situations, for example when:

- You have multiple replicas of Traefik Forward Auth, and/or
- You auto-scale Traefik Forward Auth, and/or
- You want tokens to remain valid even after a restart of Traefik Forward Auth

You can set an explicit value for the [`tokenSigningKey`](#config-opt-tokensigningkey) (env: `TFA_TOKENSIGNINGKEY`) option. For example, you can generate a random string with `openssl rand -base64 32`.

> Note that Traefik Forward Auth does not use the value provided in `tokenSigningKey` as-is to sign JWTs. Instead, the actual token signing key is derived using a key derivation function on the value provided in the configuration option.


