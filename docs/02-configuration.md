# ⚙️ Configuration

- [Configuring Traefik Forward Auth](#configuring-traefik-forward-auth)
- [Exposing Traefik Forward Auth](#exposing-traefik-forward-auth)

## Configuring Traefik Forward Auth

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

    Environmental variables take precedence over values set in the configuration file.

You can find the list of [all configuration options](./03-all-configuration-options.md).

> When passing secrets to Traefik Forward Auth, mounting a YAML configuration file is recommended over passing confidential values as environmental variables.

## Exposing Traefik Forward Auth

In order to use Traefik Forward Auth, it needs to be reachable through a Traefik router. You can configure it in 2 ways:

1. [**Using a dedicated sub-domain**](#using-a-dedicated-sub-domain)  
   This is most commonly used when all the apps you want to protect are served under the same domain (e.g. `example.com`). Traefik Forward Auth is exposed through its own sub-domain (for example, `https://auth.example.com`), while your apps are served through the parent domain (`https://example.com`) or other sub-domains (`https://myapp.example.com`).  
   This scenario is the most convenient one when you need to protect multiple applications at once using the same Traefik Forward Auth instance.
2. [**Using a sub-path**](#using-a-sub-path)  
   In this scenario you do not need a dedicated sub-domain for Traefik Forward Auth, which is instead exposed in a sub-path. For example, if your app is reachable at `https://example.com`, Traefik is configured to route requests to Traefik Forward Auth at `https://example.com/auth`.

> Although Traefik Forward Auth doesn't need to be reachable from the public Internet, your clients must be able to have a route to it (for example, within the LAN or using a VPN)  
> Additionally, many OAuth2 identity providers (including Google and Microsoft Entra ID) require the callback URL to be served via HTTPS/TLS (even if using a self-signed certificate).

### Using a dedicated sub-domain

Using a dedicated sub-domain is the most convenient way to protect multiple apps, as long as they are all served under sub-domains of the same domain name (e.g. `example.com`).

In this example:

- Applications are hosted on `https://example.com` and/or subdomains such as `https://myapp.example.com`.
- Traefik Forward Auth is served on `https://auth.example.com`.

To configure Traefik and Traefik Forward Auth in this scenario:

1. If using a provider based on OAuth2 (including Google, Microsoft Entra ID, GitHub, and OpenID Connect providers), configure your authentication callback to: `https://auth.example.com/oauth2/callback`
2. Configure Traefik Forward Auth with:

   - [`hostname`](./03-all-configuration-options.md#config-opt-hostname) (env: `TFA_HOSTNAME`): `auth.example.com`
   - [`cookieDomain`](./03-all-configuration-options.md#config-opt-cookiedomain) (env: `TFA_COOKIEDOMAIN`): `example.com`

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

### Using a sub-path

Using a sub-path does not require the use of sub-domains, but it is generally harder to implement when you want to protect more than one application.

In this example:

- Your application is hosted at `https://example.com`.
- Traefik Forward Auth is served on `https://example.com/auth`.

To configure Traefik and Traefik Forward Auth in this scenario:

1. If using a provider based on OAuth2 (including GitHub, Google, Microsoft Entra ID, and OpenID Connect providers), configure your authentication callback to: `https://example.com/auth/oauth2/callback`
2. Configure Traefik Forward Auth with:

   - [`hostname`](./03-all-configuration-options.md#config-opt-hostname) (env: `TFA_HOSTNAME`): `example.com`
   - [`basePath`](./03-all-configuration-options.md#config-opt-basepath) (env: `TFA_BASEPATH`): `/auth`

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
