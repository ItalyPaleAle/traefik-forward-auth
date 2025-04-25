# 🚀 Quickstart

- [Authenticate with Google](#authenticate-with-google)
- [Authenticate with Tailscale](#authenticate-with-tailscale)

## Authenticate with Google

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
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User,X-Authenticated-User"
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

## Authenticate with Tailscale

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
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User,X-Authenticated-User"
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
