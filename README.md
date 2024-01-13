# Traefik Forward Auth

A minimal service that provides authentication and SSO with OAuth2, OpenID Connect, and Tailscale Whois, for the [Traefik](https://github.com/traefik/traefik) reverse proxy.

> This project began as a fork of [thomseddon/traefik-forward-auth](https://github.com/italypaleale/traefik-forward-auth). Since version 3, it has been completely rewritten and is not compatible with the upstream project anymore.

## Highlights

- Supports authentication with Google, Microsoft Entra ID (formerly Azure AD), GitHub. (More OAuth2 and OpenID Connect providers can be added)
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

## Usage

### Docker Compose

```yaml
# docker-compose.yaml
version: '3'

services:
  traefik:
    image: traefik:v2.10
    command: --providers.docker
    ports:
      - "8085:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  traefik-forward-auth:
    image: ghcr.io/italypaleale/traefik-forward-auth:3
    environment:
      - PROVIDERS_GOOGLE_CLIENT_ID=your-client-id
      - PROVIDERS_GOOGLE_CLIENT_SECRET=your-client-secret
      - SECRET=something-random # Example: generate with `openssl rand -base64 32`
      - INSECURE_COOKIE=true # Example assumes no https, do not use in production
    labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"

  whoami:
    image: containous/whoami
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.mycompany.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
```
