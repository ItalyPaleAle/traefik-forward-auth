# Traefik Forward Auth

A minimal service that provides authentication and SSO with OAuth2, OpenID Connect, and Tailscale Whois, for the [Traefik](https://github.com/traefik/traefik) reverse proxy.

> This project began as a fork of [thomseddon/traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth). Since version 3, it has been completely rewritten and is not compatible with the upstream project anymore.

## ✨ Highlights

- Supports authentication with Google, Microsoft Entra ID (formerly Azure AD), GitHub, and generic OpenID Connect providers (including Auth0, Okta, etc).
- Single Sign-On with Tailscale Whois (similarly to Tailscale's [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth))
- Protect multiple Traefik services with a single instance of traefik-forward-auth.

## 👉 Releases

The Docker image is available on GitHub Packages. Container images are multi-arch and run on `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.

Using the `3` tag is recommended:

```text
ghcr.io/italypaleale/traefik-forward-auth:3
```

You can also pin to the latest patch release as found in the [Releases page](https://github.com/ItalyPaleAle/traefik-forward-auth/releases):

```text
ghcr.io/italypaleale/traefik-forward-auth:3.x.x
```

## 📘 Docs

- [**🚀 Quickstart**](./docs/01-quickstart.md)
  - [Authenticate with Google](./docs/01-quickstart.md#authenticate-with-google)
  - [Authenticate with Tailscale](./docs/01-quickstart.md#authenticate-with-tailscale)
- [**⚙️ Configuration**](./docs/02-configuration.md)
  - [Configuring Traefik Forward Auth](./docs/02-configuration.md#configuring-traefik-forward-auth)
  - [Exposing Traefik Forward Auth](./docs/02-configuration.md#exposing-traefik-forward-auth)
- [**📖 All configuration options**](./docs/03-all-configuration-options.md)
- [**🔑 Authentication providers**](./docs/04-authentication-providers.md)
  - [GitHub](./docs/04-authentication-providers.md#github)
  - [Google](./docs/04-authentication-providers.md#google)
  - [Microsoft Entra ID](./docs/04-authentication-providers.md#microsoft-entra-id)
  - [Other OpenID Connect providers](./docs/04-authentication-providers.md#other-openid-connect-providers)
  - [Tailscale Whois](./docs/04-authentication-providers.md#tailscale-whois)
- [**🎓 Advanced configuration**](./docs/05-advanced-configuration.md)
  - [Configure health checks](./docs/05-advanced-configuration.md#configure-health-checks)
  - [Metrics](./docs/05-advanced-configuration.md#metrics)
  - [Token signing keys](./docs/05-advanced-configuration.md#token-signing-keys)
  - [Configure session lifetime](./docs/05-advanced-configuration.md#configure-session-lifetime)
  - [Security hardening](./docs/05-advanced-configuration.md#security-hardening)
- [**📍 Endpoints**](./docs/06-endpoints.md)
  - [Profile route](./docs/06-endpoints.md#profile-route)
  - [APIs](./docs/06-endpoints.md#apis)
