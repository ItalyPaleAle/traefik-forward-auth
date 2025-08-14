# Traefik Forward Auth v4

A simple service that provides authentication and SSO with OAuth2, OpenID Connect, and Tailscale Whois, for the [Traefik](https://github.com/traefik/traefik) reverse proxy.

> 👉 Looking for the source code and docs for Traefik Forward Auth v3? You can find them in the [v3 branch](https://github.com/ItalyPaleAle/traefik-forward-auth/tree/v3).

## ✨ Highlights

- Supports authentication with **Google**, **Microsoft Entra ID** (formerly Azure AD), **GitHub**, and generic **OpenID Connect** providers (including Auth0, Okta, etc).
- Single Sign-On with **Tailscale Whois** (similarly to Tailscale's [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth))
- Protect multiple Traefik services with a single instance of traefik-forward-auth.

## 👉 Releases

The Docker image is available on GitHub Packages. Container images are multi-arch and run on `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.

Using the `4` tag is recommended:

```text
ghcr.io/italypaleale/traefik-forward-auth:4
```

You can also pin to the latest patch release as found in the [Releases page](https://github.com/ItalyPaleAle/traefik-forward-auth/releases):

```text
ghcr.io/italypaleale/traefik-forward-auth:4.x.x
```

## 📘 Docs

- [**🚀 Quickstart**](./docs/01-quickstart.md)
  - [Authenticate with Google](./docs/01-quickstart.md#authenticate-with-google)
  - [Authenticate with Tailscale](./docs/01-quickstart.md#authenticate-with-tailscale)
- [**⚙️ Configuration**](./docs/02-configuration.md)
  - [Configuring Traefik Forward Auth](./docs/02-configuration.md#configuring-traefik-forward-auth)
  - [Exposing Traefik Forward Auth](./docs/02-configuration.md#exposing-traefik-forward-auth)
- [**📖 All configuration options**](./docs/03-all-configuration-options.md)
- [**🛡️ Authentication portals**](./docs/04-authentication-portals.md)
  - [Configuring portals](./docs/04-authentication-portals.md#configuring-portals)
  - [Default portal](./docs/04-authentication-portals.md#default-portal)
- [**🔑 Supported providers**](./docs/05-supported-providers.md)
  - [GitHub](./docs/05-supported-providers.md#github)
  - [Google](./docs/05-supported-providers.md#google)
  - [Microsoft Entra ID](./docs/05-supported-providers.md#microsoft-entra-id)
  - [Other OpenID Connect providers](./docs/05-supported-providers.md#other-openid-connect-providers)
  - [Tailscale Whois](./docs/05-supported-providers.md#tailscale-whois)
- [**🔐 Authorization conditions**](./docs/06-authorization-conditions.md)
  - [Using conditions](./docs/06-authorization-conditions.md#using-conditions)
  - [Sessions and authorization conditions](./docs/06-authorization-conditions.md#sessions-and-authorization-conditions)
- [**🎓 Advanced configuration**](./docs/07-advanced-configuration.md)
  - [Configure health checks](./docs/07-advanced-configuration.md#configure-health-checks)
  - [Observability: Logs, Traces, Metrics](./docs/07-advanced-configuration.md#observability-logs-traces-metrics)
  - [Token signing keys](./docs/07-advanced-configuration.md#token-signing-keys)
  - [Configure session lifetime](./docs/07-advanced-configuration.md#configure-session-lifetime)
  - [Security hardening](./docs/07-advanced-configuration.md#security-hardening)
- [**📍 Endpoints**](./docs/08-endpoints.md)
  - [Profile routes](./docs/08-endpoints.md#profile-routes)
  - [APIs](./docs/08-endpoints.md#apis)

Migrating from a previous version of Traefik Forward Auth:

- [Migrating from v3](./docs/migrating-v3.md)
