# Traefik Forward Auth v4

A simple service that provides authentication and SSO with OAuth2, OpenID Connect, and Tailscale Whois, for the [Traefik](https://github.com/traefik/traefik) reverse proxy.

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

The documentation is available at [`https://traefik-forward-auth.italypaleale.me`](https://traefik-forward-auth.italypaleale.me).

- [Quickstart](https://traefik-forward-auth.italypaleale.me/docs/quickstart)
- [Configuration](https://traefik-forward-auth.italypaleale.me/docs/configuration)
- [All configuration options](https://traefik-forward-auth.italypaleale.me/advanced/all-configuration-options)
- [Authentication portals](https://traefik-forward-auth.italypaleale.me/docs/authentication-portals)
- [Supported providers](https://traefik-forward-auth.italypaleale.me/providers)
- [Authorization conditions](https://traefik-forward-auth.italypaleale.me/docs/authorization-conditions)
- [Advanced configuration](https://traefik-forward-auth.italypaleale.me/docs/advanced-configuration)
- [Endpoints](https://traefik-forward-auth.italypaleale.me/docs/endpoints)

Migrating from a previous version of Traefik Forward Auth:

- [Migrating from v3](https://traefik-forward-auth.italypaleale.me/advanced/migrating-v3)
