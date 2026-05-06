---
title: "Traefik Forward Auth v4"
nav_title: "Introduction"
weight: 11
---

Traefik Forward Auth is a simple service that provides authentication and SSO with OAuth2, OpenID Connect, and Tailscale Whois for the [Traefik](https://github.com/traefik/traefik) reverse proxy.

## Highlights

- Supports authentication with **Google**, **Microsoft Entra ID** (formerly Azure AD), **GitHub**, and generic **OpenID Connect** providers including Auth0, Okta, Pocket ID
- Single Sign-On with **Tailscale Whois**, similarly to Tailscale's [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth)
- Protect multiple Traefik services with a single instance of Traefik Forward Auth

## Releases

The Docker image is available on GitHub Packages. Container images are multi-arch and run on `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.

Using the `4` tag is recommended:

```text
ghcr.io/italypaleale/traefik-forward-auth:4
```

You can also pin to the latest patch release as found in the [Releases page](https://github.com/ItalyPaleAle/traefik-forward-auth/releases):

```text
ghcr.io/italypaleale/traefik-forward-auth:4.x.x
```

## Start here

- [Quickstart](/docs/quickstart)
- [Configuration](/docs/configuration)
- [Supported Providers](/providers)
- [Advanced Topics](/advanced)
