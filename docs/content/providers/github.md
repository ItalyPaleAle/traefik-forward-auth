---
title: "GitHub"
---

To use GitHub for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](/docs/configuration#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `github` property:

- [`clientID`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientid): OAuth2 client ID of your application
- [`clientSecret`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientsecret): OAuth2 client secret of your application

## Full configuration example

The following is a complete `tfa-config.yaml` example using GitHub as the authentication provider. Required options are populated, while optional ones are commented out.

```yaml
# tfa-config.yaml
server:
  # Domain(s) served by Traefik Forward Auth
  # `domain` is the cookie domain (the domain where the app is reachable, or a parent domain)
  # `authHost` is the public hostname of Traefik Forward Auth itself (omit it when using "sub-path" mode)
  domains:
    - domain: "example.com"
      authHost: "auth.example.com"

portals:
  - name: "main"
    providers:
      - # Configure authentication with GitHub
        github:
          clientID: "your-client-id"
          clientSecret: "your-client-secret"
          # Alternative to `clientSecret`: load the secret from a file
          # clientSecretFile: "/var/run/secrets/traefik-forward-auth/github/client-secret"
```

[Full list of configuration options for GitHub and example](/advanced/all-configuration-options#using-github)
