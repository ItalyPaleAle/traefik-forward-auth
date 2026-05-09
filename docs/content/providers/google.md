---
title: "Google"
---

To use Google for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](/docs/configuration#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `google` property:

- [`clientID`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-google-portals-$-providers-$-google-clientid): OAuth2 client ID of your application
- [`clientSecret`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-google-portals-$-providers-$-google-clientsecret): OAuth2 client secret of your application

## Full configuration example

The following is a complete `tfa-config.yaml` example using Google as the authentication provider. Required options are populated, while optional ones are commented out.

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
      - # Configure authentication with Google
        google:
          clientID: "your-google-client-id.apps.googleusercontent.com"
          clientSecret: "your-client-secret"
          # Alternative to `clientSecret`: load the secret from a file
          # clientSecretFile: "/var/run/secrets/traefik-forward-auth/google/client-secret"
```

[Full list of configuration options for Google and example](/advanced/all-configuration-options#using-google)
