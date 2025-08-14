# Migrating from v3

Traefik Forward Auth v4 is a major release that includes a number of breaking changes. At minimum, the way you configure Traefik Forward Auth needs to be updated significantly.

## YAML-only configuration, new format

In v4, support for configuring Traefik Forward Auth via **environmental variables has been removed**, and passing a YAML file is the only way to configure the application. This was both necessary to support structured config options (such as lists of providers - more on that below) and for security reasons (since passing secrets, such as secret keys, via env vars is not secure).

> It's recommended to treat the Traefik Forward Auth's configuration file as a secret, mounted as a Docker secret (or Kubernetes secret).

**Actions:**

- ✅ Take a look at the [`config.sample.yaml`](../config.sample.yaml) file which explains the **new configuration format**, and convert your config file (note the use of portals now).
- ✅ **Remove all environmental variables** and use the configuration file for all options. You can take a look at the [Quickstart](./01-quickstart.md) docs for an example of mounting the config file as a Docker secret.

## Authentication portals, redirect URL changes, and default portal

New in v4 is the concept of [authentication portals](./04-authentication-portals.md), which allows both:

- Configuring multiple auth providers for a single portal. For example, allows signing in with both Google and Microsoft accounts.
- Configure multiple portals for different apps (different Traefik routers). For example, you can now use the same instance of Traefik Forward Auth for multiple Traefik routers, with different authentication portals (and providers).

In the config file (see [`config.sample.yaml`](../config.sample.yaml)), there's a new top-level [`portal`](03-all-configuration-options.md#portal-configuration) array that allows defining portals, each containing one or more identity providers.

Because of the addition of portals,

1. **The endpoint used in the Traefik's configuration** for the forward auth middleware may need to be changed.

   ```yaml
   # Before (no portal):
   labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181/"

   # After (with "main" portal):
   labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181/portals/main"
   ```

1. **Callback URLs** may need to be updated in your Identity Provider's configuration too. For example, with a portal named `main`, the callback URL becomes:

   ```
   Before (no portal):
   https://auth.example.com/oauth2/callback

   After (with "main" portal):
   https://auth.example.com/portals/main/oauth2/callback
   ```

**Alternatively**, if you have a single portal, you can use the [`defaultPortal`](03-all-configuration-options.md#config-opt-defaultportal) key in the config file to set a **default portal**, which remains available at the root endpoint of Traefik Forward Auth. For example, if you have a single portal named `main` in the `portals` array, you can set it as default portal:

```yaml
defaultPortal: "main"
```

With the default portal, Traefik Forward Auth **continues to respond on the root endpoint** too (in addition to `/portal/<name>`), so:

- Traefik can stay configured with `http://traefik-forward-auth:4181/` as endpoint for Traefik Forward Auth
- You can leave `https://auth.example.com/oauth2/callback` as callback URL in your IdP

**Action:**

- ✅ Configure authentication portals in the Traefik Forward Auth config file
   - 👉 If using a single portal, consider setting `defaultPortal` to preserve the URLs used in the Traefik configuration and in your IdP
   - 👉 If configuring multiple portals, make sure to update the Traefik's configuration and the callback URL in the IdP

**More info:**

- [Docs for authentication portals](./04-authentication-portals.md)

## Authorization conditions replace provider's allowlists

In v3, Traefik Forward Auth included the ability to set certain authorization (AuthZ) rules in certain providers, such as:

- GitHub: `authGitHub_allowedUsers`
- Google: `authGoogle_allowedUsers`, `authGoogle_allowedEmails`, `authGoogle_allowedDomains`
- Microsoft Entra ID: `authMicrosoftEntraID_allowedUsers`, `authMicrosoftEntraID_allowedEmails`
- OpenID Connect: `authOpenIDConnect_allowedUsers`, `authOpenIDConnect_allowedEmails`
- Tailscale Whois: `authTailscaleWhois_allowedUsers`

All the options above have been removed and **replaced with [authorization conditions](06-authorization-conditions.md)**.

- Authorization conditions offer much more flexibility, including being able to set rules on all kinds of claims, not just usernames or emails: this includes group membership (_GBAC, Group Based Access Control_) and roles (_RBAC, Role Based Access Control_).
- Authorization conditions are passed by Traefik as query string args, allowing you to set different authorization rules for each Traefik router. For example, if you have an app where all endpoints require authentication (AuthN), but some are restricted to admins only, you can now do that with the same Traefik Forward Auth instance, maintaing the same session for users.
- Lastly, with authorization conditions all authorization rules are kept in the Traefik's configuration (dynamic configuration or Docker container labels). This way, they are defined alongside your app, and not in the configuration for Traefik Forward Auth.

**Action:**

- ✅ Set your authorization rules in the Traefik's configuration as query string args passed to Traefik Forward Auth. For example:

   ```yaml
   # Docker labels

   # Requires users' IDs to be "user123" OR "user987"
   # Note the "if" query string arg is the URL-encoded value of `Eq("id","user123") || Eq("id","user987")`
   - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181/portals/main?if=Eq%28%22id%22%2C%22user123%22%29%20%7C%7C%20Eq%28%22id%22%2C%22user987%22%29"

   # Requires users' emails to be "user1@example.com" OR "user2@example.com"
   # Note the "if" query string arg is the URL-encoded value of `Eq("email","user1@example.com") || Eq("email","user2@example.com")`
   - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181/portals/main?if=Eq%28%22email%22%2C%22user1%40example.com%22%29%20%7C%7C%20Eq%28%22email%22%2C%22user2%40example.com%22%29"

   # For the Google provider, requires the domain to be "example.com"
   # Note the "if" query string arg is the URL-encoded value of `Eq("hd","example.com")`
   - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181/portals/main?if=Eq%28%22hd%22%2C%22example.com%22%29"
   ```

**More info:**

- [Docs for authorization conditions](06-authorization-conditions.md)

## Changes in authentication providers

Traefik Forward Auth v4 includes some changes to how two providers interpret data from the authentication server. These _may require_ changes to your application.

### Google

- Detecting the user's domain now uses the `hd` claim returned by Google, rather than the domain of the email address.  
   This should make it simpler to work with users who are federated.

**Action:**

- ✅ If using the Google provider and you work with federated accounts, ensure your application can handle them properly.

### Microsoft Entra ID

- The user ID now uses the value of the `oid` claim instead of the user's email address.  
   The [`oid` claim](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference#payload-claims) is stable for each user in a given tenant, guaranteed to never change. The previous behavior, of using the email address, was incorrect, explicitly discouraged by Microsoft.

**Action:**

- ✅ If using the Microsoft Entra ID provider, ensure your application can work with the new values for user IDs.

## Changes to OpenTelemetry and Prometheus configuration

Starting with v4, you can configure observability with OpenTelemetry and/or Prometheus using the `OTEL_*` environmental variables from the OpenTelemetry SDK, for logs, metrics, and traces. Support for configuring observability with the Traefik Forward Auth configuration file has been removed.

**Action:**

- ✅ Check the [docs on observability](./07-advanced-configuration.md#observability-logs-traces-metrics) for how to configure Traefik Forward Auth with OpenTelemetry and/or Prometheus.
