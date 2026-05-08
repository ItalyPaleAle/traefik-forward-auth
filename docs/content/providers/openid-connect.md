---
title: "OpenID Connect"
---

Traefik Forward Auth support generic OpenID Connect providers. This includes Auth0, Okta, etc.

To use an OpenID Connect provider for user authentication, create an application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](/docs/configuration#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `openIDConnect` property:

- [`tokenIssuer`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tokenissuer): Token issuer  
   This is generally a URL like `https://tenant.identityprovider.com/`.  
   Traefik Forward Auth will try to fetch the OpenID Configuration document at `<tokenIssuer>/.well-known/openid-configuration`; in this example, `https://tenant.identityprovider.com/.well-known/openid-configuration`.
- [`clientID`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-clientid): Client ID of your application
- [`clientSecret`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-clientsecret): Client secret of your application

The OpenID Connect provider supports additional configuration options that can be helpful to configure how Traefik Forward Auth communicates with the Identity Provider:

- [`tlsInsecureSkipVerify`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlsinsecureskipverify): If true, skips validating TLS certificates when communicating with the Identity Provider. While this option can enable support for self-signed TLS certificates, it should be used with caution.
- [`tlsCACertificatePEM`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlscacertificatepem): PEM-encoded CA certificate used when communicating with the Identity Provider.
- [`tlsCACertificatepath`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlscacertificatepath): Path to a file containing the PEM-encoded CA certificate used when communicating with the Identity Provider.

[Full list of configuration options for OpenID Connect and example](/advanced/all-configuration-options#using-openid-connect)
