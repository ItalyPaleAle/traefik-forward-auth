---
title: "GitHub"
---

To use GitHub for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](/docs/configuration#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `github` property:

- [`clientID`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientid): OAuth2 client ID of your application
- [`clientSecret`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientsecret): OAuth2 client secret of your application

[Full list of configuration options for GitHub and example](/advanced/all-configuration-options#using-github)
