---
title: "Tailscale Whois"
---

You can configure Single Sign-On (SSO) for clients that access your Traefik server through [Tailscale](https://tailscale.com/). Users will be automatically authenticated when the request comes through the Tailscale network.

This offers a similar behavior to the Tailscale [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth) component.

1. Your container host must be joined to a Tailnet, and you must have the Tailscale service running on the host.
2. Make sure that the socket `/var/run/tailscale/` is mounted into the `traefik-forward-auth` container.  
3. Configure Traefik Forward Auth with a `tailscaleWhois` property in the provider's configuration:

You can restrict the Tailnets that can authenticate with your service using this option:

- [`allowedTailnet`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-allowedtailnet): If set, restricts users who are part of this specific Tailnet. Note that due to how Tailscale works, Tailnet names are only returned for nodes that are part of the current Tailnet, and not nodes that are being added as "guests".

Traefik Forward Auth will also include in the session tokens [Application Capabilities](https://tailscale.com/kb/1537/grants-app-capabilities) that are assigned to the node in the Tailnet's ACL configuration. Only capabilities listed in the [`capabilityNames`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-capabilityNames) option are included, whose default value is `["italypaleale.me/traefik-forward-auth"]`.

For example, you can assign app capabilities to a node by listing them in your ACL configuration:

```json
"grants": [
  {
    "src": ["user@example.com", "group:engineering"],
    "dst": ["tag:traefik"],
    "app": {
      "italypaleale.me/traefik-forward-auth": [
        { /* Object 1 */ },
        { /* Object 2 */ }
      ],
    }
  }
]
```

The session tokens issued by Traefik Forward Auth will then include a claim `{"italypaleale.me/traefik-forward-auth": [ { ... }, { ... } ]}`.

## Full configuration example

The following is a complete `tfa-config.yaml` example using Tailscale Whois as the authentication provider. The `tailscaleWhois` provider has no required options; the optional ones listed above are commented out.

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
      - # Configure authentication with Tailscale Whois
        tailscaleWhois:
          # Optional: restrict to a specific Tailnet only
          # allowedTailnet: "yourtailnet.ts.net"
          # Optional: customize the names of the capabilities to read from Tailscale peer capabilities
          # capabilityNames: ["italypaleale.me/traefik-forward-auth"]
```

[Full list of configuration options for Tailscale Whois and example](/advanced/all-configuration-options#using-tailscale-whois)
