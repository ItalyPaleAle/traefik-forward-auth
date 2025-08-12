# 🔑 Supported providers

- [GitHub](#github)
- [Google](#google)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Other OpenID Connect providers](#other-openid-connect-providers)
- [Tailscale Whois](#tailscale-whois)

## GitHub

To use GitHub for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `github` property:

- [`clientID`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientid): OAuth2 client ID of your application
- [`clientSecret`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-github-portals-$-providers-$-github-clientsecret): OAuth2 client secret of your application

[Full list of configuration options for GitHub and example](./03-all-configuration-options.md#using-github)

## Google

To use Google for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `google` property:

- [`clientID`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-google-portals-$-providers-$-google-clientid): OAuth2 client ID of your application
- [`clientSecret`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-google-portals-$-providers-$-google-clientsecret): OAuth2 client secret of your application

[Full list of configuration options for Google and example](./03-all-configuration-options.md#using-google)

## Microsoft Entra ID

To use Microsoft Entra ID (formerly Azure AD) for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `microsoftEntraID` property:

- [`tenantID`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-tenantid): ID of the tenant where your application resides
- [`clientID`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientid): Client ID of your application
- [`clientSecret`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientsecret): Client secret of your application

[Full list of configuration options for Microsoft Entra ID and example](./03-all-configuration-options.md#using-microsoftentraid)

### Using Federated Identity Credentials

Using Federated Identity Credentials is an alternative to configuring your Microsoft Entra ID application with a client secret. This offers better security because there are no pre-shared secrets to manage, and easier maintenance since client secrets need to be rotated periodically.

Using Federated Identity Credentials is the **recommended** approach when:

- The application is running on Azure on a platform that supports [Managed Identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview). Both system-assigned and user-assigned identities are supported.
- The application is running on platforms that support [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation), for example on Kubernetes (on any cloud or on-premises) or other clouds.

> Check the documentation for your platform on configuring the managed identity or the workload identity for your application.

To use Federated Identity Credentials, you need configure the application for federated credentials. The steps below show an example for using managed identity; for using workload identity federation, consult the documentation for your platform.

For managed identity, you will need the **object ID** (i.e. "principal ID") of your identity. This can usually be found on the Azure Portal in the "Identity" section of your resource.

```sh
# Set this to the ID of your Entra ID application
APP_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Set this to the UUID of your managed identity
IDENTITY_OBJECT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Set the TENANT_ID environmental variable
TENANT_ID=$(az account show | jq -r '.tenantId')

az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters "{\"name\": \"mi-${IDENTITY_OBJECT_ID}\",\"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",\"subject\": \"${IDENTITY_OBJECT_ID}\",\"description\": \"Federated Identity for Managed Identity ${IDENTITY_OBJECT_ID}\",\"audiences\": [\"api://AzureADTokenExchange\"]}"
```

Finally, configure Traefik Forward Auth by setting a value for [`azureFederatedIdentity`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-azurefederatedidentity):

- `"ManagedIdentity"` for using a system-assigned managed identity
- `"ManagedIdentity=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` for using a user-assigned managed identity (replace the placeholder value with the **client ID** of your managed identity)
- `"WorkloadIdentity"` for using workload identity

## Other OpenID Connect providers

Traefik Forward Auth support generic OpenID Connect providers. This includes Auth0, Okta, etc.

To use an OpenID Connect provider for user authentication, create an application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `openIDConnect` property:

- [`tokenIssuer`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tokenissuer): Token issuer  
   This is generally a URL like `https://tenant.identityprovider.com/`.  
   Traefik Forward Auth will try to fetch the OpenID Configuration document at `<tokenIssuer>/.well-known/openid-configuration`; in this example, `https://tenant.identityprovider.com/.well-known/openid-configuration`.
- [`clientID`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-clientid): Client ID of your application
- [`clientSecret`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-clientsecret): Client secret of your application

The OpenID Connect provider supports additional configuration options that can be helpful to configure how Traefik Forward Auth communicates with the Identity Provider:

- [`tlsInsecureSkipVerify`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlsinsecureskipverify): If true, skips validating TLS certificates when communicating with the Identity Provider. While this option can enable support for self-signed TLS certificates, it should be used with caution.
- [`tlsCACertificatePEM`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlscacertificatepem): PEM-encoded CA certificate used when communicating with the Identity Provider.
- [`tlsCACertificatepath`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-openidconnect-portals-$-providers-$-openidconnect-tlscacertificatepath): Path to a file containing the PEM-encoded CA certificate used when communicating with the Identity Provider.

[Full list of configuration options for OpenID Connect and example](./03-all-configuration-options.md#using-openid-connect)

## Tailscale Whois

You can configure Single Sign-On (SSO) for clients that access your Traefik server through [Tailscale](https://tailscale.com/). Users will be automatically authenticated when the request comes through the Tailscale network.

This offers a similar behavior to the Tailscale [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth) component.

1. Your container host must be joined to a Tailnet, and you must have the Tailscale service running on the host.
2. Make sure that the socket `/var/run/tailscale/` is mounted into the `traefik-forward-auth` container.  
3. Configure Traefik Forward Auth with a `tailscaleWhois` property in the provider's configuration:

You can restrict the Tailnets that can authenticate with your service using this option:

- [`allowedTailnet`](./03-all-configuration-options.md#config-opt-portals.$.providers.$-tailscalewhois-portals-$-providers-$-tailscalewhois-allowedtailnet): If set, restricts users who are part of this specific Tailnet. Note that due to how Tailscale works, Tailnet names are only returned for nodes that are part of the current Tailnet, and not nodes that are being added as "guests".

[Full list of configuration options for Tailscale Whois and example](./03-all-configuration-options.md#using-tailscale-whois)
