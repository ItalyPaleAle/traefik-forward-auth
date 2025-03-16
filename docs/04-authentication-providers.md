# 🔑 Authentication providers

- [GitHub](#github)
- [Google](#google)
- [Microsoft Entra ID](#microsoft-entra-id)
- [Other OpenID Connect providers](#other-openid-connect-providers)
- [Tailscale Whois](#tailscale-whois)

## GitHub

To use GitHub for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](./03-all-configuration-options.md#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `github`
- [`authGithub_clientID`](./03-all-configuration-options.md#config-opt-authgithub_clientid) (env: `TFA_AUTHGITHUB_CLIENTID`): OAuth2 client ID of your application
- [`authGithub_clientSecret`](./03-all-configuration-options.md#config-opt-authgithub_clientsecret) (env: `TFA_AUTHGITHUB_CLIENTSECRET`): OAuth2 client secret of your application

You can restrict the users that can authenticate with your service using this option:

- [`authGitHub_allowedUsers`](./03-all-configuration-options.md#config-opt-authgithub_allowedusers) (env: `TFA_AUTHGITHUB_ALLOWEDUSERS`): List of allowed users, matching the GitHub user handle.

## Google

To use Google for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](./03-all-configuration-options.md#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `google`
- [`authGoogle_clientID`](./03-all-configuration-options.md#config-opt-authgoogle_clientid) (env: `TFA_AUTHGOOGLE_CLIENTID`): OAuth2 client ID of your application
- [`authGoogle_clientSecret`](./03-all-configuration-options.md#config-opt-authgoogle_clientsecret) (env: `TFA_AUTHGOOGLE_CLIENTSECRET`): OAuth2 client secret of your application

You can restrict the users that can authenticate with your service using one (or more) of these options:

- [`authGoogle_allowedEmails`](./03-all-configuration-options.md#config-opt-authgoogle_allowedemails) (env: `TFA_AUTHGOOGLE_ALLOWEDEMAILS`): List of allowed users, matching their email address (e.g. `example@gmail.com`)
- [`authGoogle_allowedDomains`](./03-all-configuration-options.md#config-opt-authgoogle_alloweddomains) (env: `TFA_AUTHGOOGLE_ALLOWEDDOMAINS`): List of allowed domain names of users' email addresses (e.g. `mydomain.com`)
- [`authGoogle_allowedUsers`](./03-all-configuration-options.md#config-opt-authgoogle_allowedusers) (env: `TFA_AUTHGOOGLE_ALLOWEDUSERS`): List of allowed users, matching the internal user ID.

## Microsoft Entra ID

To use Microsoft Entra ID (formerly Azure AD) for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](./03-all-configuration-options.md#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `microsoftentraid`
- [`authMicrosoftEntraID_tenantID`](./03-all-configuration-options.md#config-opt-authmicrosoftentraid_tenantid) (env: `TFA_AUTHMICROSOFTENTRAID_TENANTID`): ID of the tenant where your application resides
- [`authMicrosoftEntraID_clientID`](./03-all-configuration-options.md#config-opt-authmicrosoftentraid_clientid) (env: `TFA_AUTHMICROSOFTENTRAID_CLIENTID`): Client ID of your application
- [`authMicrosoftEntraID_clientSecret`](./03-all-configuration-options.md#config-opt-authmicrosoftentraid_clientsecret) (env: `TFA_AUTHMICROSOFTENTRAID_CLIENTSECRET`): Client secret of your application

You can restrict the users that can authenticate with your service using one (or more) of these options:

- [`authMicrosoftEntraID_allowedEmails`](./03-all-configuration-options.md#config-opt-authmicrosoftentraid_allowedemails) (env: `TFA_AUTHMICROSOFTENTRAID_ALLOWEDEMAILS`): List of allowed users, matching their email address (e.g. `example@gmail.com`)
- [`authMicrosoftEntraID_allowedUsers`](./03-all-configuration-options.md#config-opt-authmicrosoftentraid_allowedusers) (env: `TFA_AUTHMICROSOFTENTRAID_ALLOWEDUSERS`): List of allowed users, matching the internal user ID.

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

Finally, configure Traefik Forward Auth by setting a value for [`authMicrosoftEntraID_azureFederatedIdentity`](./03-all-configuration-options.md#config-opt-authmicrosoftentraid_azureFederatedIdentity) (env: `TFA_AUTHMICROSOFTENTRAID_AZUREFEDERATEDIDENTITY`)

- `"ManagedIdentity"` for using a system-assigned managed identity
- `"ManagedIdentity=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` for using a user-assigned managed identity (replace the placeholder value with the **client ID** of your managed identity)
- `"WorkloadIdentity"` for using workload identity

## Other OpenID Connect providers

Traefik Forward Auth support generic OpenID Connect providers. This includes Auth0, Okta, etc.

To use an OpenID Connect provider for user authentication, create an application and configure the callback to `https://<endpoint>/oauth2/callback` (see [examples](./02-configuration.md#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Set the following options for Traefik Forward Auth:

- [`authProvider`](./03-all-configuration-options.md#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `openidconnect`
- [`authOpenIDConnect_tokenIssuer`](./03-all-configuration-options.md#config-opt-authopenidconnect_tokenissuer) (env: `TFA_AUTHOPENIDCONNECT_TOKENISSUER`): Token issuer  
   This is generally a URL like `https://tenant.identityprovider.com/`.  
   Traefik Forward Auth will try to fetch the OpenID Configuration document at `<tokenIssuer>/.well-known/openid-configuration`; in this example, `https://tenant.identityprovider.com/.well-known/openid-configuration`.
- [`authOpenIDConnect_clientID`](./03-all-configuration-options.md#config-opt-authopenidconnect_clientid) (env: `TFA_AUTHOPENIDCONNECT_CLIENTID`): Client ID of your application
- [`authOpenIDConnect_clientSecret`](./03-all-configuration-options.md#config-opt-authopenidconnect_clientsecret) (env: `TFA_AUTHOPENIDCONNECT_CLIENTSECRET`): Client secret of your application

You can restrict the users that can authenticate with your service using one (or more) of these options:

- [`authOpenIDConnect_allowedUsers`](./03-all-configuration-options.md#config-opt-authopenidconnect_allowedusers) (env: `TFA_OPENIDCONNECT_ALLOWEDUSERS`): List of allowed users, matching the value of the "sub" claim.
- [`authOpenIDConnect_allowedEmails`](./03-all-configuration-options.md#config-opt-authopenidconnect_allowedemails) (env: `TFA_OPENIDCONNECT_ALLOWEDEMAILS`): List of allowed users, matching the value of the "email" claim.

## Tailscale Whois

You can configure Single Sign-On (SSO) for clients that access your Traefik server through [Tailscale](https://tailscale.com/). Users will be automatically authenticated when the request comes through the Tailscale network.

This offers a similar behavior to the Tailscale [nginx-auth](https://github.com/tailscale/tailscale/tree/main/cmd/nginx-auth) component.

1. Your container host must be joined to a Tailnet, and you must have the Tailscale service running on the host.
2. Make sure that the socket `/var/run/tailscale/` is mounted into the `traefik-forward-auth` container.  
3. Configure Traefik Forward Auth with:

   - [`authProvider`](./03-all-configuration-options.md#config-opt-authprovider) (env: `TFA_AUTHPROVIDER`): `tailscalewhois`

Example using Docker Compose (unrelated configuration options and labels omitted):

```yaml
services:
  traefik-forward-auth:
    image: ghcr.io/italypaleale/traefik-forward-auth:3
    volumes:
      - /var/run/tailscale/:/var/run/tailscale
    environment:
      - TFA_AUTHPROVIDER=tailscalewhois
```

You can restrict the users or tailnets that can authenticate with your service using one (or more) of these options:

- [`authTailscaleWhois_allowedTailnet`](./03-all-configuration-options.md#config-opt-authtailscalewhois_allowedtailnet) (env: `TFA_AUTHTAILSCALEWHOIS_ALLOWEDTAILNET`): If set, restricts users who are part of this specific Tailnet. Note that due to how Tailscale works, Tailnet names are only returned for nodes that are part of the current Tailnet, and not nodes that are being added as "guests".
- [`authTailscaleConnect_allowedUsers`](./03-all-configuration-options.md#config-opt-authtailscaleconnect_allowedusers) (env: `TFA_AUTHTAILSCALECONNECT_ALLOWEDUSERS`): List of allowed users, matching the user ID.
