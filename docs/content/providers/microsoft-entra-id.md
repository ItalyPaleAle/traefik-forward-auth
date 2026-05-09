---
title: "Microsoft Entra ID"
---

To use Microsoft Entra ID (formerly Azure AD) for user authentication, create an OAuth2 application and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](/docs/configuration#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `microsoftEntraID` property:

- [`tenantID`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-tenantid): ID of the tenant where your application resides
- [`clientID`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientid): Client ID of your application
- [`clientSecret`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientsecret): Client secret of your application

## Full configuration example

The following is a complete `tfa-config.yaml` example using Microsoft Entra ID as the authentication provider.

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
      # Configure authentication with Microsoft Entra ID
      - microsoftEntraID:
          tenantID: "your-tenant-id"
          clientID: "your-client-id"
          clientSecret: "your-client-secret"

          # Recommended on supported platforms: use a Federated Identity Credential instead of `clientSecret`
          # See "Using Federated Identity Credentials" below for details
          #clientAssertion: "AzureManagedIdentity"
```

[Full list of configuration options for Microsoft Entra ID](/advanced/all-configuration-options#using-microsoftentraid)

## Using Federated Identity Credentials

Using Federated Identity Credentials is an alternative to configuring your Microsoft Entra ID application with a client secret. This offers better security because there are no pre-shared secrets to manage, and easier maintenance since client secrets need to be rotated periodically.

Using Federated Identity Credentials is the **recommended** approach when:

- The application is running on Azure on a platform that supports [Managed Identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview). Both system-assigned and user-assigned identities are supported.
- The application is running on platforms that support [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation), for example on Kubernetes (on any cloud or on-premises) or other clouds.
- The application is running on Kubernetes and can use service account tokens
- The application is running on a node connected to a Tailscale network and you have deployed [tsiam](https://github.com/italypaleale/tsiam)

> Check the documentation for your platform on configuring the managed identity or the workload identity for your application.

To use Federated Identity Credentials, you first need to configure your Entra ID applictaion. The steps below show an example for using managed identity; for using workload identity federation, consult the documentation for your platform.

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

Finally, configure Traefik Forward Auth by setting a value for [`clientAssertion`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-microsoftentraid-portals-$-providers-$-microsoftentraid-clientassertion):

- `AzureManagedIdentity`: uses Azure Managed Identity with a system-assigned identity
- `AzureManagedIdentity=client-id`: uses Azure Managed Identity with a user-assigned identity whose client id is "client-id" (e.g. "AzureManagedIdentity=00000000-0000-0000-0000-000000000000")
- `AzureWorkloadIdentity`: uses Azure Workload Identity, e.g. in Kubernetes
- `KubernetesServiceAccountToken=path`: uses a token read from a Kubernetes service account token file. If `path` is omitted, defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- `tsiam=endpoint`: uses tsiam to obtain Workload Identity from nodes that use Tailscale. Specify the endpoint of tsiam as value, e.g. `tsiam=https://tsiam`. Uses as resource name the constant value `api://AzureADTokenExchange`.
