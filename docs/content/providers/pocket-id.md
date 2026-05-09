---
title: "Pocket ID"
---

To use [Pocket ID](https://pocket-id.org/) for user authentication, create a new OAuth2 Client (application) and configure the callback to `https://<endpoint>/portals/<portal>/oauth2/callback` (see [examples](/docs/configuration#exposing-traefik-forward-auth) depending on how Traefik Forward Auth is exposed).

Configure a provider with these options in the `pocketID` property:

- [`endpoint`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-pocketid-portals-$-providers-$-pocketid-endpoint): Pocket ID server endpoint.  
   This is generally a URL like `https://pocketidid.example.com`.
- [`clientID`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-pocketid-portals-$-providers-$-pocketid-clientid): Client ID of your application
- [`clientSecret`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-pocketid-portals-$-providers-$-pocketid-clientsecret): Client secret of your application

The Pocket ID provider supports additional configuration options that can be helpful to configure how Traefik Forward Auth communicates with the Pocket ID:

- [`tlsInsecureSkipVerify`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-pocketID-portals-$-providers-$-pocketID-tlsinsecureskipverify): If true, skips validating TLS certificates when communicating with Pocket ID. While this option can enable support for self-signed TLS certificates, it should be used with caution.
- [`tlsCACertificatePEM`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-pocketID-portals-$-providers-$-pocketID-tlscacertificatepem): PEM-encoded CA certificate used when communicating with Pocket ID.
- [`tlsCACertificatepath`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-pocketID-portals-$-providers-$-pocketID-tlscacertificatepath): Path to a file containing the PEM-encoded CA certificate used when communicating with Pocket ID.

## Full configuration example

The following is a complete `tfa-config.yaml` example using Pocket ID as the authentication provider. Required options are populated, while optional ones (including the recommended `clientAssertion` for Federated Client Credentials and the additional TLS configuration options) are commented out.

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
      - # Configure authentication with Pocket ID
        pocketID:
          endpoint: "https://pocketidid.example.com"
          clientID: "your-client-id"
          clientSecret: "your-client-secret"
          # Alternative to `clientSecret`: load the secret from a file
          # clientSecretFile: "/var/run/secrets/traefik-forward-auth/pocketid/client-secret"
          # Recommended on supported platforms: use a Federated Client Credential instead of `clientSecret`
          # See "Using Federated Client Credentials" below for details
          # clientAssertion: "AzureManagedIdentity"
          # Optional: TLS configuration for communicating with Pocket ID
          # tlsInsecureSkipVerify: false
          # tlsCACertificatePEM: ""
          # tlsCACertificatePath: ""
```

[Full list of configuration options for Pocket ID and example](/advanced/all-configuration-options#using-pocketID)

## Using Federated Client Credentials

Using Federated Client Credentials is an alternative to configuring your Pocket ID application with a client secret. This offers better security because there are no pre-shared secrets to manage, and easier maintenance since client secrets need to be rotated periodically.

Using Federated Client Credentials is the **recommended** approach when:

- The application is running on Azure on a platform that supports [Managed Identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview). Both system-assigned and user-assigned identities are supported.
- The application is running on platforms that support [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation), for example on Kubernetes (on any cloud or on-premises) or other clouds.
- The application is running on Kubernetes and can use service account tokens.
- The application is running on a node connected to a Tailscale network and you have deployed [tsiam](https://github.com/italypaleale/tsiam).

To use Federated Client Credentials, you first need to configure your OAuth2 Client in Pocket ID, as described in the [official documentation](https://pocket-id.org/docs/guides/oidc-client-authentication).

Finally, configure Traefik Forward Auth by setting a value for [`clientAssertion`](/advanced/all-configuration-options#config-opt-portals.$.providers.$-pocketid-portals-$-providers-$-pocketid-clientassertion):

- `AzureManagedIdentity`: uses Azure Managed Identity with a system-assigned identity
- `AzureManagedIdentity=client-id`: uses Azure Managed Identity with a user-assigned identity whose client id is "client-id" (e.g. "AzureManagedIdentity=00000000-0000-0000-0000-000000000000")
- `AzureWorkloadIdentity`: uses Azure Workload Identity, e.g. in Kubernetes
- `KubernetesServiceAccountToken=path`: uses a token read from a Kubernetes service account token file. If `path` is omitted, defaults to `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- `tsiam=endpoint`: uses tsiam to obtain Workload Identity from nodes that use Tailscale. Specify the endpoint of tsiam as value, e.g. `tsiam=https://tsiam`. Uses as resource name the value of `endpoint`.
