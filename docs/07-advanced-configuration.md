# 🎓 Advanced configuration

- [Configure health checks](#configure-health-checks)
- [Observability: Logs, Traces, Metrics](#observability-logs-traces-metrics)
- [Token signing keys](#token-signing-keys)
- [Configure session lifetime](#configure-session-lifetime)
- [Security hardening](#security-hardening)

## Configure health checks

Traefik Forward Auth supports health checks on the `/healthz` endpoint, which can be used to configure health checks in your platform. This endpoint returns a response with a `200` status code to indicate the application is healthy.

Calls to the `/healthz` endpoint do not appear in access logs unless the configuration option [`logs.omitHealthChecks`](./03-all-configuration-options.md#config-opt-logs-omithealthchecks) is set to `false` (default is `true`).

> The `/healthz` endpoint is unchanged regardless of the value of the [`server.basePath`](./03-all-configuration-options.md#config-opt-server-basepath) configuration.

## Observability: Logs, Traces, Metrics

Traefik Forward Auth offers supprot for observability using OpenTelemetry.

Observability features are configured with the [OpenTelemetry SDK's standard `OTEL_*` environmental variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/). To send logs, metrics, and traces to a collector using the OTLP protocol, you will need to set environmental variables similar to these ([full docs](https://opentelemetry.io/docs/specs/otel/protocol/exporter/)):

```sh
export OTEL_LOGS_EXPORTER="otlp"
export OTEL_METRICS_EXPORTER="otlp"
export OTEL_TRACES_EXPORTER="otlp"
export OTEL_EXPORTER_OTLP_PROTOCOL="" # "grpc" or "http/protobuf" or "http/json"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://collector:4318"
```

Metrics can also be exposed on a Prometheus-compatible endpoint, which can be enabled using environmental variables similar to:

```sh
export OTEL_METRICS_EXPORTER="prometheus"
export OTEL_EXPORTER_PROMETHEUS_HOST="0.0.0.0"
export OTEL_EXPORTER_PROMETHEUS_PORT="9464"
```

## Token signing keys

Traefik Forward Auth issues JWT tokens which are signed with HMAC-SHA256 (HS256), an operation which requires a "signing key".

The signing key is randomly generated when Traefik Forward Auth starts. For most users, relaying on the default behavior is sufficient—and recommended.

However, when a JWT is signed with a randomly-generated token, they are invalidated when the Traefik Forward Auth process that issued them is restarted, or if the request hits a separate replica.

In certain situations, for example when:

- You have multiple replicas of Traefik Forward Auth, and/or
- You auto-scale Traefik Forward Auth, and/or
- You want tokens to remain valid even after a restart of Traefik Forward Auth

You can set an explicit value for the [`tokens.signingKey`](./03-all-configuration-options.md#config-opt-tokens-signingkey) option. For example, you can generate a random string with `openssl rand -base64 32`.

The token signing key can also be written to a file (including a Docker/Kubernetes secret mounted inside the container), whose path is passed using the [`tokens.signingKeyFile`](./03-all-configuration-options.md#config-opt-tokens-signingkeyfile) configuration option.

> Note that Traefik Forward Auth does not use the value provided in `tokens.signingKey` as-is to sign JWTs. Instead, the actual token signing key is derived using a key derivation function on the value provided in the configuration option.

## Configure session lifetime

When Traefik Forward Auth authenticates a user, it issues a JWT, saved in a cookie on the user's browser, to maintain the session.

By default, sessions are valid for 2 hours.

You can configure the lifetime of a session using the option [`tokens.sessionLifetime`](./03-all-configuration-options.md#config-opt-tokens-sessionlifetime), which accepts a Go duration (such as `2h` for 2 hours, or `30m` for 30 minutes).

## Security hardening

This section contains some advanced options to harden the security of Traefik Forward Auth.

### Container security options

Traefik Forward Auth's containers run as non-root users and do not require write access to the root file system of the container. As such, you can configure the container with certain security options.

For **Docker Compose** (unrelated fields are omitted):

```yaml
# docker-compose.yaml
services:
  traefik-forward-auth:
    # Read-only root file system
    read_only: true
    # Run as UID/GID 65532/65532
    user: 65532:65532
```

For **Kubernetes**, set these options in the Pod's container definition (unrelated fields are omitted):

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: "traefik-forward-auth"
      securityContext:
        readOnlyRootFilesystem: true
        runAsUser: 65532
        runAsGroup: 65532
```

### mTLS between Traefik and Traefik Forward Auth

Traefik Forward Auth's root endpoint (`/`) is meant to be invoked by Traefik only. Aside from network-level access control rules, you can configure TLS with mutual authentication to encrypt the traffic between Traefik and Traefik Forward Auth, and ensure that only Traefik can invoke the root endpoint of the forward auth service.

1. Generate a root CA certificate, then generate a certificate for the server (Traefik Forward Auth) and the client (Traefik).

   > You can see an example of generating the various certificates and keys using [CFSSL](https://github.com/cloudflare/cfssl) in [mradile/cfssl-mtls-demo](https://github.com/mradile/cfssl-mtls-demo/).

2. Make sure that files are named according to these conventions:

   - For Traefik Forward Auth, files must be mounted in the container in the path `/etc/traefik-forward-auth` (the same folder where the `config.yaml` file is mounted):

     - `tls-ca.pem`: CA certificate
     - `tls-cert.pem`: Server certificate for Traefik Forward Auth
     - `tls-key.pem`: Server key for Traefik Forward Auth

   - For Traefik, mount the files in the container at the path you prefer. You need to provide the CA certificate, as well as the client certificate and key for Traefik.  
     In this example, we'll mount the certificates in `/mnt/tls` in the container, with files named:

     - `tls-ca.pem`: CA certificate
     - `tls-cert.pem`: Client certificate for Traefik
     - `tls-key.pem`: Client key for Traefik

3. Configure Traefik Forward Auth to use mTLS by setting these options:

   - [`server.tlsPath`](./03-all-configuration-options.md#config-opt-server-tlspath): `/etc/traefik-forward-auth`
   - [`server.tlsClientAuth`](./03-all-configuration-options.md#config-opt-server-tlsclientauth): `true`

4. Configure Traefik to present a client certificate when connecting to Traefik Forward Auth. For example, using this Docker Compose and Traefik Forward Auth configuration (unrelated properties are omitted):

   ```yaml
   ### docker-compose.yaml
   version: '3'
     traefik:
       volumes:
         - "/path/on/host:/mnt/tls"

     traefik-forward-auth:
       secrets:
         - source: "tfa_config"
           target: "/etc/traefik-forward-auth/config.yaml"
       labels:
         # Note the use of "https"
         - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=https://traefik-forward-auth:4181/portals/main"

         # Set the client certificates
         - "traefik.http.middlewares.traefik-forward-auth.forwardauth.tls.ca=/mnt/tls/tls-ca.pem"
         - "traefik.http.middlewares.traefik-forward-auth.forwardauth.tls.cert=/mnt/tls/tls-cert.pem"
         - "traefik.http.middlewares.traefik-forward-auth.forwardauth.tls.key=/mnt/tls/tls-key.pem"

         - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User,X-Authenticated-User"
         - "traefik.http.middlewares.traefik-forward-auth.forwardauth.trustForwardHeader=true"
         - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"
         - "traefik.http.services.traefik-forward-auth.loadbalancer.serversTransport=forwardAuthCA@file"
         - "traefik.http.routers.traefik-forward-auth.rule=Host(`auth.example.com`)"
         - "traefik.http.routers.traefik-forward-auth.entrypoints=websecure"
         - "traefik.http.routers.traefik-forward-auth.tls=true"

   secrets:
     tfa_config:
       file: tfa-config.yaml

   ### tfa-config.yaml
   server:
      tlsPath: "/etc/traefik-forward-auth"
      tlsClientAuth: true
   ```

5. Set the [server transport](https://doc.traefik.io/traefik/routing/services/#serverstransport_1) in the Traefik configuration using a [File provider](https://doc.traefik.io/traefik/providers/file/):

   ```yaml
   http:
     serversTransports:
       forwardAuthCA:
         rootCAs:
           - "/mnt/tls/tls-ca.pem"
   ```

If the certificates are updated on disk, Traefik Forward Auth automatically reloads them.

> When mTLS is used, only the portal's root endpoint (`/portal/<name>`) authenticates the client certificate. Other endpoints will be served over TLS, but will not require the callers to present a valid client certificate.
w
> Note: you can enable TLS in Traefik Forward Auth without configuring mTLS for authenticating Traefik. In this case, set `tlsClientAuth` to `false`, but nonetheless mount the server certificates in the Traefik Forward Auth containers. When configuring Traefik, do not include client certificates.
