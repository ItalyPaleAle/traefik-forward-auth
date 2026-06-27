FROM gcr.io/distroless/static-debian12:nonroot

# Build args
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH

# Copy app
COPY .bin/linux-${TARGETARCH}/traefik-forward-auth /traefik-forward-auth

# Expose ports
EXPOSE 4181 2112

# Start app
ENTRYPOINT ["/traefik-forward-auth"]

# Healthcheck command
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 CMD ["/traefik-forward-auth", "healthcheck"]
