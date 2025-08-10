FROM gcr.io/distroless/static-debian12:nonroot

# Build args
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH

# Copy app
COPY .bin/linux-${TARGETARCH}/traefik-forward-auth /traefik-forward-auth

# Environmental variables
ENV TFA_PORT=4181 TFA_BIND=0.0.0.0 TFA_METRICSPORT=2112

# Expose ports
EXPOSE 4181 2112

# Start app
ENTRYPOINT ["/traefik-forward-auth"]
