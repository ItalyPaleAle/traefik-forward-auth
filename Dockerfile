FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
# TARGETARCH is set automatically when using BuildKit
ARG TARGETARCH
COPY .bin/linux-${TARGETARCH}/traefik-forward-auth /bin/traefik-forward-auth
EXPOSE 4181 2112
ENTRYPOINT ["/bin/traefik-forward-auth"]
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 CMD ["/bin/traefik-forward-auth", "healthcheck"]
