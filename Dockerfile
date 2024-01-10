FROM golang:1.21 AS builder

# Setup
WORKDIR /workspace

# Copy & build
ENV CGO_ENABLED=0
ADD . /workspace/
RUN go build -o /traefik-forward-auth ./cmd/traefik-forward-auth

# Copy into distroless container
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /traefik-forward-auth /
ENTRYPOINT ["/traefik-forward-auth"]
