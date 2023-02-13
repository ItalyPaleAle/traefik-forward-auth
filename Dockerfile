FROM golang:1.19 AS builder

# Setup
WORKDIR /workspace

# Add libraries
RUN apk add --no-cache git

# Copy & build
ENV CGO_ENABLED=0
ADD . /workspace/
RUN go build -o /traefik-forward-auth github.com/thomseddon/traefik-forward-auth/cmd

# Copy into distroless container
FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=builder /traefik-forward-auth /
ENTRYPOINT ["/traefik-forward-auth"]
