# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum first (for caching dependencies)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary for the target architecture
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o traefik-forward-auth ./cmd/traefik-forward-auth

# Stage 2: Create minimal image with distroless
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH

# Copy binary from builder stage
COPY --from=builder /app/traefik-forward-auth /traefik-forward-auth

# Environment variables
ENV TFA_PORT=4181 TFA_BIND=0.0.0.0 TFA_METRICSPORT=2112

# Expose ports
EXPOSE 4181 2112

# Run the binary
ENTRYPOINT ["/traefik-forward-auth"]