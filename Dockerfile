FROM golang:1.21 AS builder

WORKDIR /workspace
ENV CGO_ENABLED=0
ADD go.mod go.sum /workspace/
RUN go mod download -v
ADD . /workspace/
RUN go build -o /traefik-forward-auth ./cmd/traefik-forward-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /traefik-forward-auth /
ENTRYPOINT ["/traefik-forward-auth"]
