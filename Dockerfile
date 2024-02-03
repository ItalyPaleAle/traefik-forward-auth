FROM golang:1.21 AS builder

ARG BUILD_LDFLAGS

WORKDIR /workspace
ENV CGO_ENABLED=0
ADD go.mod go.sum /workspace/
RUN go mod download
ADD . /workspace/
RUN go build -o /traefik-forward-auth -trimpath -ldflags "${BUILD_LDFLAGS}" ./cmd/traefik-forward-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /traefik-forward-auth /
ENTRYPOINT ["/traefik-forward-auth"]
