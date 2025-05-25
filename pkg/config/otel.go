package config

import (
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.32.0"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
)

// GetOtelResource returns the OpenTelemetry Resource object
func (c *Config) GetOtelResource(name string) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName(name),
			semconv.ServiceInstanceID(c.GetInstanceID()),
			semconv.ServiceVersion(buildinfo.BuildId),
		),
	)
}
