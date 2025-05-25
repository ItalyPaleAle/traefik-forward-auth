package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
)

const prefix = "tfa"

type TFAMetrics struct {
	serverRequests  api.Float64Histogram
	authentications api.Int64Counter

	prometheusRegisterer *prom.Registry
}

func NewTFAMetrics(ctx context.Context, log *slog.Logger) (m *TFAMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()
	m = &TFAMetrics{}

	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	// Get the metric reader
	// If the env var OTEL_METRICS_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_METRICS_EXPORTER") == "" {
		os.Setenv("OTEL_METRICS_EXPORTER", "none")
	}
	mr, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize OpenTelemetry metric reader: %w", err)
	}

	mp := metric.NewMeterProvider(
		metric.WithResource(resource),
		metric.WithReader(mr),
	)
	meter := mp.Meter(prefix)

	m.serverRequests, err = meter.Float64Histogram(
		prefix+"_server_requests",
		api.WithUnit("ms"),
		api.WithDescription("Requests processed by the server and duration in milliseconds"),
		api.WithExplicitBucketBoundaries(1, 2.5, 5, 10, 25, 50, 100, 250, 500),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create "+prefix+"_server_requests meter: %w", err)
	}

	m.authentications, err = meter.Int64Counter(
		prefix+"_authentications",
		api.WithDescription("The number of authentications"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create "+prefix+"_authentications meter: %w", err)
	}

	return m, mp.Shutdown, nil
}

// RecordServerRequest records a request processed by the server.
func (m *TFAMetrics) RecordServerRequest(route string, status int, duration time.Duration) {
	if m == nil {
		return
	}

	m.serverRequests.Record(
		context.Background(),
		float64(duration.Microseconds())/1000,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "status", Value: attribute.IntValue(status)},
				attribute.KeyValue{Key: "route", Value: attribute.StringValue(route)},
			),
		),
	)
}

func (m *TFAMetrics) RecordAuthentication(success bool) {
	if m == nil {
		return
	}

	m.authentications.Add(
		context.Background(),
		1,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "success", Value: attribute.BoolValue(success)},
			),
		),
	)
}
