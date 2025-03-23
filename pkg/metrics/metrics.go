package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	api "go.opentelemetry.io/otel/metric"
	metricSdk "go.opentelemetry.io/otel/sdk/metric"
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
	providerOpts := make([]metricSdk.Option, 0, 2)

	// If we have an OpenTelemetry Collector for metrics, add that
	exporter, err := cfg.Metrics.GetMetricsExporter(ctx, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init metrics: %w", err)
	}
	if exporter != nil {
		providerOpts = append(providerOpts,
			metricSdk.WithReader(metricSdk.NewPeriodicReader(exporter)),
			metricSdk.WithResource(cfg.GetOtelResource(buildinfo.AppName)),
		)
	}

	// If the metrics server is enabled, create a Prometheus exporter
	if cfg.Metrics.ServerEnabled {
		m.prometheusRegisterer = prom.NewRegistry()
		promExporter, err := prometheus.New(
			prometheus.WithRegisterer(m.prometheusRegisterer),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
		}
		providerOpts = append(providerOpts, metricSdk.WithReader(promExporter))
	}

	// If there's no exporter configured, stop here
	if len(providerOpts) == 0 {
		return nil, nil, nil
	}

	provider := metricSdk.NewMeterProvider(providerOpts...)
	meter := provider.Meter(prefix)

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

	return m, provider.Shutdown, nil
}

func (m *TFAMetrics) HTTPHandler() http.Handler {
	if m.prometheusRegisterer == nil {
		// This indicates a development-time error
		panic("called HTTPHandler when metrics server is disabled")
	}

	return promhttp.InstrumentMetricHandler(
		m.prometheusRegisterer,
		promhttp.HandlerFor(
			prom.Gatherers{
				m.prometheusRegisterer,
				prom.DefaultGatherer,
			},
			promhttp.HandlerOpts{},
		),
	)
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
