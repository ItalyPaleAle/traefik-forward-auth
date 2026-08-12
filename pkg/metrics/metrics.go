package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/italypaleale/go-kit/observability"
	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

const prefix = "tfa"

type TFAMetrics struct {
	serverRequests  api.Float64Histogram
	authentications api.Int64Counter
}

func NewTFAMetrics(ctx context.Context) (m *TFAMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()
	m = &TFAMetrics{}

	meter, shutdownFn, err := observability.InitMetrics(ctx, observability.InitMetricsOpts{
		Config:  cfg,
		AppName: buildinfo.AppName,
		Prefix:  prefix,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init metrics: %w", err)
	}

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

	return m, shutdownFn, nil
}

// RecordServerRequest records a request processed by the server
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
