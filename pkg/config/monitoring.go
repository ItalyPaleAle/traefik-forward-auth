package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	logExporterOltpGrpc "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	logExporterOltpHttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	metricExporterOltpGrpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metricExporterOltpHttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	traceExporterOltpGrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	traceExporterOltpHttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	logSdk "go.opentelemetry.io/otel/sdk/log"
	metricSdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	traceSdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
)

// GetOtelResource returns the OpenTelemetry Resource object
func (c *Config) GetOtelResource(name string) *resource.Resource {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(name),
		semconv.ServiceInstanceIDKey.String(c.GetInstanceID()),
		semconv.ServiceVersionKey.String(buildinfo.BuildId),
	)
}

// GetLogsExporter returns the OpenTelemetry log Exporter if configured
// Note that since the logger isn't configured when this method is invoked, we don't log anything, but return a function that can emit the log
func (c *ConfigLogs) GetLogsExporter(ctx context.Context) (exp logSdk.Exporter, logFn func(log *slog.Logger), err error) {
	switch {
	case strings.HasPrefix(c.OtelCollectorEndpoint, "http://") || strings.HasPrefix(c.OtelCollectorEndpoint, "https://"):
		// Configure OTel exporter using HTTP and the endpoint from the configuration
		logFn = logsExporterLogFnWrapper("Exporting logs to OpenTelemetry collector using HTTP", slog.String("endpoint", c.OtelCollectorEndpoint))
		exp, err = logExporterOltpHttp.New(ctx, logExporterOltpHttp.WithEndpointURL(c.OtelCollectorEndpoint))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OpenTelemetry HTTP log exporter: %w", err)
		}
		return exp, logFn, nil

	case strings.HasPrefix(c.OtelCollectorEndpoint, "grpc://") || strings.HasPrefix(c.OtelCollectorEndpoint, "grpcs://"):
		// Configure OTel exporter using gRPC and the endpoint from the configuration
		logFn = logsExporterLogFnWrapper("Exporting logs to OpenTelemetry collector using gRPC", slog.String("endpoint", c.OtelCollectorEndpoint))
		// Replace "grpc(s)" with "http(s)"
		endpoint := "http" + c.OtelCollectorEndpoint[4:]
		exp, err = logExporterOltpGrpc.New(ctx, logExporterOltpGrpc.WithEndpointURL(endpoint))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OpenTelemetry gRPC log exporter: %w", err)
		}
		return exp, logFn, nil

	case os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") != "":
		// Configure OTel exporter using the standard environmental variable OTEL_EXPORTER_OTLP_LOGS_ENDPOINT
		// Optionally, OTEL_EXPORTER_OTLP_PROTOCOL can be used to switch to gRPC
		return getOtelLogExporterFromEnv(ctx, os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"))

	case os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "":
		// The environmental variable OTEL_EXPORTER_OTLP_ENDPOINT is another standard one, and we append "/v1/logs" if using HTTP
		endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		otelProtocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		// otelProtocol can be "grpc" or "http/protobuf" (possibly other HTTP-based protocols in the future)
		// If protocol is empty, the default is "http/protobuf"
		if otelProtocol == "" || strings.HasPrefix(otelProtocol, "http") {
			if strings.HasSuffix(endpoint, "/") {
				endpoint += "v1/logs"
			} else {
				endpoint += "/v1/logs"
			}
		}
		return getOtelLogExporterFromEnv(ctx, endpoint, otelProtocol)

	default:
		// No log exporter configured
		return nil, nil, nil
	}
}

// GetMetricsExporter returns the metrics exporter for the OpenTelemetry collector
func (c *ConfigMetrics) GetMetricsExporter(ctx context.Context, log *slog.Logger) (exp metricSdk.Exporter, err error) {
	switch {
	case strings.HasPrefix(c.OtelCollectorEndpoint, "http://") || strings.HasPrefix(c.OtelCollectorEndpoint, "https://"):
		// Configure OTel exporter using HTTP and the endpoint from the configuration
		log.DebugContext(ctx, "Exporting metrics to OpenTelemetry collector using HTTP", slog.String("endpoint", c.OtelCollectorEndpoint))
		exp, err = metricExporterOltpHttp.New(ctx, metricExporterOltpHttp.WithEndpointURL(c.OtelCollectorEndpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry HTTP metric exporter: %w", err)
		}
		return exp, nil

	case strings.HasPrefix(c.OtelCollectorEndpoint, "grpc://") || strings.HasPrefix(c.OtelCollectorEndpoint, "grpcs://"):
		// Configure OTel exporter using gRPC and the endpoint from the configuration
		log.DebugContext(ctx, "Exporting metrics to OpenTelemetry collector using gRPC", slog.String("endpoint", c.OtelCollectorEndpoint))
		// Replace "grpc(s)" with "http(s)"
		endpoint := "http" + c.OtelCollectorEndpoint[4:]
		exp, err = metricExporterOltpGrpc.New(ctx, metricExporterOltpGrpc.WithEndpointURL(endpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry gRPC metric exporter: %w", err)
		}
		return exp, nil

	case os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != "":
		// Configure OTel exporter using the standard environmental variable OTEL_EXPORTER_OTLP_METRICS_ENDPOINT
		// Optionally, OTEL_EXPORTER_OTLP_PROTOCOL can be used to switch to gRPC
		return getOtelMetricExporterFromEnv(ctx, os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"), log)

	case os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "":
		// The environmental variable OTEL_EXPORTER_OTLP_ENDPOINT is another standard one, and we append "/v1/metrics" if using HTTP
		endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		otelProtocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		// otelProtocol can be "grpc" or "http/protobuf" (possibly other HTTP-based protocols in the future)
		// If protocol is empty, the default is "http/protobuf"
		if otelProtocol == "" || strings.HasPrefix(otelProtocol, "http") {
			if strings.HasSuffix(endpoint, "/") {
				endpoint += "v1/metrics"
			} else {
				endpoint += "/v1/metrics"
			}
		}
		return getOtelMetricExporterFromEnv(ctx, endpoint, otelProtocol, log)

	default:
		// This disables metrics
		return nil, nil
	}
}

// GetTraceExporter returns the trace exporter, either for the OpenTelemetry Collector or Zipkin
func (c *ConfigTracing) GetTraceExporter(ctx context.Context, log *slog.Logger) (exp traceSdk.SpanExporter, err error) {
	switch {
	case strings.HasPrefix(c.OtelCollectorEndpoint, "http://") || strings.HasPrefix(c.OtelCollectorEndpoint, "https://"):
		// Configure OTel exporter using HTTP and the endpoint from the configuration
		log.DebugContext(ctx, "Exporting traces to OpenTelemetry collector using HTTP", slog.String("endpoint", c.OtelCollectorEndpoint))
		exp, err = traceExporterOltpHttp.New(ctx, traceExporterOltpHttp.WithEndpointURL(c.OtelCollectorEndpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry HTTP trace exporter: %w", err)
		}
		return exp, nil

	case strings.HasPrefix(c.OtelCollectorEndpoint, "grpc://") || strings.HasPrefix(c.OtelCollectorEndpoint, "grpcs://"):
		// Configure OTel exporter using gRPC and the endpoint from the configuration
		log.DebugContext(ctx, "Exporting traces to OpenTelemetry collector using gRPC", slog.String("endpoint", c.OtelCollectorEndpoint))
		// Replace "grpc(s)" with "http(s)"
		endpoint := "http" + c.OtelCollectorEndpoint[4:]
		exp, err = traceExporterOltpGrpc.New(ctx, traceExporterOltpGrpc.WithEndpointURL(endpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry gRPC trace exporter: %w", err)
		}
		return exp, nil

	case os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "":
		// Configure OTel exporter using the standard environmental variable OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
		// Optionally, OTEL_EXPORTER_OTLP_PROTOCOL can be used to switch to gRPC
		return getOtelTraceExporterFromEnv(ctx, os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"), os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"), log)

	case os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "":
		// The environmental variable OTEL_EXPORTER_OTLP_ENDPOINT is another standard one, and we append "/v1/traces" if using HTTP
		endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		otelProtocol := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
		// otelProtocol can be "grpc" or "http/protobuf" (possibly other HTTP-based protocols in the future)
		// If protocol is empty, the default is "http/protobuf"
		if otelProtocol == "" || strings.HasPrefix(otelProtocol, "http") {
			if strings.HasSuffix(endpoint, "/") {
				endpoint += "v1/traces"
			} else {
				endpoint += "/v1/traces"
			}
		}
		return getOtelTraceExporterFromEnv(ctx, endpoint, otelProtocol, log)

	default:
		// This disables tracing
		return nil, nil
	}
}

func getOtelTraceExporterFromEnv(ctx context.Context, endpoint string, otelProtocol string, log *slog.Logger) (exp traceSdk.SpanExporter, err error) {
	// otelProtocol can be "http/protobuf", the default, or "grpc"
	switch otelProtocol {
	case "grpc":
		log.DebugContext(ctx, "Exporting traces to OpenTelemetry collector using gRPC", slog.String("endpoint", endpoint))
		exp, err = traceExporterOltpGrpc.New(ctx, traceExporterOltpGrpc.WithEndpointURL(endpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry gRPC trace exporter: %w", err)
		}
		return exp, nil
	case "http/protobuf", "":
		log.DebugContext(ctx, "Exporting traces to OpenTelemetry collector using HTTP", slog.String("endpoint", endpoint))
		exp, err = traceExporterOltpHttp.New(ctx, traceExporterOltpHttp.WithEndpointURL(endpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry HTTP trace exporter: %w", err)
		}
		return exp, nil
	default:
		return nil, fmt.Errorf("unsupported OpenTelemetry protocol: %s", otelProtocol)
	}
}

func getOtelLogExporterFromEnv(ctx context.Context, endpoint string, otelProtocol string) (exp logSdk.Exporter, logFn func(log *slog.Logger), err error) {
	// otelProtocol can be "http/protobuf", the default, or "grpc"
	switch otelProtocol {
	case "grpc":
		logFn = logsExporterLogFnWrapper("Exporting logs to OpenTelemetry collector using gRPC", slog.String("endpoint", endpoint))
		exp, err = logExporterOltpGrpc.New(ctx, logExporterOltpGrpc.WithEndpointURL(endpoint))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OpenTelemetry gRPC log exporter: %w", err)
		}
		return exp, logFn, nil
	case "http/protobuf", "":
		logFn = logsExporterLogFnWrapper("Exporting logs to OpenTelemetry collector using HTTP", slog.String("endpoint", endpoint))
		exp, err = logExporterOltpHttp.New(ctx, logExporterOltpHttp.WithEndpointURL(endpoint))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OpenTelemetry HTTP log exporter: %w", err)
		}
		return exp, logFn, nil
	default:
		return nil, nil, fmt.Errorf("unsupported OpenTelemetry protocol: %s", otelProtocol)
	}
}

func getOtelMetricExporterFromEnv(ctx context.Context, endpoint string, otelProtocol string, log *slog.Logger) (exp metricSdk.Exporter, err error) {
	// otelProtocol can be "http/protobuf", the default, or "grpc"
	switch otelProtocol {
	case "grpc":
		log.DebugContext(ctx, "Exporting metrics to OpenTelemetry collector using gRPC", slog.String("endpoint", endpoint))
		exp, err = metricExporterOltpGrpc.New(ctx, metricExporterOltpGrpc.WithEndpointURL(endpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry gRPC metric exporter: %w", err)
		}
		return exp, nil
	case "http/protobuf", "":
		log.DebugContext(ctx, "Exporting metrics to OpenTelemetry collector using HTTP", slog.String("endpoint", endpoint))
		exp, err = metricExporterOltpHttp.New(ctx, metricExporterOltpHttp.WithEndpointURL(endpoint))
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry HTTP metric exporter: %w", err)
		}
		return exp, nil
	default:
		return nil, fmt.Errorf("unsupported OpenTelemetry protocol: %s", otelProtocol)
	}
}

func logsExporterLogFnWrapper(msg string, args ...any) func(log *slog.Logger) {
	return func(log *slog.Logger) {
		log.DebugContext(context.Background(), msg, args...)
	}
}
