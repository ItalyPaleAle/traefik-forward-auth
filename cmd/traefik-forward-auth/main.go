package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/exporters/autoexport"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	tfametrics "github.com/italypaleale/traefik-forward-auth/pkg/metrics"
	"github.com/italypaleale/traefik-forward-auth/pkg/server"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/signals"
)

func main() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init a logger used for initialization only, to report initialization errors
	initLogger := slog.Default().
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// Load config
	err := loadConfig()
	if err != nil {
		var lce *loadConfigError
		if errors.As(err, &lce) {
			lce.LogFatal(initLogger)
		} else {
			utils.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}
	conf := config.Get()

	// Shutdown functions
	shutdownFns := make([]utils.Service, 0, 3)

	// Get the logger and set it in the context
	log, loggerShutdownFn, err := getLogger(context.Background(), conf)
	if err != nil {
		utils.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	if loggerShutdownFn != nil {
		shutdownFns = append(shutdownFns, loggerShutdownFn)
	}

	// Validate the configuration
	err = conf.Process(log)
	if err != nil {
		utils.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting traefik-forward-auth", "build", buildinfo.BuildDescription)

	// Get a context that is canceled when the application receives a termination signal
	// We store the logger in the context too
	ctx := utils.LogToContext(context.Background(), log)
	ctx = signals.SignalContext(ctx)

	// Init metrics
	metrics, metricsShutdownFn, err := tfametrics.NewTFAMetrics(ctx, log)
	if err != nil {
		utils.FatalError(log, "Failed to init metrics", err)
		return
	}
	if metricsShutdownFn != nil {
		shutdownFns = append(shutdownFns, metricsShutdownFn)
	}

	// Get the portals
	portals, err := server.GetPortalsConfig(ctx, conf)
	if err != nil {
		utils.FatalError(log, "Failed to get portals configuration", err)
		return
	}

	// Get the trace exporter
	// If the env var OTEL_TRACES_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_TRACES_EXPORTER") == "" {
		os.Setenv("OTEL_TRACES_EXPORTER", "none")
	}
	traceExporter, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		utils.FatalError(log, "Failed to init trace exporter", err)
		return
	}
	shutdownFns = append(shutdownFns, traceExporter.Shutdown)

	// Create the Server object
	srv, err := server.NewServer(server.NewServerOpts{
		Log:           log,
		Portals:       portals,
		Metrics:       metrics,
		TraceExporter: traceExporter,
	})
	if err != nil {
		utils.FatalError(log, "Cannot initialize the server", err)
		return
	}

	// Run the service
	err = utils.
		NewServiceRunner(srv.Run).
		Run(ctx)
	if err != nil {
		utils.FatalError(log, "Failed to run service", err)
		return
	}

	// Invoke all shutdown functions
	// We give these a timeout of 5s
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = utils.
		NewServiceRunner(shutdownFns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
