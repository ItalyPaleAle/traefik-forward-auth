package cmds

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/go-kit/servicerunner"
	"github.com/italypaleale/go-kit/signals"
	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/contrib/exporters/autoexport"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	tfametrics "github.com/italypaleale/traefik-forward-auth/pkg/metrics"
	"github.com/italypaleale/traefik-forward-auth/pkg/server"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

var rootCmd = &cobra.Command{
	Use:   "traefik-forward-auth",
	Short: "A simple service that provides authentication and SSO for the Traefik reverse proxy",
	Long:  "The root command starts the traefik-forward-auth service",
	Run: func(cmd *cobra.Command, args []string) {
		runService(cmd.Context())
	},
}

func Execute() {
	// Get a context that is canceled when the application is stopping
	ctx := signals.SignalContext(context.Background())

	// Set the default slog to have the app name and version
	slog.SetDefault(
		slog.Default().
			With(slog.String("app", buildinfo.AppName)).
			With(slog.String("version", buildinfo.AppVersion)),
	)

	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		os.Exit(1)
	}
}

func runService(ctx context.Context) {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// We need an initialization logger until we get the final one with all required config
	initLogger := slog.Default()

	// Load config
	loadConfigOrFatal(initLogger)
	conf := config.Get()

	// Shutdown functions
	shutdownFns := make([]servicerunner.Service, 0, 3)

	// Get the logger and set it in the context
	log, loggerShutdownFn, err := getLogger(ctx, conf)
	if err != nil {
		slogkit.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	if loggerShutdownFn != nil {
		shutdownFns = append(shutdownFns, loggerShutdownFn)
	}

	// Validate the configuration
	err = conf.Process(log)
	if err != nil {
		slogkit.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting traefik-forward-auth", "build", buildinfo.BuildDescription)

	// Store the logger in the context too
	ctx = utils.LogToContext(ctx, log)

	// Init metrics
	metrics, metricsShutdownFn, err := tfametrics.NewTFAMetrics(ctx, log)
	if err != nil {
		slogkit.FatalError(log, "Failed to init metrics", err)
		return
	}
	if metricsShutdownFn != nil {
		shutdownFns = append(shutdownFns, metricsShutdownFn)
	}

	// Get the portals
	portals, err := server.GetPortalsConfig(ctx, conf)
	if err != nil {
		slogkit.FatalError(log, "Failed to get portals configuration", err)
		return
	}

	// Get the trace exporter
	// If the env var OTEL_TRACES_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_TRACES_EXPORTER") == "" {
		os.Setenv("OTEL_TRACES_EXPORTER", "none")
	}
	traceExporter, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		slogkit.FatalError(log, "Failed to init trace exporter", err)
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
		slogkit.FatalError(log, "Cannot initialize the server", err)
		return
	}

	// Run the service
	err = servicerunner.
		NewServiceRunner(srv.Run).
		Run(ctx)
	if err != nil {
		slogkit.FatalError(log, "Failed to run service", err)
		return
	}

	// Invoke all shutdown functions
	// We give these a timeout of 5s
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = servicerunner.
		NewServiceRunner(shutdownFns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
