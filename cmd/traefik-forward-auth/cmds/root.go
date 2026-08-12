package cmds

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	configkit "github.com/italypaleale/go-kit/config"
	"github.com/italypaleale/go-kit/observability"
	"github.com/italypaleale/go-kit/servicerunner"
	"github.com/italypaleale/go-kit/signals"
	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/spf13/cobra"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	tfametrics "github.com/italypaleale/traefik-forward-auth/pkg/metrics"
	"github.com/italypaleale/traefik-forward-auth/pkg/server"
)

const (
	configDirName = "traefik-forward-auth"
	configEnvVar  = "TFA_CONFIG"
)

var rootCmd = &cobra.Command{
	Use:   "traefik-forward-auth",
	Short: "A forward-auth service that provides authentication and SSO for the Traefik reverse proxy",
	Long:  "The root command starts the traefik-forward-auth service",
	Run: func(_ *cobra.Command, _ []string) {
		runService()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func runService() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init a logger used for initialization only, to report initialization errors
	initLogger := slog.Default().
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// Load config
	cfg := config.Get()
	err := configkit.LoadConfig(cfg, configkit.LoadConfigOpts{
		EnvVar:  configEnvVar,
		DirName: configDirName,
	})
	if err != nil {
		configErr, ok := errors.AsType[*configkit.ConfigError](err)
		if ok {
			configErr.LogFatal(initLogger)
		} else {
			slogkit.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}

	// List of services to run
	services := make([]servicerunner.Service, 0, 1)

	shutdowns := &shutdownManager{
		fns: make([]servicerunner.Service, 0, 3),
	}

	// Get a context that is canceled when the application receives a termination signal
	ctx := signals.SignalContext(context.Background())

	// Get the logger and set it as default
	log, loggerShutdownFn, err := observability.InitLogs(ctx, observability.InitLogsOpts{
		Config:     cfg,
		Level:      cfg.Logs.Level,
		JSON:       cfg.Logs.JSON,
		AppName:    buildinfo.AppName,
		AppVersion: buildinfo.AppVersion,
	})
	if err != nil {
		slogkit.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	shutdowns.Add(loggerShutdownFn)

	// Validate the configuration
	err = cfg.Process(log)
	if err != nil {
		shutdowns.Run(ctx, log)
		slogkit.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting traefik-forward-auth", slog.String("build", buildinfo.BuildDescription))

	// Init metrics
	metrics, metricsShutdownFn, err := tfametrics.NewTFAMetrics(ctx)
	if err != nil {
		shutdowns.Run(ctx, log)
		slogkit.FatalError(log, "Failed to init metrics", err)
		return
	}
	shutdowns.Add(metricsShutdownFn)

	// Get the portals
	portals, err := server.GetPortalsConfig(ctx, cfg)
	if err != nil {
		shutdowns.Run(ctx, log)
		slogkit.FatalError(log, "Failed to get portals configuration", err)
		return
	}

	// Init tracing
	traceProvider, tracerShutdownFn, err := observability.InitTraces(ctx, observability.InitTracesOpts{
		Config:  cfg,
		AppName: buildinfo.AppName,
	})
	if err != nil {
		shutdowns.Run(ctx, log)
		slogkit.FatalError(log, "Failed to init tracing", err)
		return
	}
	shutdowns.Add(tracerShutdownFn)

	// Create the Server object
	srv, err := server.NewServer(server.NewServerOpts{
		Portals:       portals,
		Metrics:       metrics,
		TraceProvider: traceProvider,
	})
	if err != nil {
		shutdowns.Run(ctx, log)
		slogkit.FatalError(log, "Cannot initialize the server", err)
		return
	}
	services = append(services, srv.Run)

	// Run all services
	// This call blocks until the context is canceled
	err = servicerunner.
		NewServiceRunner(services...).
		Run(ctx)
	if err != nil {
		shutdowns.Run(ctx, log)
		slogkit.FatalError(log, "Failed to run service", err)
		return
	}

	shutdowns.Run(ctx, log)
}

type shutdownManager struct {
	fns []servicerunner.Service
}

func (s *shutdownManager) Add(fn servicerunner.Service) {
	if fn == nil {
		return
	}
	s.fns = append(s.fns, fn)
}

func (s *shutdownManager) Run(ctx context.Context, log *slog.Logger) {
	// Use a context without cancellation because the context has been canceled already
	shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer shutdownCancel()
	sr := servicerunner.NewServiceRunner(s.fns...)
	sr.WaitAll = true
	err := sr.Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
