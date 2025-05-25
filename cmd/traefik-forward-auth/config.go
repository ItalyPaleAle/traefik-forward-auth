package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cast"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	logGlobal "go.opentelemetry.io/otel/log/global"
	logSdk "go.opentelemetry.io/otel/sdk/log"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/configloader"
)

const configEnvPrefix = "TFA_"

func loadConfig() error {
	// Get the path to the config.yaml
	// First, try with the TFA_CONFIG env var
	configFile := os.Getenv(configEnvPrefix + "CONFIG")
	if configFile != "" {
		exists, _ := utils.FileExists(configFile)
		if !exists {
			return newLoadConfigError("Environmental variable "+configEnvPrefix+"CONFIG points to a file that does not exist", "Error loading config file")
		}
	} else {
		// Look in the default paths
		configFile = findConfigFile("config.yaml", ".", "~/.traefik-forward-auth", "/etc/traefik-forward-auth")
		if configFile == "" {
			// Ok, if you really, really want to use ".yml"....
			configFile = findConfigFile("config.yml", ".", "~/.traefik-forward-auth", "/etc/traefik-forward-auth")
		}
	}

	// Load the configuration
	// Note that configFile can be empty
	cfg := config.Get()
	err := configloader.Load(cfg, configFile, configloader.LoadOptions{
		EnvPrefix:                configEnvPrefix,
		IgnoreZeroValuesInConfig: true,
	})
	if err != nil {
		return newLoadConfigError(err, "Error loading config file")
	}
	cfg.SetLoadedConfigPath(configFile)

	return nil
}

func getLogger(ctx context.Context, cfg *config.Config) (log *slog.Logger, shutdownFn func(ctx context.Context) error, err error) {
	// Get the level
	level, err := getLogLevel(cfg)
	if err != nil {
		return nil, nil, err
	}

	// Create the handler
	var handler slog.Handler
	switch {
	case cfg.Logs.JSON:
		// Log as JSON if configured
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	case isatty.IsTerminal(os.Stdout.Fd()):
		// Enable colors if we have a TTY
		handler = tint.NewHandler(os.Stdout, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.StampMilli,
		})
	default:
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	}

	// Create a handler that sends logs to OTel too
	// We wrap the handler in a "fanout" handler that sends logs to both
	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	// If the env var OTEL_LOGS_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_LOGS_EXPORTER") == "" {
		os.Setenv("OTEL_LOGS_EXPORTER", "none")
	}
	exp, err := autoexport.NewLogExporter(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize OpenTelemetry log exporter: %w", err)
	}

	// Create the logger provider
	provider := logSdk.NewLoggerProvider(
		logSdk.WithProcessor(
			logSdk.NewBatchProcessor(exp),
		),
		logSdk.WithResource(resource),
	)

	// Set the logger provider globally
	logGlobal.SetLoggerProvider(provider)

	// Wrap the handler in a "fanout" one
	handler = utils.LogFanoutHandler{
		handler,
		otelslog.NewHandler(buildinfo.AppName, otelslog.WithLoggerProvider(provider)),
	}

	// Return a function to invoke during shutdown
	shutdownFn = provider.Shutdown

	log = slog.New(handler).
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	return log, shutdownFn, nil
}

func findConfigFile(fileName string, searchPaths ...string) string {
	for _, path := range searchPaths {
		if path == "" {
			continue
		}

		p, _ := homedir.Expand(path)
		if p != "" {
			path = p
		}

		search := filepath.Join(path, fileName)
		exists, _ := utils.FileExists(search)
		if exists {
			return search
		}
	}

	return ""
}

// Processes the configuration
func processConfig(log *slog.Logger, cfg *config.Config) (err error) {
	// Check required variables
	err = cfg.Validate(log)
	if err != nil {
		return err
	}

	// Ensures the token signing key is present
	err = cfg.SetTokenSigningKey(log)
	if err != nil {
		return err
	}

	return nil
}

func getLogLevel(cfg *config.Config) (slog.Level, error) {
	switch strings.ToLower(cfg.Logs.Level) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info": // Also default log level
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, newLoadConfigError("Invalid value for 'logLevel'", "Invalid configuration")
	}
}

// Error returned by loadConfig
type loadConfigError struct {
	err string
	msg string
}

// newLoadConfigError returns a new loadConfigError.
// The err argument can be a string or an error.
func newLoadConfigError(err any, msg string) *loadConfigError {
	return &loadConfigError{
		err: cast.ToString(err),
		msg: msg,
	}
}

// Error implements the error interface
func (e loadConfigError) Error() string {
	return e.err + ": " + e.msg
}

// LogFatal causes a fatal log
func (e loadConfigError) LogFatal(log *slog.Logger) {
	utils.FatalError(log, e.msg, errors.New(e.err))
}
