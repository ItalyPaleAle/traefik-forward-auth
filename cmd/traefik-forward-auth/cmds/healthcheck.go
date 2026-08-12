package cmds

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	configkit "github.com/italypaleale/go-kit/config"
	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/spf13/cobra"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

// Adapted from https://github.com/pocket-id/pocket-id/blob/v1.11.2/backend/internal/cmds/healthcheck.go
// Copyright (c) 2024, Elias Schneider
// License: BSD (https://github.com/pocket-id/pocket-id/blob/v1.11.2/LICENSE)

type healthcheckFlags struct {
	Endpoint string
	Verbose  bool
}

func init() {
	var flags healthcheckFlags

	healthcheckCmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Performs a healthcheck of a running traefik-forward-auth instance",
		Run: func(cmd *cobra.Command, args []string) {
			initLogger := slog.Default().
				With(slog.String("app", buildinfo.AppName)).
				With(slog.String("version", buildinfo.AppVersion))

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

			client := http.DefaultClient

			// Set the default endpoint
			if flags.Endpoint == "" {
				if cfg.Server.HasTLS() {
					// Disable TLS certificate validation for healthchecks
					transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert
					if transport.TLSClientConfig == nil {
						transport.TLSClientConfig = &tls.Config{
							MinVersion: tls.VersionTLS12,
						}
					}
					transport.TLSClientConfig.InsecureSkipVerify = true
					client.Transport = transport

					flags.Endpoint = "https://localhost:" + strconv.Itoa(cfg.Server.Port)
				} else {
					flags.Endpoint = "http://localhost:" + strconv.Itoa(cfg.Server.Port)
				}
			}

			start := time.Now()

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			url := flags.Endpoint + "/healthz"
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				slog.ErrorContext(ctx,
					"Failed to create request object",
					"error", err,
					"url", url,
					"ms", time.Since(start).Milliseconds(),
				)
				os.Exit(1)
			}

			res, err := client.Do(req)
			if err != nil {
				slog.ErrorContext(ctx,
					"Failed to perform request",
					"error", err,
					"url", url,
					"ms", time.Since(start).Milliseconds(),
				)
				os.Exit(1)
			}
			defer res.Body.Close()

			if res.StatusCode < 200 || res.StatusCode >= 300 {
				slog.ErrorContext(ctx,
					"Healthcheck failed",
					"status", res.StatusCode,
					"url", url,
					"ms", time.Since(start).Milliseconds(),
				)
				os.Exit(1)
			}

			if flags.Verbose {
				slog.InfoContext(ctx,
					"Healthcheck succeeded",
					"status", res.StatusCode,
					"url", url,
					"ms", time.Since(start).Milliseconds(),
				)
			}
		},
	}

	healthcheckCmd.Flags().StringVarP(&flags.Endpoint, "endpoint", "e", "", "Endpoint for traefik-forward-auth")
	healthcheckCmd.Flags().BoolVarP(&flags.Verbose, "verbose", "v", false, "Enable verbose mode")

	rootCmd.AddCommand(healthcheckCmd)
}
