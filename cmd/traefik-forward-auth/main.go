package main

import (
	"context"
	"errors"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"

	"github.com/italypaleale/traefik-forward-auth/pkg/buildinfo"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/server"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/signals"
)

func main() {
	// Set Gin to Release mode
	gin.SetMode(gin.ReleaseMode)

	// Init the logger and set it in the context
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", buildinfo.AppName).
		Str("version", buildinfo.AppVersion).
		Logger()
	ctx := log.WithContext(context.Background())

	log.Info().
		Str("build", buildinfo.BuildDescription).
		Msg("Starting Traefik Forward Auth")

	// Get a context that is canceled when the application receives a termination signal
	ctx = signals.SignalContext(ctx)

	// Load config
	err := loadConfig(&log)
	if err != nil {
		var lce *loadConfigError
		if errors.As(err, &lce) {
			lce.LogFatal(&log)
		} else {
			log.Fatal().Err(err).Msg("Failed to load configuration")
			return
		}
	}
	conf := config.Get()

	// Get the auth provider
	auth, err := conf.GetAuthProvider()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get auth provider")
		return
	}

	// Create the Server object
	srv, err := server.NewServer(server.NewServerOpts{
		Log:  &log,
		Auth: auth,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot initialize the server")
		return
	}

	// Run the service
	runner := utils.NewServiceRunner(srv.Run)
	err = runner.Run(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to run service")
		return
	}
}
