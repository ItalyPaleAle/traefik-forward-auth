package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/configloader"
)

const configEnvPrefix = "TFA_"

func loadConfig(log *zerolog.Logger) error {
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
	err := configloader.Load(cfg, configloader.LoadOptions{
		FilePath:                 configFile,
		IgnoreZeroValuesInConfig: true,
	})
	if err != nil {
		return newLoadConfigError(err, "Error loading config file")
	}
	cfg.SetLoadedConfigPath(configFile)

	// Process the configuration
	return processConfig(log, cfg)
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
func processConfig(log *zerolog.Logger, cfg *config.Config) (err error) {
	// Log level
	err = setLogLevel(cfg)
	if err != nil {
		return err
	}

	// Check required variables
	err = cfg.Validate(log)
	if err != nil {
		return err
	}

	return nil
}

// Sets the log level based on the configuration
func setLogLevel(cfg *config.Config) error {
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "", "info": // Also default log level
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		return newLoadConfigError("Invalid value for 'logLevel'", "Invalid configuration")
	}
	return nil
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
		err: fmt.Sprintf("%v", err),
		msg: msg,
	}
}

// Error implements the error interface
func (e loadConfigError) Error() string {
	return e.err + ": " + e.msg
}

// LogFatal causes a fatal log
func (e loadConfigError) LogFatal(log *zerolog.Logger) {
	log.Fatal().
		Str("error", e.err).
		Msg(e.msg)
}
