package config

import (
	"time"

	configkit "github.com/italypaleale/go-kit/config"
)

var config *Config

func init() {
	// Set the default config at startup
	config = GetDefaultConfig()

	// Set the instance ID
	// This may panic if there's not enough entropy in the system
	var err error
	config.internal.instanceID, err = configkit.GetInstanceID()
	if err != nil {
		panic("failed to set instance ID: " + err.Error())
	}
}

// Get returns the singleton instance
func Get() *Config {
	return config
}

// GetDefaultConfig returns the default configuration
func GetDefaultConfig() *Config {
	return &Config{
		Cookies: ConfigCookies{
			NamePrefix: "tf_sess",
			Insecure:   false,
		},
		Server: ConfigServer{
			Port: 4181,
			Bind: "0.0.0.0",
		},
		Tokens: ConfigTokens{
			SessionLifetime: 2 * time.Hour,
		},
		Logs: ConfigLogs{
			Level:            "info",
			OmitHealthChecks: true,
		},
	}
}
