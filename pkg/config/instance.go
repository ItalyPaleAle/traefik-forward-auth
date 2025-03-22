package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

var config *Config

func init() {
	// Set the default config at startup
	config = GetDefaultConfig()

	// Set the instance ID
	// This may panic if there's not enough entropy in the system
	var err error
	config.internal.instanceID, err = initInstanceID()
	if err != nil {
		panic("failed to set instance ID: " + err.Error())
	}
}

// Get returns the singleton instance
func Get() *Config {
	return config
}

// GetDefaultConfig returns the default configuration.
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
		Metrics: ConfigMetrics{
			ServerEnabled: false,
			ServerPort:    2112,
			ServerBind:    "0.0.0.0",
		},
		AuthenticationTimeout: 5 * time.Minute,
	}
}

func initInstanceID() (string, error) {
	// First, check if we have an instance ID from the environment/platform
	var val string

	// Azure Container Apps
	if val = os.Getenv("CONTAINER_APP_REPLICA_NAME"); val != "" {
		return os.Getenv("CONTAINER_APP_REPLICA_NAME"), nil
	}

	// Check if we have a "service.instance.id" in the "OTEL_RESOURCE_ATTRIBUTES" env var
	if val = os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); val != "" {
		parsed := parseOtelResourceAttributesEnvVar(val)
		if parsed["service.instance.id"] != "" {
			return parsed["service.instance.id"], nil
		}
	}

	// Fallback to computing a random 56-bit value
	instanceID := make([]byte, 7)
	_, err := io.ReadFull(rand.Reader, instanceID)
	if err != nil {
		return "", fmt.Errorf("could not generate random instance ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(instanceID), nil
}

func parseOtelResourceAttributesEnvVar(val string) map[string]string {
	// Format is "key1=value1,key2=value2" where the value is URL-encoded
	// https://github.com/open-telemetry/opentelemetry-go/blob/002c0a4c0352a56ebebc13f3ec20f73c23b348f6/sdk/resource/env.go
	if val == "" {
		return make(map[string]string, 0)
	}

	var err error
	pairs := strings.Split(val, ",")
	vals := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v, err = url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			continue
		}
		vals[k] = v
	}

	return vals
}
