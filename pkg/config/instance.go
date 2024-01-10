package config

var config *Config

func init() {
	// Set the default config at startup
	config = GetDefaultConfig()
}

// Get returns the singleton instance
func Get() *Config {
	return config
}

// GetDefaultConfig returns the default configuration.
func GetDefaultConfig() *Config {
	return &Config{
		LogLevel:      "info",
		Port:          4181,
		Bind:          "0.0.0.0",
		EnableMetrics: false,
		MetricsPort:   2112,
		MetricsBind:   "0.0.0.0",
	}
}
