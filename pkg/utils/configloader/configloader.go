package configloader

import (
	"fmt"
	"os"

	env "github.com/caarlos0/env/v11"
	yaml "gopkg.in/yaml.v3"
)

// LoadOptions contains options for the Load method.
type LoadOptions struct {
	// Optional prefix for env vars.
	EnvPrefix string
	// If true, values loaded from the config file which have a zero value (e.g. empty strings or number 0's) are ignored.
	IgnoreZeroValuesInConfig bool
}

// Load the configuration from a file and from the environment.
// "dst" must be a pointer to a struct.
func Load(dst any, filePath string, opts LoadOptions) error {
	// First, load the config from the YAML
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open config file '%s': %w", filePath, err)
	}
	defer f.Close()
	yamlDec := yaml.NewDecoder(f)
	yamlDec.KnownFields(true)
	err = yamlDec.Decode(dst)
	if err != nil {
		return fmt.Errorf("failed to decode config file '%s': %w", filePath, err)
	}

	// Next, update from env
	err = env.ParseWithOptions(dst, env.Options{
		Prefix:                opts.EnvPrefix,
		UseFieldNameByDefault: false,
	})
	if err != nil {
		return fmt.Errorf("failed to parse config from env vars: %w", err)
	}

	return nil
}
