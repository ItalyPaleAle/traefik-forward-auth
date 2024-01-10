//go:build unit

// This file is only built when the "unit" tag is set

package config

import (
	"github.com/jinzhu/copier"

	"github.com/italypaleale/traefik-forward-auth/pkg/utils/configloader"
)

// Updates the configuration in the global config object for the test
// Returns a function that should be called with "defer" to restore the previous configuration
func SetTestConfig(values map[string]any) func() {
	// Save the previous config
	prevConfig := config

	// Create a deep copy of the previous config
	// Note that this doesn't copy unexported fields
	config = &Config{}
	err := copier.CopyWithOption(config, prevConfig, copier.Option{
		DeepCopy: true,
	})
	if err != nil {
		// Panic in case of errors, since this function is used for testing only
		panic(err)
	}

	// Set the new values
	err = configloader.LoadFromMap(config, values)
	if err != nil {
		panic(err)
	}

	// Return a function that restores the original value
	return func() {
		config = prevConfig
	}
}
