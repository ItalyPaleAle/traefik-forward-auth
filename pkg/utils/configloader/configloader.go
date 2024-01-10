package configloader

import (
	"fmt"
	"maps"
	"os"
	"reflect"

	env "github.com/caarlos0/env/v10"
	"github.com/mitchellh/mapstructure"
	yaml "gopkg.in/yaml.v3"

	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
)

// LoadOptions contains options for the Load method.
type LoadOptions struct {
	// Optional path to a YAML (or JSON) file to load
	FilePath string
	// Optional prefix for env vars.
	EnvPrefix string
	// If true, values loaded from the config file which have a zero value (e.g. empty strings or number 0's) are ignored.
	IgnoreZeroValuesInConfig bool
}

// Load the configuration from a file and from the environment.
// "dst" must be a pointer to a struct.
// Note: this method currently does not work correctly with properties of the struct that are pointers.
func Load(dst any, opts LoadOptions) error {
	// First, load the config from the YAML into a map (if we have a file)
	if opts.FilePath != "" {
		m := map[string]any{}
		f, err := os.Open(opts.FilePath)
		if err != nil {
			return fmt.Errorf("failed to open config file '%s': %w", opts.FilePath, err)
		}
		defer f.Close()
		yamlDec := yaml.NewDecoder(f)
		yamlDec.KnownFields(true)
		err = yamlDec.Decode(&m)
		if err != nil {
			return fmt.Errorf("failed to decode config file '%s': %w", opts.FilePath, err)
		}

		// Ignore fields with zero value
		if opts.IgnoreZeroValuesInConfig {
			maps.DeleteFunc(m, func(s string, a any) bool {
				return reflect.ValueOf(a).IsZero()
			})
		}

		// Now apply the changes into the config object
		err = loadFromMap(dst, m)
		if err != nil {
			return err
		}
	}

	// Next, update from env
	err := env.ParseWithOptions(dst, env.Options{
		Prefix: opts.EnvPrefix,
	})
	if err != nil {
		return fmt.Errorf("failed to parse config from env vars: %w", err)
	}

	return nil
}

// Internal function that applies the options from a map.
func loadFromMap(dst any, m map[string]any) error {
	mapDec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			mapstructure.TextUnmarshallerHookFunc(),
			toTruthyBoolHookFunc(),
		),
		Result:           dst,
		WeaklyTypedInput: true,
		TagName:          "yaml",
	})
	if err != nil {
		return fmt.Errorf("failed to init mapstructure decoder: %w", err)
	}
	err = mapDec.Decode(m)
	if err != nil {
		return fmt.Errorf("failed to decode from map: %w", err)
	}
	return nil
}

// Adapted from https://github.com/dapr/kit
// Copyright (C) 2023 The Dapr Authors
// License: Apache2
func toTruthyBoolHookFunc() mapstructure.DecodeHookFunc {
	var boolVar bool
	stringType := reflect.TypeOf("")
	boolType := reflect.TypeOf(boolVar)
	boolPtrType := reflect.TypeOf(&boolVar)

	return func(
		f reflect.Type,
		t reflect.Type,
		data any,
	) (any, error) {
		switch {
		case f == stringType && t == boolType:
			//nolint:forcetypeassert
			return utils.IsTruthy(data.(string)), nil
		case f == stringType && t == boolPtrType:
			//nolint:forcetypeassert
			res := utils.IsTruthy(data.(string))
			return &res, nil
		default:
			return data, nil
		}
	}
}
