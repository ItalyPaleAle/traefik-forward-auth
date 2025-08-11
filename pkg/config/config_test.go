package config

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfig(t *testing.T) {
	// Set initial variables in the global object
	oldConfig := config
	config = GetDefaultConfig()
	t.Cleanup(func() {
		config = oldConfig
	})

	t.Cleanup(SetTestConfig(func(c *Config) {
		c.Portals = []ConfigPortal{
			{
				Name: "github1",
				Providers: []ConfigPortalProvider{
					{GitHub: &ProviderConfig_GitHub{}},
				},
			},
		}
		c.Server.Hostname = "localhost"
	}))

	log := slog.New(slog.DiscardHandler)

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := config.Validate(log)
		require.NoError(t, err)
	})

	t.Run("fails without a portal", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		assert.ErrorContains(t, err, "at least one portal must be defined")
	})

	t.Run("fails without hostname", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Server.Hostname = ""
		}))

		err := config.Validate(log)
		require.Error(t, err)
		assert.ErrorContains(t, err, "'server.hostname' is required")
	})

	t.Run("fails when portal has invalid name", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{
				{
					Name: "1",
					Providers: []ConfigPortalProvider{
						{GitHub: &ProviderConfig_GitHub{}},
					},
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid portal '1'") &&
			assert.ErrorContains(t, err, "property 'name' is invalid")
	})

	t.Run("fails when portal has no provider in list", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{
				{
					Name: "foo",
					// In this test, the slice is empty
					Providers: []ConfigPortalProvider{},
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid portal 'foo'") &&
			assert.ErrorContains(t, err, "at least one authentication provider must be configured")
	})

	t.Run("fails when portal has no providers in object", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{
				{
					Name: "foo",
					Providers: []ConfigPortalProvider{
						// In this test, the slice has 1 element which has no provider configured
						{},
					},
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid portal 'foo'") &&
			assert.ErrorContains(t, err, "no provider type configured for the provider")
	})

	t.Run("fails when portal has too many providers", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{
				{
					Name: "foo",
					Providers: []ConfigPortalProvider{
						{
							GitHub: &ProviderConfig_GitHub{},
							Google: &ProviderConfig_Google{},
						},
					},
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid portal 'foo'") &&
			assert.ErrorContains(t, err, "cannot configure more than one provider type in each provider")
	})

	t.Run("parse provider config", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{
				{
					Name: "github1",
					Providers: []ConfigPortalProvider{
						{
							GitHub: &ProviderConfig_GitHub{
								ClientID:       "abcdef123456",
								ClientSecret:   "000-000-000",
								RequestTimeout: 40 * time.Second,
							},
						},
					},
				},
			}
		}))

		expectProviderConfig := &ProviderConfig_GitHub{
			ClientID:       "abcdef123456",
			ClientSecret:   "000-000-000",
			RequestTimeout: 40 * time.Second,
		}

		err := config.Validate(log)
		require.NoError(t, err)

		require.Len(t, config.Portals, 1)
		assert.EqualValues(t, expectProviderConfig, config.Portals[0].Providers[0].configParsed)
	})
}

func TestSetTokenSigningKey(t *testing.T) {
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	t.Run("tokenSigningKey present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Tokens.SigningKey = "hello-world-1234567890"
		}))

		err := config.SetTokenSigningKey(logger)
		require.NoError(t, err)

		tsk := config.GetTokenSigningKey()
		var tskRaw []byte
		err = jwk.Export(tsk, &tskRaw)
		require.NoError(t, err)
		assert.Equal(t, "ab5150d6fd45693503c863ff3fb6e5c51890efbc094bef810d8ae79f5139aa81", hex.EncodeToString(tskRaw))
	})

	t.Run("tokenSigningKey not present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Tokens.SigningKey = ""
		}))

		err := config.SetTokenSigningKey(logger)
		require.NoError(t, err)
		tsk1 := config.GetTokenSigningKey()
		var tsk1Raw []byte
		err = jwk.Export(tsk1, &tsk1Raw)
		require.NoError(t, err)
		require.Len(t, tsk1Raw, 32)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokens.signingKey' found in the configuration")

		// Should be different every time
		err = config.SetTokenSigningKey(logger)
		require.NoError(t, err)

		tsk2 := config.GetTokenSigningKey()
		var tsk2Raw []byte
		err = jwk.Export(tsk2, &tsk2Raw)
		require.NoError(t, err)
		assert.NotEqual(t, tsk1Raw, tsk2Raw)
	})
}
