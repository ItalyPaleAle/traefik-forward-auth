package config

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

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
					{Provider: "github"},
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
						{Provider: "github"},
					},
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid portal '1'") &&
			assert.ErrorContains(t, err, "property 'name' is invalid")
	})

	t.Run("fails when portal has invalid provider", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{
				{
					Name: "foo",
					Providers: []ConfigPortalProvider{
						{Provider: "bad"},
					},
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid portal 'foo'") &&
			assert.ErrorContains(t, err, "invalid value for 'provider': bad")
	})

	t.Run("parse provider config", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{
				{
					Name: "github1",
					Providers: []ConfigPortalProvider{
						{
							Provider: "github",
							Config: map[string]any{
								"clientID":       "abcdef123456",
								"clientSecret":   "000-000-000",
								"requestTimeout": "30s",
							},
						},
					},
				},
			}
		}))

		expectProviderConfig := &ProviderConfig_GitHub{
			ClientID:       "abcdef123456",
			ClientSecret:   "000-000-000",
			RequestTimeout: 30 * time.Second,
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
			c.Tokens.SigningKey = "hello-world"
		}))

		err := config.SetTokenSigningKey(logger)
		require.NoError(t, err)

		tsk := config.GetTokenSigningKey()
		var tskRaw []byte
		err = tsk.Raw(&tskRaw)
		require.NoError(t, err)
		assert.Equal(t, "b0c4b5e9cd81511ee72e7ecfcaee8fae84de71bc02e575960928cc606f6622fb", hex.EncodeToString(tskRaw))
	})

	t.Run("tokenSigningKey not present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Tokens.SigningKey = ""
		}))

		err := config.SetTokenSigningKey(logger)
		require.NoError(t, err)
		tsk1 := config.GetTokenSigningKey()
		var tsk1Raw []byte
		err = tsk1.Raw(&tsk1Raw)
		require.NoError(t, err)
		require.Len(t, tsk1Raw, 32)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokens.signingKey' found in the configuration")

		// Should be different every time
		err = config.SetTokenSigningKey(logger)
		require.NoError(t, err)

		tsk2 := config.GetTokenSigningKey()
		var tsk2Raw []byte
		err = tsk2.Raw(&tsk2Raw)
		require.NoError(t, err)
		assert.NotEqual(t, tsk1Raw, tsk2Raw)
	})
}
