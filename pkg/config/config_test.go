package config

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/rs/zerolog"
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

	t.Cleanup(SetTestConfig(map[string]any{
		"database":    "postgresql://localhost/testdb",
		"emailSender": "console://",
	}))

	log := zerolog.Nop()

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := config.Validate(&log)
		require.NoError(t, err)
	})

	t.Run("fails without emailSender", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"emailSender": "",
		}))

		err := config.Validate(&log)
		require.Error(t, err)
		require.ErrorContains(t, err, "'emailSender' missing")
	})

	t.Run("fails with emailVerificationTimeout too small", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"emailVerificationTimeout": 100 * time.Millisecond,
		}))

		err := config.Validate(&log)
		require.Error(t, err)
		require.ErrorContains(t, err, "'emailVerificationTimeout' is invalid")
	})

	t.Run("fails with sessionIdleTimeout too small", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"sessionIdleTimeout": 100 * time.Millisecond,
		}))

		err := config.Validate(&log)
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionIdleTimeout' is invalid")
	})

	t.Run("fails with sessionMaxLifetime too small", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"sessionMaxLifetime": 100 * time.Millisecond,
		}))

		err := config.Validate(&log)
		require.Error(t, err)
		require.ErrorContains(t, err, "'sessionMaxLifetime' is invalid")
	})
}

func TestSetTokenSigningKey(t *testing.T) {
	logs := &bytes.Buffer{}
	logger := zerolog.New(logs)

	t.Run("tokenSigningKey present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"tokenSigningKey": "hello-world",
		}))

		err := config.SetTokenSigningKey(&logger)
		require.NoError(t, err)
		assert.Equal(t, "b8cf67b06159c291d6cc1e27b10cddeab93f48f444995f4b0fb886e3ea75d422", hex.EncodeToString(config.GetTokenSigningKey()))
	})

	t.Run("tokenSigningKey not present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"tokenSigningKey": "",
		}))

		err := config.SetTokenSigningKey(&logger)
		require.NoError(t, err)
		val := config.GetTokenSigningKey()
		require.Len(t, val, 32)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokenSigningKey' found in the configuration")

		// Should be different every time
		err = config.SetTokenSigningKey(&logger)
		require.NoError(t, err)
		assert.NotEqual(t, val, config.GetTokenSigningKey())
	})
}
