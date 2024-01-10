package config

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
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
