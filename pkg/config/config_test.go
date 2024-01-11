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

		tsk := config.GetTokenSigningKey()
		var tskRaw []byte
		err = tsk.Raw(&tskRaw)
		require.NoError(t, err)
		assert.Equal(t, "b0c4b5e9cd81511ee72e7ecfcaee8fae84de71bc02e575960928cc606f6622fb", hex.EncodeToString(tskRaw))
	})

	t.Run("tokenSigningKey not present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"tokenSigningKey": "",
		}))

		err := config.SetTokenSigningKey(&logger)
		require.NoError(t, err)
		tsk1 := config.GetTokenSigningKey()
		var tsk1Raw []byte
		err = tsk1.Raw(&tsk1Raw)
		require.NoError(t, err)
		require.Len(t, tsk1Raw, 32)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokenSigningKey' found in the configuration")

		// Should be different every time
		err = config.SetTokenSigningKey(&logger)
		require.NoError(t, err)

		tsk2 := config.GetTokenSigningKey()
		var tsk2Raw []byte
		err = tsk2.Raw(&tsk2Raw)
		require.NoError(t, err)
		assert.NotEqual(t, tsk1Raw, tsk2Raw)
	})
}
