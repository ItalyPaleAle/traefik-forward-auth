package config

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"testing"

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
		"authProvider": "github",
		"hostname":     "localhost",
	}))

	log := slog.New(slog.DiscardHandler)

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := config.Validate(log)
		require.NoError(t, err)
	})

	t.Run("fails without authProvider", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"authProvider": "",
		}))

		err := config.Validate(log)
		require.Error(t, err)
		require.ErrorContains(t, err, "'authProvider' is required")
	})

	t.Run("fails without hostname", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"hostname": "",
		}))

		err := config.Validate(log)
		require.Error(t, err)
		require.ErrorContains(t, err, "'hostname' is required")
	})
}

func TestSetTokenSigningKey(t *testing.T) {
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	t.Run("tokenSigningKey present", func(t *testing.T) {
		t.Cleanup(SetTestConfig(map[string]any{
			"tokenSigningKey": "hello-world",
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
		t.Cleanup(SetTestConfig(map[string]any{
			"tokenSigningKey": "",
		}))

		err := config.SetTokenSigningKey(logger)
		require.NoError(t, err)
		tsk1 := config.GetTokenSigningKey()
		var tsk1Raw []byte
		err = tsk1.Raw(&tsk1Raw)
		require.NoError(t, err)
		require.Len(t, tsk1Raw, 32)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokenSigningKey' found in the configuration")

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
