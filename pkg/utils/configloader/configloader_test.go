package configloader

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	AString      string            `env:"A_STRING" yaml:"aString"`
	AnInt        int               `env:"AN_INT" yaml:"anInt"`
	ABool        bool              `env:"A_BOOL" yaml:"aBool"`
	AFloat       float64           `env:"A_FLOAT" yaml:"aFloat"`
	ADuration    time.Duration     `env:"A_DURATION" yaml:"aDuration"`
	AStringSlice []string          `env:"A_STRING_SLICE" yaml:"aStringSlice"`
	AMap         map[string]string `env:"A_MAP" yaml:"aMap"`
}

func TestConfigLoader(t *testing.T) {
	t.Run("load from YAML", func(t *testing.T) {
		cfg := &testConfig{}
		err := Load(cfg, LoadOptions{
			FilePath:  "testdata/full.yaml",
			EnvPrefix: "TEST_",
		})
		require.NoError(t, err)

		assert.Equal(t, "foo", cfg.AString)
		assert.Equal(t, 42, cfg.AnInt)
		assert.True(t, cfg.ABool)
		assert.InDelta(t, 123.45, cfg.AFloat, 0.01)
		assert.Equal(t, 2*time.Minute, cfg.ADuration)
	})
}
