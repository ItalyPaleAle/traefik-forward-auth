package configloader

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	AString      string            `yaml:"aString"`
	AnInt        int               `yaml:"anInt"`
	ABool        bool              `yaml:"aBool"`
	AFloat       float64           `yaml:"aFloat"`
	ADuration    time.Duration     `yaml:"aDuration"`
	AStringSlice []string          `yaml:"aStringSlice"`
	AMap         map[string]string `yaml:"aMap"`
	AStruct      struct {
		AString string `yaml:"aString"`
		AnInt   int    `yaml:"anInt"`
		ABool   bool   `yaml:"aBool"`
	} `yaml:"aStruct"`
}

func TestConfigLoader(t *testing.T) {
	t.Run("load from YAML", func(t *testing.T) {
		cfg := &testConfig{}
		err := Load(cfg, LoadOptions{
			FilePath: "testdata/full.yaml",
		})
		require.NoError(t, err)

		assert.Equal(t, "foo", cfg.AString)
		assert.Equal(t, 42, cfg.AnInt)
		assert.True(t, cfg.ABool)
		assert.InDelta(t, 123.45, cfg.AFloat, 0.01)
		assert.Equal(t, 2*time.Minute, cfg.ADuration)
	})
}
