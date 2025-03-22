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
	Nested       testConfigNested  `env:"NESTED" yaml:"nested"`
}

type testConfigNested struct {
	Foo string `env:"FOO" yaml:"foo"`
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
		assert.EqualValues(t, []string{"ciao", "mondo"}, cfg.AStringSlice)
		assert.EqualValues(t, map[string]string{"hello": "world", "salut": "monde"}, cfg.AMap)
		assert.Equal(t, "bar", cfg.Nested.Foo)
	})

	t.Run("load from env", func(t *testing.T) {
		t.Setenv("TEST_A_STRING", "foo2")
		t.Setenv("TEST_AN_INT", "10")
		t.Setenv("TEST_A_BOOL", "false")
		t.Setenv("TEST_A_FLOAT", "3.14")
		t.Setenv("TEST_A_DURATION", "4m")
		t.Setenv("TEST_A_STRING_SLICE", "a,b,c")
		t.Setenv("TEST_A_MAP", "ciao:mondo,hola:mundo")
		t.Setenv("TEST_FOO", "bar2")

		cfg := &testConfig{}
		err := Load(cfg, LoadOptions{
			FilePath:  "testdata/full.yaml",
			EnvPrefix: "TEST_",
		})
		require.NoError(t, err)

		assert.Equal(t, "foo2", cfg.AString)
		assert.Equal(t, 10, cfg.AnInt)
		assert.False(t, cfg.ABool)
		assert.InDelta(t, 3.14, cfg.AFloat, 0.01)
		assert.Equal(t, 4*time.Minute, cfg.ADuration)
		assert.EqualValues(t, []string{"a", "b", "c"}, cfg.AStringSlice)
		assert.EqualValues(t, map[string]string{"ciao": "mondo", "hola": "mundo"}, cfg.AMap)
		assert.Equal(t, "bar2", cfg.Nested.Foo)
	})
}
