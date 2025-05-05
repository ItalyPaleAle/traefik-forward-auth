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
		err := Load(cfg, "testdata/full.yaml", LoadOptions{
			EnvPrefix: "TEST_",
		})
		require.NoError(t, err)

		expect := &testConfig{
			AString:      "foo",
			AnInt:        42,
			ABool:        true,
			AFloat:       123.45,
			ADuration:    2 * time.Minute,
			AStringSlice: []string{"ciao", "mondo"},
			AMap:         map[string]string{"hello": "world", "salut": "monde"},
			Nested: testConfigNested{
				Foo: "bar",
			},
		}

		assert.Equal(t, expect, cfg)
	})

	t.Run("override from env", func(t *testing.T) {
		t.Setenv("TEST_A_STRING", "foo2")
		t.Setenv("TEST_AN_INT", "10")
		t.Setenv("TEST_A_BOOL", "false")
		t.Setenv("TEST_A_FLOAT", "3.14")
		t.Setenv("TEST_A_DURATION", "4m")
		t.Setenv("TEST_A_STRING_SLICE", "a,b,c")
		t.Setenv("TEST_A_MAP", "ciao:mondo,hola:mundo")
		t.Setenv("TEST_FOO", "bar2")

		cfg := &testConfig{}
		err := Load(cfg, "testdata/full.yaml", LoadOptions{
			EnvPrefix: "TEST_",
		})
		require.NoError(t, err)

		expect := &testConfig{
			AString:      "foo2",
			AnInt:        10,
			ABool:        false,
			AFloat:       3.14,
			ADuration:    4 * time.Minute,
			AStringSlice: []string{"a", "b", "c"},
			AMap:         map[string]string{"ciao": "mondo", "hola": "mundo"},
			Nested: testConfigNested{
				Foo: "bar2",
			},
		}

		assert.Equal(t, expect, cfg)
	})

	t.Run("override default values", func(t *testing.T) {
		cfg := &testConfig{
			AString:      "bar",
			AnInt:        10,
			AStringSlice: []string{"👋", "🌍"},
			AMap:         map[string]string{"hello": "who", "me": "🙃"},
			Nested: testConfigNested{
				Foo: "nothing",
			},
		}
		err := Load(cfg, "testdata/full.yaml", LoadOptions{
			EnvPrefix: "TEST_",
		})
		require.NoError(t, err)

		expect := &testConfig{
			AString:      "foo",
			AnInt:        42,
			ABool:        true,
			AFloat:       123.45,
			ADuration:    2 * time.Minute,
			AStringSlice: []string{"ciao", "mondo"},
			// Appends new fields but doesn't delete existing ones
			AMap: map[string]string{"hello": "world", "me": "🙃", "salut": "monde"},
			Nested: testConfigNested{
				Foo: "bar",
			},
		}

		assert.Equal(t, expect, cfg)
	})
}
