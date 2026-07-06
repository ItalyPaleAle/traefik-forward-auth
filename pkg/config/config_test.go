package config

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
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
	}))

	log := slog.New(slog.DiscardHandler)

	t.Run("succeeds with all required vars", func(t *testing.T) {
		err := config.Validate(log)
		require.NoError(t, err)
	})

	t.Run("uses server domains", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = ""
			c.Server.Hostname = ""
			c.Server.Domains = []ConfigServerDomain{
				{Domain: "example.com", AuthHost: "auth.example.com"},
				{Domain: "example.org"},
			}
		}))

		err := config.Validate(log)
		require.NoError(t, err)
		assert.Empty(t, config.Cookies.Domain)
		assert.Empty(t, config.Server.Hostname)
		assert.Equal(t, []ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
			{Domain: "example.org", AuthHost: "example.org"},
		}, config.Server.Domains)
	})

	t.Run("migrates legacy cookie domain and emits a deprecation warning", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = "Example.Com"
			c.Server.Hostname = ""
			c.Server.Domains = nil
		}))

		buf := &bytes.Buffer{}
		warnLog := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		err := config.Validate(warnLog)
		require.NoError(t, err)
		assert.Empty(t, config.Cookies.Domain)
		assert.Equal(t, []ConfigServerDomain{
			{Domain: "example.com", AuthHost: "example.com"},
		}, config.Server.Domains)
		out := buf.String()
		assert.Contains(t, out, "level=WARN")
		assert.Contains(t, out, "'cookies.domain' is deprecated")
		assert.Contains(t, out, "server.domains")
	})

	t.Run("migrates legacy cookie domain with hostname as auth host", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = "example.com"
			c.Server.Hostname = "Auth.Example.Com"
			c.Server.Domains = nil
		}))

		err := config.Validate(log)
		require.NoError(t, err)
		assert.Empty(t, config.Cookies.Domain)
		assert.Empty(t, config.Server.Hostname)
		assert.Equal(t, []ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
		}, config.Server.Domains)
	})

	t.Run("ignores hostname without legacy cookie domain", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = ""
			c.Server.Hostname = "auth.example.com"
			c.Server.Domains = []ConfigServerDomain{{Domain: "example.com"}}
		}))

		err := config.Validate(log)
		require.NoError(t, err)
		assert.Empty(t, config.Server.Hostname)
		assert.Equal(t, []ConfigServerDomain{
			{Domain: "example.com", AuthHost: "example.com"},
		}, config.Server.Domains)
	})

	t.Run("normalizes server domains", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = ""
			c.Server.Hostname = ""
			c.Server.Domains = []ConfigServerDomain{
				{Domain: "Example.Com", AuthHost: "Auth.Example.Com."},
				{Domain: "Apps.Example.Com."},
			}
		}))

		err := config.Validate(log)
		require.NoError(t, err)
		assert.Equal(t, []ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
			{Domain: "apps.example.com", AuthHost: "apps.example.com"},
		}, config.Server.Domains)
	})

	t.Run("dedupes server domains by domain", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = ""
			c.Server.Hostname = ""
			c.Server.Domains = []ConfigServerDomain{
				{Domain: "example.com", AuthHost: "auth.example.com"},
				{Domain: "Example.Com"},
			}
		}))

		err := config.Validate(log)
		require.NoError(t, err)
		assert.Equal(t, []ConfigServerDomain{
			{Domain: "example.com", AuthHost: "auth.example.com"},
		}, config.Server.Domains)
	})

	t.Run("fails when authHost is not a sub-domain of domain", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = ""
			c.Server.Hostname = ""
			c.Server.Domains = []ConfigServerDomain{
				{Domain: "example.com", AuthHost: "auth.example.org"},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		require.ErrorContains(t, err, "authHost")
		require.ErrorContains(t, err, "sub-domain")
	})

	t.Run("fails when legacy and new domains are both set", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = "example.com"
			c.Server.Domains = []ConfigServerDomain{{Domain: "example.org"}}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		require.ErrorContains(t, err, "cookies.domain")
		require.ErrorContains(t, err, "server.domains")
	})

	t.Run("fails when domain entry is missing domain", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Cookies.Domain = ""
			c.Server.Domains = []ConfigServerDomain{{AuthHost: "auth.example.com"}}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		require.ErrorContains(t, err, "server.domains[0].domain")
	})

	t.Run("fails without a portal", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals = []ConfigPortal{}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		require.ErrorContains(t, err, "at least one portal must be defined")
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

	t.Run("fails when header has no name", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals[0].Headers = &[]ConfigPortalHeader{
				{
					Claim: "email",
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid header at index 0") &&
			assert.ErrorContains(t, err, "property 'name' is required")
	})

	t.Run("fails when header has no claim or property", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals[0].Headers = &[]ConfigPortalHeader{
				{
					Name: "X-Forwarded-Email",
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid header 'X-Forwarded-Email'") &&
			assert.ErrorContains(t, err, "property 'claim' or 'property' is required")
	})

	t.Run("fails when header has claim and property", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals[0].Headers = &[]ConfigPortalHeader{
				{
					Name:     "X-Forwarded-Email",
					Claim:    "email",
					Property: "portal.name",
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid header 'X-Forwarded-Email'") &&
			assert.ErrorContains(t, err, "properties 'claim' and 'property' are mutually exclusive")
	})

	t.Run("fails when header has unknown property", func(t *testing.T) {
		t.Cleanup(SetTestConfig(func(c *Config) {
			c.Portals[0].Headers = &[]ConfigPortalHeader{
				{
					Name:     "X-Forwarded-Email",
					Property: "foobar",
				},
			}
		}))

		err := config.Validate(log)
		require.Error(t, err)
		_ = assert.ErrorContains(t, err, "invalid header 'X-Forwarded-Email'") &&
			assert.ErrorContains(t, err, "invalid property 'foobar'")
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
		tskRaw, err := jwk.Export[[]byte](tsk)
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
		tsk1Raw, err := jwk.Export[[]byte](tsk1)
		require.NoError(t, err)
		require.Len(t, tsk1Raw, 32)

		logsMsg := logs.String()
		require.Contains(t, logsMsg, "No 'tokens.signingKey' found in the configuration")

		// Should be different every time
		err = config.SetTokenSigningKey(logger)
		require.NoError(t, err)

		tsk2 := config.GetTokenSigningKey()
		tsk2Raw, err := jwk.Export[[]byte](tsk2)
		require.NoError(t, err)
		assert.NotEqual(t, tsk1Raw, tsk2Raw)
	})
}
