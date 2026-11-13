package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

func TestAuthenticatedClaimHeader(t *testing.T) {
	portal := &Portal{Name: "myportal"}
	provider := auth.NewTestProviderSeamless()

	t.Run("GetName", func(t *testing.T) {
		h := authenticatedClaimHeader{name: "X-Forwarded-Email", claim: "email"}
		assert.Equal(t, "X-Forwarded-Email", h.GetName())
	})

	t.Run("GetValue with a full profile", func(t *testing.T) {
		profile := &user.Profile{
			Provider: "testseamless",
			ID:       "user123",
			Name: user.ProfileName{
				FullName:          "John Doe",
				First:             "John",
				Middle:            "Q",
				Last:              "Doe",
				Nickname:          "johnd",
				PreferredUsername: "john.doe",
			},
			Email:    &user.ProfileEmail{Value: "john@example.com", Verified: true},
			Picture:  "https://example.com/avatar.jpg",
			Locale:   "en-US",
			Timezone: "America/New_York",
			Groups:   []string{"admins", "users"},
			Roles:    []string{"admin", "editor"},
			AdditionalClaims: map[string]any{
				"custom_string": "hello",
				"custom_number": 42,
				"custom_bool":   true,
				"custom_slice":  []string{"one", "two"},
			},
		}

		tests := []struct {
			claim  string
			expect string
		}{
			{claim: "provider", expect: "testseamless"},
			{claim: "id", expect: "user123"},
			{claim: "sub", expect: "user123"},
			{claim: "name", expect: "John Doe"},
			{claim: "given_name", expect: "John"},
			{claim: "middle_name", expect: "Q"},
			{claim: "family_name", expect: "Doe"},
			{claim: "nickname", expect: "johnd"},
			{claim: "preferred_username", expect: "john.doe"},
			{claim: "email", expect: "john@example.com"},
			{claim: "email_verified", expect: "true"},
			{claim: "picture", expect: "https://example.com/avatar.jpg"},
			{claim: "locale", expect: "en-US"},
			{claim: "zoneinfo", expect: "America/New_York"},
			// Groups and roles are encoded as space-separated lists
			{claim: "groups", expect: "admins users"},
			{claim: "roles", expect: "admin editor"},
			// Custom claims
			{claim: "custom_string", expect: "hello"},
			{claim: "custom_number", expect: "42"},
			{claim: "custom_bool", expect: "true"},
			// Only scalar values are supported for custom claims, so slices are empty
			{claim: "custom_slice", expect: ""},
			// Claims that are not present
			{claim: "missing", expect: ""},
			{claim: "", expect: ""},
		}

		for _, tc := range tests {
			t.Run(tc.claim, func(t *testing.T) {
				h := authenticatedClaimHeader{name: "X-Test", claim: tc.claim}
				assert.Equal(t, tc.expect, h.GetValue(portal, provider, profile))
			})
		}
	})

	t.Run("GetValue with a single group or role", func(t *testing.T) {
		profile := &user.Profile{
			ID:     "user123",
			Groups: []string{"admins"},
			Roles:  []string{"admin"},
		}

		assert.Equal(t, "admins", authenticatedClaimHeader{claim: "groups"}.GetValue(portal, provider, profile))
		assert.Equal(t, "admin", authenticatedClaimHeader{claim: "roles"}.GetValue(portal, provider, profile))
	})

	t.Run("GetValue with a minimal profile", func(t *testing.T) {
		// Profile with no email, groups, or roles
		profile := &user.Profile{ID: "user123"}

		tests := []string{"name", "email", "email_verified", "picture", "groups", "roles"}
		for _, claim := range tests {
			t.Run(claim, func(t *testing.T) {
				h := authenticatedClaimHeader{name: "X-Test", claim: claim}
				assert.Empty(t, h.GetValue(portal, provider, profile))
			})
		}
	})

	t.Run("GetValue with empty groups and roles", func(t *testing.T) {
		// Non-nil but empty
		profile := &user.Profile{
			ID:     "user123",
			Groups: []string{},
			Roles:  []string{},
		}

		assert.Empty(t, authenticatedClaimHeader{claim: "groups"}.GetValue(portal, provider, profile))
		assert.Empty(t, authenticatedClaimHeader{claim: "roles"}.GetValue(portal, provider, profile))
	})
}

func TestAuthenticatedPropertyHeader(t *testing.T) {
	portal := &Portal{Name: "myportal"}
	provider := auth.NewTestProviderSeamless()
	profile := &user.Profile{ID: "user123"}

	t.Run("GetName", func(t *testing.T) {
		h := authenticatedPropertyHeader{name: "X-Portal", property: config.PropertyPortalName}
		assert.Equal(t, "X-Portal", h.GetName())
	})

	t.Run("GetValue", func(t *testing.T) {
		tests := []struct {
			property string
			expect   string
		}{
			{property: config.PropertyPortalName, expect: "myportal"},
			{property: config.PropertyProviderName, expect: "testseamless"},
			// Unsupported properties return an empty value
			{property: "provider.type", expect: ""},
			{property: "", expect: ""},
		}

		for _, tc := range tests {
			t.Run(tc.property, func(t *testing.T) {
				h := authenticatedPropertyHeader{name: "X-Test", property: tc.property}
				assert.Equal(t, tc.expect, h.GetValue(portal, provider, profile))
			})
		}
	})
}

func TestBuiltinAuthenticatedUserHeader(t *testing.T) {
	portal := &Portal{Name: "myportal"}
	provider := auth.NewTestProviderSeamless()

	h := builtinAuthenticatedUserHeader{}

	t.Run("GetName", func(t *testing.T) {
		assert.Equal(t, headerXAuthenticatedUser, h.GetName())
	})

	t.Run("GetValue", func(t *testing.T) {
		profile := &user.Profile{ID: "user123"}
		assert.JSONEq(t,
			`{"provider":"testseamless","portal":"myportal","user":"user123"}`,
			h.GetValue(portal, provider, profile),
		)
	})

	t.Run("GetValue escapes the user ID as JSON", func(t *testing.T) {
		// The value is built by concatenating strings, so ensure the user ID is escaped and the result is valid JSON
		profile := &user.Profile{ID: `foo"bar`}
		assert.JSONEq(t,
			`{"provider":"testseamless","portal":"myportal","user":"foo\"bar"}`,
			h.GetValue(portal, provider, profile),
		)
	})
}

func TestGetHeadersConfig(t *testing.T) {
	t.Run("default headers when unset", func(t *testing.T) {
		headers := getHeadersConfig(config.ConfigPortal{})

		require.Len(t, headers, 3)

		require.IsType(t, authenticatedClaimHeader{}, headers[0])
		assert.Equal(t, authenticatedClaimHeader{name: headerXForwardedUser, claim: "id"}, headers[0])

		assert.IsType(t, builtinAuthenticatedUserHeader{}, headers[1])

		require.IsType(t, authenticatedClaimHeader{}, headers[2])
		assert.Equal(t, authenticatedClaimHeader{name: headerXForwardedDisplayName, claim: "name"}, headers[2])
	})

	t.Run("no headers when set to an empty list", func(t *testing.T) {
		headers := getHeadersConfig(config.ConfigPortal{
			Headers: &[]config.ConfigPortalHeader{},
		})

		assert.Empty(t, headers)
	})

	t.Run("custom headers", func(t *testing.T) {
		headers := getHeadersConfig(config.ConfigPortal{
			Headers: &[]config.ConfigPortalHeader{
				{Name: "X-Forwarded-Email", Claim: "email"},
				{Name: "X-Forwarded-Groups", Claim: "groups"},
				{Name: "X-Portal", Property: config.PropertyPortalName},
			},
		})

		require.Len(t, headers, 3)
		assert.Equal(t, authenticatedClaimHeader{name: "X-Forwarded-Email", claim: "email"}, headers[0])
		assert.Equal(t, authenticatedClaimHeader{name: "X-Forwarded-Groups", claim: "groups"}, headers[1])
		assert.Equal(t, authenticatedPropertyHeader{name: "X-Portal", property: config.PropertyPortalName}, headers[2])
	})
}

func TestJSONQuoteString(t *testing.T) {
	// jsonQuoteString takes a shortcut for values that need no escaping, so its output must be identical to the JSON encoder's for every input
	//nolint:gosmopolitan
	values := []string{
		"",
		"user123",
		"user@example.com",
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"with space",
		"tilde~and-dash_dot.",
		`quote"inside`,
		`back\slash`,
		"angle<brackets>",
		"amper&sand",
		"new\nline",
		"tab\tchar",
		"null\x00byte",
		"del\x7fchar",
		"accented-é",
		"日本語",
		"emoji-🎉",
		"invalid-utf8-\xff",
	}

	for _, val := range values {
		t.Run(fmt.Sprintf("%q", val), func(t *testing.T) {
			expected, err := json.Marshal(val)
			require.NoError(t, err)

			assert.Equal(t, string(expected), jsonQuoteString(val))
		})
	}
}

func TestSetAuthenticatedHeaders(t *testing.T) {
	provider := auth.NewTestProviderSeamless()
	profile := &user.Profile{
		Provider: "testseamless",
		ID:       "user123",
		Name:     user.ProfileName{FullName: "John Doe"},
		Email:    &user.ProfileEmail{Value: "john@example.com", Verified: true},
	}

	newContext := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		return c
	}

	t.Run("sets every configured header", func(t *testing.T) {
		portal := &Portal{
			Name: "myportal",
			Headers: []AuthenticatedHeader{
				authenticatedClaimHeader{name: "X-Forwarded-User", claim: "id"},
				authenticatedClaimHeader{name: "X-Forwarded-Email", claim: "email"},
				authenticatedPropertyHeader{name: "X-Forwarded-Portal", property: config.PropertyPortalName},
			},
		}

		c := newContext()
		setAuthenticatedHeaders(c, portal, provider, profile)

		h := c.Writer.Header()
		assert.Equal(t, "user123", h.Get("X-Forwarded-User"))
		assert.Equal(t, "john@example.com", h.Get("X-Forwarded-Email"))
		assert.Equal(t, "myportal", h.Get("X-Forwarded-Portal"))
	})

	t.Run("an empty value removes the header", func(t *testing.T) {
		portal := &Portal{
			Name: "myportal",
			Headers: []AuthenticatedHeader{
				authenticatedClaimHeader{name: "X-Forwarded-User", claim: "id"},
				// The profile has no nickname, so this one resolves to an empty value
				authenticatedClaimHeader{name: "X-Forwarded-Nickname", claim: "nickname"},
			},
		}

		c := newContext()
		c.Writer.Header().Set("X-Forwarded-Nickname", "stale")

		setAuthenticatedHeaders(c, portal, provider, profile)

		h := c.Writer.Header()
		assert.Equal(t, "user123", h.Get("X-Forwarded-User"))
		assert.NotContains(t, h, "X-Forwarded-Nickname")
	})

	t.Run("values stay independent even though they share a backing array", func(t *testing.T) {
		portal := &Portal{
			Name: "myportal",
			Headers: []AuthenticatedHeader{
				authenticatedClaimHeader{name: "X-Forwarded-User", claim: "id"},
				authenticatedClaimHeader{name: "X-Forwarded-Email", claim: "email"},
				authenticatedClaimHeader{name: "X-Forwarded-Displayname", claim: "name"},
			},
		}

		c := newContext()
		setAuthenticatedHeaders(c, portal, provider, profile)

		h := c.Writer.Header()
		// Adding a second value to one header must not overwrite the value of the next one
		h.Add("X-Forwarded-User", "extra")

		assert.Equal(t, []string{"user123", "extra"}, h["X-Forwarded-User"])
		assert.Equal(t, []string{"john@example.com"}, h["X-Forwarded-Email"])
		assert.Equal(t, []string{"John Doe"}, h["X-Forwarded-Displayname"])
	})

	t.Run("no headers configured", func(t *testing.T) {
		c := newContext()
		setAuthenticatedHeaders(c, &Portal{Name: "myportal"}, provider, profile)
		assert.Empty(t, c.Writer.Header())
	})

	t.Run("allocates once regardless of the number of headers", func(t *testing.T) {
		portal := &Portal{
			Name: "myportal",
			Headers: []AuthenticatedHeader{
				authenticatedClaimHeader{name: "X-Forwarded-User", claim: "id"},
				authenticatedClaimHeader{name: "X-Forwarded-Email", claim: "email"},
				authenticatedClaimHeader{name: "X-Forwarded-Displayname", claim: "name"},
			},
		}

		c := newContext()
		allocs := testing.AllocsPerRun(100, func() {
			setAuthenticatedHeaders(c, portal, provider, profile)
		})

		assert.Equal(t, 1, int(allocs))
	})
}

func TestValidateHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "printable ASCII is unchanged", value: "John Doe <john@example.com>", want: "John Doe <john@example.com>"},
		{name: "empty value", value: "", want: ""},
		{name: "valid UTF-8 is kept", value: "José Müller – Zoë", want: "José Müller – Zoë"},
		{name: "tabs are kept", value: "a\tb", want: "a\tb"},
		{name: "CR and LF are removed", value: "X\r\nSet-Cookie: evil=1", want: "XSet-Cookie: evil=1"},
		{name: "NUL is removed", value: "a\x00b", want: "ab"},
		{name: "DEL is removed", value: "a\x7fb", want: "ab"},
		{name: "C1 control characters are removed", value: "a\u0085b\u009fc", want: "abc"},
		{name: "invalid UTF-8 is removed", value: "a\xffb\xc3c", want: "abc"},
		{name: "a literal replacement character is kept", value: "a�b", want: "a�b"},
		{name: "only control characters becomes empty", value: "\r\n\x00", want: ""},
		{name: "1KB is allowed", value: strings.Repeat("a", 1<<10), want: strings.Repeat("a", 1<<10)},
		{name: "longer than 1KB is dropped", value: strings.Repeat("a", 1<<10+1), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, validateHeaderValue(tt.value))
		})
	}

	t.Run("printable ASCII does not allocate", func(t *testing.T) {
		value := "John Doe <john@example.com>"
		allocs := testing.AllocsPerRun(100, func() {
			_ = validateHeaderValue(value)
		})
		assert.Zero(t, allocs)
	})
}

// TestSetAuthenticatedHeadersReadableByGoClient checks that a claim containing control characters doesn't produce a response that Go HTTP clients (like Traefik) refuse to parse
func TestSetAuthenticatedHeadersReadableByGoClient(t *testing.T) {
	provider := auth.NewTestProviderSeamless()
	profile := &user.Profile{
		Provider: "testseamless",
		ID:       "user123",
		Name:     user.ProfileName{FullName: "Jo\x00hn\x7f D\xffoe\r\nSet-Cookie: evil=1"},
	}
	portal := &Portal{
		Name: "myportal",
		Headers: []AuthenticatedHeader{
			authenticatedClaimHeader{name: "X-Forwarded-Displayname", claim: "name"},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := gin.CreateTestContext(w)
		setAuthenticatedHeaders(c, portal, provider, profile)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, "John DoeSet-Cookie: evil=1", res.Header.Get("X-Forwarded-Displayname"))
	assert.Empty(t, res.Header.Values("Set-Cookie"))
}
