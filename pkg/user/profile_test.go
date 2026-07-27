package user

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt/openid"
	"github.com/spf13/cast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProfileFromOpenIDToken(t *testing.T) {
	tests := []struct {
		name          string
		setupToken    func() openid.Token
		expectedError bool
		validate      func(t *testing.T, profile *Profile)
	}{
		{
			name: "complete token",
			setupToken: func() openid.Token {
				builder := openid.NewBuilder()
				builder.Subject("user123")
				builder.Name("John Doe")
				builder.GivenName("John")
				builder.MiddleName("A")
				builder.FamilyName("Doe")
				builder.Nickname("Johnny")
				builder.Email("john@example.com")
				builder.EmailVerified(true)
				builder.Picture("https://example.com/picture.jpg")
				builder.Locale("en-US")
				builder.Zoneinfo("America/New_York")
				token, _ := builder.Build()
				return token
			},
			validate: func(t *testing.T, profile *Profile) {
				assert.Equal(t, "user123", profile.ID)
				assert.Equal(t, "John Doe", profile.Name.FullName)
				assert.Equal(t, "John", profile.Name.First)
				assert.Equal(t, "A", profile.Name.Middle)
				assert.Equal(t, "Doe", profile.Name.Last)
				assert.Equal(t, "Johnny", profile.Name.Nickname)
				require.NotNil(t, profile.Email)
				assert.Equal(t, "john@example.com", profile.Email.Value)
				assert.True(t, profile.Email.Verified)
				assert.Equal(t, "https://example.com/picture.jpg", profile.Picture)
				assert.Equal(t, "en-US", profile.Locale)
				assert.Equal(t, "America/New_York", profile.Timezone)
			},
		},
		{
			name: "minimal token with subject",
			setupToken: func() openid.Token {
				builder := openid.NewBuilder()
				builder.Subject("user456")
				token, _ := builder.Build()
				return token
			},
			validate: func(t *testing.T, profile *Profile) {
				assert.Equal(t, "user456", profile.ID)
				assert.Empty(t, profile.Name.FullName)
				assert.Nil(t, profile.Email)
			},
		},
		{
			name: "token with ID claim instead of subject",
			setupToken: func() openid.Token {
				token, _ := openid.NewBuilder().Claim("id", "user789").Build()
				return openid.Token(token)
			},
			validate: func(t *testing.T, profile *Profile) {
				assert.Equal(t, "user789", profile.ID)
			},
		},
		{
			name: "token without sub or id",
			setupToken: func() openid.Token {
				token, _ := openid.NewBuilder().Name("No ID User").Build()
				return token
			},
			expectedError: true,
		},
		{
			name: "token with non-standard email verification",
			setupToken: func() openid.Token {
				token, _ := openid.NewBuilder().
					Subject("user101").
					Claim("email", "user@example.com").
					Claim("verified_email", true).
					Build()
				return openid.Token(token)
			},
			validate: func(t *testing.T, profile *Profile) {
				require.NotNil(t, profile.Email)
				assert.Equal(t, "user@example.com", profile.Email.Value)
				assert.True(t, profile.Email.Verified)
			},
		},
		{
			name: "token with name parts but no full name",
			setupToken: func() openid.Token {
				builder := openid.NewBuilder()
				builder.Subject("user202")
				builder.GivenName("Jane")
				builder.FamilyName("Smith")
				token, _ := builder.Build()
				return token
			},
			validate: func(t *testing.T, profile *Profile) {
				assert.Equal(t, "Jane Smith", profile.Name.FullName)
				assert.Equal(t, "Jane", profile.Name.First)
				assert.Equal(t, "Smith", profile.Name.Last)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.setupToken()
			profile, err := NewProfileFromOpenIDToken(token, "")

			if tc.expectedError {
				require.Error(t, err)
				assert.Nil(t, profile)
			} else {
				require.NoError(t, err)
				require.NotNil(t, profile)

				if tc.validate != nil {
					tc.validate(t, profile)
				}
			}
		})
	}
}

func TestGetAs(t *testing.T) {
	profile := &Profile{
		Provider: "test",
		ID:       "user123",
		Name:     ProfileName{FullName: "John Doe"},
		Email:    &ProfileEmail{Value: "john@example.com", Verified: true},
		Groups:   []string{"group1", "group2"},
		AdditionalClaims: map[string]any{
			"str": "hello",
			"int": 42,
		},
	}

	t.Run("known claim of matching type", func(t *testing.T) {
		val, ok := GetAs[string](profile, "email")
		assert.True(t, ok)
		assert.Equal(t, "john@example.com", val)

		verified, ok := GetAs[bool](profile, "email_verified")
		assert.True(t, ok)
		assert.True(t, verified)

		groups, ok := GetAs[[]string](profile, "groups")
		assert.True(t, ok)
		assert.Equal(t, []string{"group1", "group2"}, groups)
	})

	t.Run("additional claim of matching type", func(t *testing.T) {
		str, ok := GetAs[string](profile, "str")
		assert.True(t, ok)
		assert.Equal(t, "hello", str)

		num, ok := GetAs[int](profile, "int")
		assert.True(t, ok)
		assert.Equal(t, 42, num)
	})

	t.Run("claim of different type", func(t *testing.T) {
		// Values are not converted, so the type must match exactly
		val, ok := GetAs[bool](profile, "email")
		assert.False(t, ok)
		assert.False(t, val)

		num, ok := GetAs[int64](profile, "int")
		assert.False(t, ok)
		assert.Zero(t, num)
	})

	t.Run("claim not found", func(t *testing.T) {
		val, ok := GetAs[string](profile, "not-found")
		assert.False(t, ok)
		assert.Empty(t, val)
	})

	t.Run("known claim with empty value", func(t *testing.T) {
		// Claims that are always present in the profile are returned even if empty
		val, ok := GetAs[string](profile, "nickname")
		assert.True(t, ok)
		assert.Empty(t, val)
	})

	t.Run("email_verified without email", func(t *testing.T) {
		noEmail := &Profile{ID: "user456"}
		val, ok := GetAs[bool](noEmail, "email_verified")
		assert.False(t, ok)
		assert.False(t, val)
	})
}

func TestGetStringMatchesGetAs(t *testing.T) {
	// getAsStringReference is the implementation GetAs[string] had before GetString existed
	getAsStringReference := func(p *Profile, claim string) (val string, ok bool) {
		v := p.Get(claim)
		if v == nil {
			return "", false
		}
		val, ok = v.(string)
		if ok {
			return val, true
		}
		return cast.ToString(v), true
	}

	profiles := map[string]*Profile{
		"full": {
			Provider: "testoauth2",
			ID:       "user123",
			Name:     ProfileName{FullName: "John Doe", Nickname: "johnd", First: "John", Middle: "Q", Last: "Doe"},
			Email:    &ProfileEmail{Value: "john@example.com", Verified: true},
			Picture:  "https://example.com/avatar.jpg",
			Locale:   "en-US",
			Timezone: "America/New_York",
			Groups:   []string{"admins", "users"},
			Roles:    []string{"admin", "editor"},
			AdditionalClaims: map[string]any{
				"dept":     "eng",
				"level":    7,
				"active":   true,
				"ratio":    1.5,
				"tags":     []string{"a", "b"},
				"explicit": nil,
			},
		},
		"empty": {},
		"unverified email": {
			Email: &ProfileEmail{Value: "nobody@example.com", Verified: false},
		},
	}

	claims := []string{
		"provider", "id", "sub", "name", "given_name", "middle_name", "family_name",
		"nickname", "email", "email_verified", "picture", "locale", "zoneinfo",
		"groups", "roles",
		"dept", "level", "active", "ratio", "tags", "explicit", "missing", "",
	}

	for profileName, p := range profiles {
		for _, claim := range claims {
			t.Run(profileName+"/"+claim, func(t *testing.T) {
				wantVal, wantOk := getAsStringReference(p, claim)

				gotVal, gotOk := p.GetString(claim)
				assert.Equal(t, wantOk, gotOk, "GetString ok")
				assert.Equal(t, wantVal, gotVal, "GetString value")

				// GetAs[string] must agree too, since it now goes through GetString
				asVal, asOk := GetAs[string](p, claim)
				assert.Equal(t, wantOk, asOk, "GetAs ok")
				assert.Equal(t, wantVal, asVal, "GetAs value")
			})
		}
	}
}

func TestGetStringDoesNotAllocate(t *testing.T) {
	p := &Profile{ID: "user123", Name: ProfileName{FullName: "John Doe"}}

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = p.GetString("id")
		_, _ = GetAs[string](p, "name")
	})

	assert.Zero(t, allocs, "reading string claims should not allocate")
}
