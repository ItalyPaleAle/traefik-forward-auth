package user

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt/openid"
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
			profile, err := NewProfileFromOpenIDToken(token)

			if tc.expectedError {
				assert.Error(t, err)
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
