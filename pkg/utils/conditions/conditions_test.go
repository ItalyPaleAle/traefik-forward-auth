package conditions

import (
	"testing"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditions(t *testing.T) {
	profile := &user.Profile{
		ID: "user1234",
		Name: user.ProfileName{
			FullName: "Pinco Pallino",
			Nickname: "Anyone",
			First:    "Pinco",
			Middle:   "Noone",
			Last:     "Pallino",
		},
		Email: &user.ProfileEmail{
			Verified: true,
			Value:    "pinco@example.com",
		},
		Groups: []string{"g1", "g2"},
		Roles:  []string{"r1", "r2"},
		AdditionalClaims: map[string]any{
			"location": "earth",
			"is_admin": false,
			"is_user":  true,
		},
	}

	tests := []struct {
		name      string
		condition string
		want      bool
	}{
		{name: "matches exact claim", condition: `Equal("id", "user1234")`, want: true},
		{name: "does not match exact claim", condition: `Equal("id", "bad")`, want: false},
		{name: "match AND claims", condition: `Equal("id", "user1234") && Equal("location", "earth")`, want: true},
		{name: "does not match AND claims", condition: `Equal("id", "bad") && Equal("location", "earth")`, want: false},
		{name: "matches OR claims", condition: `Equal("id", "bad") || Equal("location", "earth")`, want: true},
		{name: "does not match OR claims", condition: `Equal("id", "bad") || Equal("location", "bad")`, want: false},
		{name: "has group", condition: `Group("g1")`, want: true},
		{name: "does not have group", condition: `Group("no")`, want: false},
		{name: "has role", condition: `Role("r1")`, want: true},
		{name: "does not have role", condition: `Role("admin")`, want: false},
		{name: "email is verified", condition: `EmailVerified()`, want: true},
		{name: "claim not equal", condition: `!Equal("id", "other")`, want: true},
		{name: "claim contains", condition: `Contains("groups", "g1")`, want: true},
		{name: "claim does not contain", condition: `Contains("groups", "g3")`, want: false},
		{name: "complex condition with NOT", condition: `!(Equal("id", "bad")) && EmailVerified()`, want: true},
		{name: "complex condition with groups and roles", condition: `Group("g1") && Role("r2")`, want: true},
		{name: "complex condition with boolean claims", condition: `Equal("is_admin", "false") && Equal("is_user", "true")`, want: true},
		{name: "nested boolean expressions", condition: `((Equal("id", "user1234") || Equal("name", "wrong")) && (Equal("location", "earth")))`, want: true},
		{name: "empty group check", condition: `Group("")`, want: false},
		{name: "empty role check", condition: `Role("")`, want: false},
		{name: "checking multiple groups", condition: `Group("g1") && Group("g2")`, want: true},
		{name: "checking one of multiple groups", condition: `Group("g1") || Group("g3")`, want: true},
		{name: "checking none of multiple groups", condition: `Group("g3") || Group("g4")`, want: false},
		{name: "contains with spaces", condition: `Contains("name", "Pinco")`, want: true},
		{name: "complex nested expressions", condition: `(Group("g1") || Group("g3")) && (Role("r1") || Role("r3"))`, want: true},
		{name: "multiple NOT operators", condition: `!(!(Group("g1")))`, want: true},
		{name: "combining EmailVerified with other conditions", condition: `EmailVerified() && Equal("id", "user1234")`, want: true},
		{name: "combining EmailVerified with groups", condition: `EmailVerified() && Group("g1")`, want: true},
		{name: "complex condition with multiple ANDs", condition: `Equal("id", "user1234") && Equal("location", "earth") && Role("r1")`, want: true},
		{name: "complex condition with multiple ORs", condition: `Equal("id", "bad") || Equal("location", "bad") || Role("r1")`, want: true},
		{name: "mixed AND and OR precedence", condition: `Equal("id", "user1234") && Equal("location", "bad") || Role("r1")`, want: true},
		{name: "precedence with parentheses", condition: `(Equal("id", "user1234") && Equal("location", "bad")) || Role("r1")`, want: true},
		{name: "different precedence", condition: `Equal("id", "user1234") && (Equal("location", "bad") || Role("r1"))`, want: true},
		{name: "case sensitive equality", condition: `Equal("name", "pinco pallino")`, want: false},
		{name: "equality with numbers in string", condition: `Equal("id", "user1234")`, want: true},
		{name: "comparing non-existent claim", condition: `Equal("non_existent", "something")`, want: false},
		{name: "equality with boolean", condition: `Equal("is_admin", false)`, want: true},
		{name: "equality with boolean as string", condition: `Equal("is_admin", "false")`, want: true},
		{name: "inequality with boolean", condition: `!Equal("is_admin", true)`, want: true},
		{name: "inequality with boolean as string", condition: `!Equal("is_admin", "true")`, want: true},
		{name: "email check with complex condition", condition: `EmailVerified() && Role("r1") && Equal("name", "Pinco Pallino")`, want: true},
		{name: "contains function in complex expression", condition: `Contains("groups", "g1") && !Contains("groups", "g3")`, want: true},
		{name: "triple nested parentheses", condition: `(((Group("g1"))))`, want: true},
		{name: "various operators in single expression", condition: `!(Equal("id", "bad")) && (EmailVerified() || Group("non-existent"))`, want: true},
		{name: "condition with four function calls", condition: `Group("g1") && Role("r1") && EmailVerified() && Contains("name", "Pinco")`, want: true},
		{name: "using Eq instead of Equal", condition: `Eq("id", "user1234")`, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate, err := NewPredicate(tt.condition)
			require.NoError(t, err)

			result := predicate(profile)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEmailVerified(t *testing.T) {
	tests := []struct {
		name    string
		profile *user.Profile
		want    bool
	}{
		{
			name: "verified email",
			profile: &user.Profile{
				Email: &user.ProfileEmail{
					Value:    "test@example.com",
					Verified: true,
				},
			},
			want: true,
		},
		{
			name: "unverified email",
			profile: &user.Profile{
				Email: &user.ProfileEmail{
					Value:    "test@example.com",
					Verified: false,
				},
			},
			want: false,
		},
		{
			name: "no email",
			profile: &user.Profile{
				Email: nil,
			},
			want: false,
		},
		{
			name: "empty email",
			profile: &user.Profile{
				Email: &user.ProfileEmail{
					Value:    "",
					Verified: true,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate, err := NewPredicate("EmailVerified()")
			require.NoError(t, err)

			result := predicate(tt.profile)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestContainsFunction(t *testing.T) {
	tests := []struct {
		name      string
		profile   *user.Profile
		condition string
		want      bool
	}{
		{
			name: "contains in array",
			profile: &user.Profile{
				Groups: []string{"users", "admins", "developers"},
			},
			condition: `Contains("groups", "admins")`,
			want:      true,
		},
		{
			name: "does not contain in array",
			profile: &user.Profile{
				Groups: []string{"users", "developers"},
			},
			condition: `Contains("groups", "admins")`,
			want:      false,
		},
		{
			name: "empty array",
			profile: &user.Profile{
				Groups: []string{},
			},
			condition: `Contains("groups", "admins")`,
			want:      false,
		},
		{
			name: "nil array",
			profile: &user.Profile{
				Groups: nil,
			},
			condition: `Contains("groups", "admins")`,
			want:      false,
		},
		{
			name: "contains in string",
			profile: &user.Profile{
				Name: user.ProfileName{
					FullName: "John Smith",
				},
			},
			condition: `Contains("name", "John")`,
			want:      true,
		},
		{
			name: "case sensitive in string",
			profile: &user.Profile{
				Name: user.ProfileName{
					FullName: "John Smith",
				},
			},
			condition: `Contains("name", "john")`,
			want:      false, // Case sensitive match
		},
		{
			name: "contains with additional claims",
			profile: &user.Profile{
				AdditionalClaims: map[string]any{
					"tags": []string{"important", "featured"},
				},
			},
			condition: `Contains("tags", "featured")`,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate, err := NewPredicate(tt.condition)
			require.NoError(t, err)

			result := predicate(tt.profile)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestNewPredicateFailure(t *testing.T) {
	tests := []struct {
		name        string
		condition   string
		expectedErr string
	}{
		{
			name:        "invalid syntax with missing parenthesis",
			condition:   `Equal("id", "test"`,
			expectedErr: "missing ',' before newline in argument list",
		},
		{
			name:        "unquoted string identifier",
			condition:   `Equal(id, "test")`,
			expectedErr: "invalid selector",
		},
		{
			name:        "unsupported function",
			condition:   `NotExistingFunction("id")`,
			expectedErr: "unsupported function",
		},
		{
			name:        "wrong number of arguments",
			condition:   `Equal("id")`,
			expectedErr: "Call with too few input arguments",
		},
		{
			name:        "invalid boolean expression",
			condition:   `Equal("id", "test") &&`,
			expectedErr: "expected operand, found 'EOF'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			predicate, err := NewPredicate(tt.condition)
			require.Error(t, err)
			assert.Nil(t, predicate)
			assert.ErrorContains(t, err, tt.expectedErr)
		})
	}
}
