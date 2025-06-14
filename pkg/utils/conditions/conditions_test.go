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
		{name: "matches exact claim", condition: `ClaimEqual("id", "user1234")`, want: true},
		{name: "does not match exact claim", condition: `ClaimEqual("id", "bad")`, want: false},
		{name: "match AND claims", condition: `ClaimEqual("id", "user1234") && ClaimEqual("location", "earth")`, want: true},
		{name: "does not match AND claims", condition: `ClaimEqual("id", "bad") && ClaimEqual("location", "earth")`, want: false},
		{name: "matches OR claims", condition: `ClaimEqual("id", "bad") || ClaimEqual("location", "earth")`, want: true},
		{name: "does not match OR claims", condition: `ClaimEqual("id", "bad") || ClaimEqual("location", "bad")`, want: false},
		{name: "has group", condition: `Group("g1")`, want: true},
		{name: "does not have group", condition: `Group("no")`, want: false},
		{name: "has role", condition: `Role("r1")`, want: true},
		{name: "does not have role", condition: `Role("admin")`, want: false},
		{name: "email is verified", condition: `EmailVerified()`, want: true},
		{name: "claim not equal", condition: `!ClaimEqual("id", "other")`, want: true},
		{name: "claim contains", condition: `ClaimContains("groups", "g1")`, want: true},
		{name: "claim does not contain", condition: `ClaimContains("groups", "g3")`, want: false},
		{name: "complex condition with NOT", condition: `!(ClaimEqual("id", "bad")) && EmailVerified()`, want: true},
		{name: "complex condition with groups and roles", condition: `Group("g1") && Role("r2")`, want: true},
		{name: "complex condition with boolean claims", condition: `ClaimEqual("is_admin", "false") && ClaimEqual("is_user", "true")`, want: true},
		{name: "nested boolean expressions", condition: `((ClaimEqual("id", "user1234") || ClaimEqual("name", "wrong")) && (ClaimEqual("location", "earth")))`, want: true},
		{name: "empty group check", condition: `Group("")`, want: false},
		{name: "empty role check", condition: `Role("")`, want: false},
		{name: "checking multiple groups", condition: `Group("g1") && Group("g2")`, want: true},
		{name: "checking one of multiple groups", condition: `Group("g1") || Group("g3")`, want: true},
		{name: "checking none of multiple groups", condition: `Group("g3") || Group("g4")`, want: false},
		{name: "contains with spaces", condition: `ClaimContains("name", "Pinco")`, want: true},
		{name: "complex nested expressions", condition: `(Group("g1") || Group("g3")) && (Role("r1") || Role("r3"))`, want: true},
		{name: "multiple NOT operators", condition: `!(!(Group("g1")))`, want: true},
		{name: "combining EmailVerified with other conditions", condition: `EmailVerified() && ClaimEqual("id", "user1234")`, want: true},
		{name: "combining EmailVerified with groups", condition: `EmailVerified() && Group("g1")`, want: true},
		{name: "complex condition with multiple ANDs", condition: `ClaimEqual("id", "user1234") && ClaimEqual("location", "earth") && Role("r1")`, want: true},
		{name: "complex condition with multiple ORs", condition: `ClaimEqual("id", "bad") || ClaimEqual("location", "bad") || Role("r1")`, want: true},
		{name: "mixed AND and OR precedence", condition: `ClaimEqual("id", "user1234") && ClaimEqual("location", "bad") || Role("r1")`, want: true},
		{name: "precedence with parentheses", condition: `(ClaimEqual("id", "user1234") && ClaimEqual("location", "bad")) || Role("r1")`, want: true},
		{name: "different precedence", condition: `ClaimEqual("id", "user1234") && (ClaimEqual("location", "bad") || Role("r1"))`, want: true},
		{name: "case sensitive equality", condition: `ClaimEqual("name", "pinco pallino")`, want: false},
		{name: "equality with numbers in string", condition: `ClaimEqual("id", "user1234")`, want: true},
		{name: "comparing non-existent claim", condition: `ClaimEqual("non_existent", "something")`, want: false},
		{name: "equality with boolean", condition: `ClaimEqual("is_admin", false)`, want: true},
		{name: "equality with boolean as string", condition: `ClaimEqual("is_admin", "false")`, want: true},
		{name: "inequality with boolean", condition: `!ClaimEqual("is_admin", true)`, want: true},
		{name: "inequality with boolean as string", condition: `!ClaimEqual("is_admin", "true")`, want: true},
		{name: "email check with complex condition", condition: `EmailVerified() && Role("r1") && ClaimEqual("name", "Pinco Pallino")`, want: true},
		{name: "contains function in complex expression", condition: `ClaimContains("groups", "g1") && !ClaimContains("groups", "g3")`, want: true},
		{name: "triple nested parentheses", condition: `(((Group("g1"))))`, want: true},
		{name: "various operators in single expression", condition: `!(ClaimEqual("id", "bad")) && (EmailVerified() || Group("non-existent"))`, want: true},
		{name: "condition with four function calls", condition: `Group("g1") && Role("r1") && EmailVerified() && ClaimContains("name", "Pinco")`, want: true},
		{name: "using Eq instead of Equal", condition: `Eq("id", "user1234")`, want: true},
		{name: "using Cont instead of Contains", condition: `Cont("groups", "g1")`, want: true},
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
			condition: `ClaimContains("groups", "admins")`,
			want:      true,
		},
		{
			name: "does not contain in array",
			profile: &user.Profile{
				Groups: []string{"users", "developers"},
			},
			condition: `ClaimContains("groups", "admins")`,
			want:      false,
		},
		{
			name: "empty array",
			profile: &user.Profile{
				Groups: []string{},
			},
			condition: `ClaimContains("groups", "admins")`,
			want:      false,
		},
		{
			name: "nil array",
			profile: &user.Profile{
				Groups: nil,
			},
			condition: `ClaimContains("groups", "admins")`,
			want:      false,
		},
		{
			name: "contains in string",
			profile: &user.Profile{
				Name: user.ProfileName{
					FullName: "John Smith",
				},
			},
			condition: `ClaimContains("name", "John")`,
			want:      true,
		},
		{
			name: "case sensitive in string",
			profile: &user.Profile{
				Name: user.ProfileName{
					FullName: "John Smith",
				},
			},
			condition: `ClaimContains("name", "john")`,
			want:      false, // Case sensitive match
		},
		{
			name: "contains with additional claims",
			profile: &user.Profile{
				AdditionalClaims: map[string]any{
					"tags": []string{"important", "featured"},
				},
			},
			condition: `ClaimContains("tags", "featured")`,
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
			condition:   `ClaimEqual("id", "test"`,
			expectedErr: "missing ',' before newline in argument list",
		},
		{
			name:        "unquoted string identifier",
			condition:   `ClaimEqual(id, "test")`,
			expectedErr: "invalid selector",
		},
		{
			name:        "unsupported function",
			condition:   `NotExistingFunction("id")`,
			expectedErr: "unsupported function",
		},
		{
			name:        "wrong number of arguments",
			condition:   `ClaimEqual("id")`,
			expectedErr: "Call with too few input arguments",
		},
		{
			name:        "invalid boolean expression",
			condition:   `ClaimEqual("id", "test") &&`,
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
