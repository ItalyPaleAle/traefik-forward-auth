package conditions

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cast"
	"github.com/vulcand/predicate"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

type UserProfilePredicate func(p *user.Profile) bool

var parser predicate.Parser

func init() {
	var err error
	parser, err = predicate.NewParser(predicate.Def{
		// Allows passing true and false as booleans, unquoted
		GetIdentifier: getIdentifier,
		Operators: predicate.Operators{
			AND: and,
			OR:  or,
			NOT: not,
		},
		Functions: map[string]any{
			"Equal":         equal,
			"Eq":            equal,
			"Contains":      contains,
			"Group":         group,
			"Role":          role,
			"EmailVerified": emailVerified,
		},
	})

	if err != nil {
		// Indicates a development-time error
		panic("failed to init parser: " + err.Error())
	}
}

func NewPredicate(in string) (UserProfilePredicate, error) {
	pr, err := parser.Parse(in)
	if err != nil {
		return nil, fmt.Errorf("failed to parse condition: %w", err)
	}

	uppr, _ := pr.(UserProfilePredicate)
	return uppr, nil
}

func getIdentifier(selector []string) (any, error) {
	// We only support selectors with a single property
	if len(selector) != 1 {
		return nil, errors.New("invalid selector")
	}

	switch selector[0] {
	case "true", "false":
		return selector[0], nil
	default:
		return nil, errors.New("invalid selector")
	}
}

func not(a UserProfilePredicate) UserProfilePredicate {
	return func(p *user.Profile) bool {
		return !a(p)
	}
}

func and(a, b UserProfilePredicate) UserProfilePredicate {
	return func(p *user.Profile) bool {
		return a(p) && b(p)
	}
}

func or(a, b UserProfilePredicate) UserProfilePredicate {
	return func(p *user.Profile) bool {
		return a(p) || b(p)
	}
}

// equal checks if the claim has the expected value
// This only works for strings or stringifiable values
func equal(claimAny any, expected any) UserProfilePredicate {
	return func(p *user.Profile) bool {
		claim, ok := claimAny.(string)
		if !ok {
			return false
		}

		// By using ToStringE, we can return false if the current value is not stringifiable, e.g. it's a slice
		cur, err := cast.ToStringE(p.Get(claim))
		if err != nil {
			return false
		}

		return cur == cast.ToString(expected)
	}
}

// contains checks if a claim that is a slice contains the given value
// If the claim is a string, it's converted to a slice separated by spaces
// This only works for values and slice elements that are strings or stringifiable
func contains(claimAny any, expected any) UserProfilePredicate {
	return func(p *user.Profile) bool {
		claim, ok := claimAny.(string)
		if !ok {
			return false
		}

		cur := cast.ToStringSlice(p.Get(claim))
		return slices.Contains(cur, cast.ToString(expected))
	}
}

// group checks if the user has the specified group
func group(groupIn any) UserProfilePredicate {
	return func(p *user.Profile) bool {
		group := cast.ToString(groupIn)
		if group == "" {
			return false
		}

		return slices.Contains(p.Groups, group)
	}
}

// role checks if the user has the specified role
func role(roleIn any) UserProfilePredicate {
	return func(p *user.Profile) bool {
		role := cast.ToString(roleIn)
		if role == "" {
			return false
		}

		return slices.Contains(p.Roles, role)
	}
}

func emailVerified() UserProfilePredicate {
	return func(p *user.Profile) bool {
		return p.Email != nil && p.Email.Value != "" && p.Email.Verified
	}
}
