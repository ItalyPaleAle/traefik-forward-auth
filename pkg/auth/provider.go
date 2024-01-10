package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/spf13/cast"
)

// Provider is an interface that represents an auth provider.
type Provider interface {
	// GetProviderName returns the name of the provider
	GetProviderName() string
	// AuthorizeURL returns the URL where to redirect users to for authorization.
	AuthorizeURL(state string, redirectURL string) (string, error)
	// ExchangeCode an authorization code for an access token
	ExchangeCode(ctx context.Context, code string, redirectURL string) (AccessToken, error)
	// RetrieveProfile retrieves the user's profile, using the id_token (if present) or requesting it from the user info endpoint.
	RetrieveProfile(ctx context.Context, at AccessToken) (UserProfile, error)
}

// UserProfile is a struct that represents a user's profile.
type UserProfile struct {
	// ID of the user
	ID string
	// Name
	Name UserProfileName
	// Email address
	Email *UserProfileEmail
	// URL of the user's picture
	Picture string
	// End user's locale, as a string (e.g. "en" or "fr-FR" or "de_DE")
	Locale string
	// Time zone name
	Timezone string
}

// UserProfileName contains the name of a user.
type UserProfileName struct {
	// Full name to display
	FullName string
	// First name
	First string
	// Last name
	Last string
	// Middle name
	Middle string
	// Nickname
	Nickname string
}

// UserProfileEmail contains the email of a user.
type UserProfileEmail struct {
	// Email address
	Value string
	// True if the email address is verified
	Verified bool
}

// NewUserProfileFromOpenIDToken returns a new UserProfile with values from an openid.Token object
func NewUserProfileFromOpenIDToken(token openid.Token) (UserProfile, error) {
	userProfile := UserProfile{
		Picture:  token.Picture(),
		Locale:   token.Locale(),
		Timezone: token.Zoneinfo(),
	}

	// At least one of sub or id are required
	userProfile.ID = token.Subject()
	if userProfile.ID == "" {
		idAny, ok := token.Get("id")
		if ok {
			id := cast.ToString(idAny)
			if id != "" {
				userProfile.ID = id
			}
		}
	}
	if userProfile.ID == "" {
		return userProfile, errors.New("at least one of sub or id must be present")
	}

	// Name
	userProfile.Name = UserProfileName{
		FullName: token.Name(),
		First:    token.GivenName(),
		Middle:   token.MiddleName(),
		Last:     token.FamilyName(),
		Nickname: token.Nickname(),
	}

	userProfile.Name.PopulateFullName()

	email := token.Email()
	if email != "" {
		verified := token.EmailVerified()
		if !verified {
			v, _ := token.Get("verified_email")
			if v != "" {
				verified = cast.ToBool(v)
			}
		}

		userProfile.Email = &UserProfileEmail{
			Value:    email,
			Verified: verified,
		}
	}

	return userProfile, nil
}

// NewUserProfileFromClaims returns a new UserProfile with values from a claim map
func NewUserProfileFromClaims(claims map[string]any) (UserProfile, error) {
	userProfile := UserProfile{
		Picture:  cast.ToString(claims["picture"]),
		Locale:   cast.ToString(claims["locale"]),
		Timezone: cast.ToString(claims["zoneinfo"]),
	}

	// At least one of sub or id are required
	userProfile.ID = cast.ToString(claims["sub"])
	if userProfile.ID == "" {
		id := cast.ToString(claims["id"])
		if id != "" {
			userProfile.ID = id
		}
	}
	if userProfile.ID == "" {
		return userProfile, errors.New("at least one of sub or id must be present")
	}

	// Name
	userProfile.Name = UserProfileName{
		FullName: cast.ToString(claims["name"]),
		First:    cast.ToString(claims["given_name"]),
		Middle:   cast.ToString(claims["middle_name"]),
		Last:     cast.ToString(claims["family_name"]),
		Nickname: cast.ToString(claims["nickname"]),
	}

	userProfile.Name.PopulateFullName()

	email := cast.ToString(claims["email"])
	if email != "" {
		userProfile.Email = &UserProfileEmail{
			Value:    email,
			Verified: cast.ToBool(claims["email_verified"]) || cast.ToBool(claims["verified_email"]),
		}
	}

	return userProfile, nil
}

// PopulateFullName builds the full name if it's not set but there are other fields
func (n *UserProfileName) PopulateFullName() {
	if n.FullName != "" {
		return
	}

	// If there's a nickname, prefer that
	if n.Nickname != "" {
		n.FullName = n.Nickname
		return
	}

	// Build the full name as first + middle + last
	parts := make([]string, 0, 3)
	if n.First != "" {
		parts = append(parts, n.First)
	}
	if n.Middle != "" {
		parts = append(parts, n.Middle)
	}
	if n.Last != "" {
		parts = append(parts, n.Last)
	}
	if len(parts) > 0 {
		n.FullName = strings.Join(parts, " ")
	}
}

// AccessToken is a struct that represents an access token.
type AccessToken struct {
	Provider     string
	AccessToken  string
	Expires      time.Time
	IDToken      string
	RefreshToken string
	Scopes       []string
}
