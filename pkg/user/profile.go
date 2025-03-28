package user

import (
	"errors"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/spf13/cast"
)

// Profile is a struct that represents a user's profile.
type Profile struct {
	// ID of the user
	ID string
	// Name
	Name ProfileName
	// Email address
	Email *ProfileEmail
	// URL of the user's picture
	Picture string
	// End user's locale, as a string (e.g. "en" or "fr-FR" or "de_DE")
	Locale string
	// Time zone name
	Timezone string

	// Additional claims
	AdditionalClaims map[string]string
}

// ProfileName contains the name of a user.
type ProfileName struct {
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

// ProfileEmail contains the email of a user.
type ProfileEmail struct {
	// Email address
	Value string
	// True if the email address is verified
	Verified bool
}

// NewProfileFromOpenIDToken returns a new Profile with values from an openid.Token object
func NewProfileFromOpenIDToken(token openid.Token) (*Profile, error) {
	profile := Profile{
		Picture:  token.Picture(),
		Locale:   token.Locale(),
		Timezone: token.Zoneinfo(),
	}

	// At least one of sub or id are required
	profile.ID = token.Subject()
	if profile.ID == "" {
		idAny, ok := token.Get("id")
		if ok {
			id := cast.ToString(idAny)
			if id != "" {
				profile.ID = id
			}
		}
	}
	if profile.ID == "" {
		return nil, errors.New("at least one of sub or id must be present")
	}

	// Name
	profile.Name = ProfileName{
		FullName: token.Name(),
		First:    token.GivenName(),
		Middle:   token.MiddleName(),
		Last:     token.FamilyName(),
		Nickname: token.Nickname(),
	}

	profile.Name.PopulateFullName()

	email := token.Email()
	if email != "" {
		verified := token.EmailVerified()
		if !verified {
			v, _ := token.Get("verified_email")
			if v != "" {
				verified = cast.ToBool(v)
			}
		}

		profile.Email = &ProfileEmail{
			Value:    email,
			Verified: verified,
		}
	}

	return &profile, nil
}

// NewProfileFromClaims returns a new Profile with values from a claim map
func NewProfileFromClaims(claims map[string]any) (*Profile, error) {
	profile := &Profile{
		Picture:  cast.ToString(claims["picture"]),
		Locale:   cast.ToString(claims["locale"]),
		Timezone: cast.ToString(claims["zoneinfo"]),
	}

	// At least one of sub or id are required
	profile.ID = cast.ToString(claims["sub"])
	if profile.ID == "" {
		id := cast.ToString(claims["id"])
		if id != "" {
			profile.ID = id
		}
	}
	if profile.ID == "" {
		return profile, errors.New("at least one of sub or id must be present")
	}

	// Name
	profile.Name = ProfileName{
		FullName: cast.ToString(claims["name"]),
		First:    cast.ToString(claims["given_name"]),
		Middle:   cast.ToString(claims["middle_name"]),
		Last:     cast.ToString(claims["family_name"]),
		Nickname: cast.ToString(claims["nickname"]),
	}

	profile.Name.PopulateFullName()

	email := cast.ToString(claims["email"])
	if email != "" {
		profile.Email = &ProfileEmail{
			Value:    email,
			Verified: cast.ToBool(claims["email_verified"]) || cast.ToBool(claims["verified_email"]),
		}
	}

	return profile, nil
}

// GetEmail returns the email address of the user if present, with nil-checks
func (p *Profile) GetEmail() string {
	if p.Email == nil {
		return ""
	}
	return p.Email.Value
}

// AppendClaims appends the claims for this user profile to a JWT builder
func (p *Profile) AppendClaims(builder *jwt.Builder) {
	builder.Subject(p.ID)
	if p.Name.FullName != "" {
		builder.Claim("name", p.Name.FullName)
	}
	if p.Name.First != "" {
		builder.Claim("given_name", p.Name.First)
	}
	if p.Name.Middle != "" {
		builder.Claim("middle_name", p.Name.Middle)
	}
	if p.Name.Last != "" {
		builder.Claim("family_name", p.Name.Last)
	}
	if p.Name.Nickname != "" {
		builder.Claim("nickname", p.Name.Nickname)
	}
	if p.Email != nil && p.Email.Value != "" {
		builder.Claim("email", p.Email.Value)
		if p.Email.Verified {
			builder.Claim("email_verified", p.Email.Verified)
		}
	}
	if p.Picture != "" {
		builder.Claim("picture", p.Picture)
	}
	if p.Locale != "" {
		builder.Claim("locale", p.Locale)
	}
	if p.Timezone != "" {
		builder.Claim("zoneinfo", p.Timezone)
	}

	for k, v := range p.AdditionalClaims {
		builder.Claim(k, v)
	}
}

func (p *Profile) SetAdditionalClaim(key, val string) {
	if p.AdditionalClaims == nil {
		p.AdditionalClaims = make(map[string]string)
	}
	p.AdditionalClaims[key] = val
}

// PopulateFullName builds the full name if it's not set but there are other fields
func (n *ProfileName) PopulateFullName() {
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
