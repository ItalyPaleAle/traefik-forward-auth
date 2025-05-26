package server

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"
)

// RouteGetProfile is the handler for GET /profile
// This handler serves the profile of authenticated users in clear-text
func (s *Server) RouteGetProfile(c *gin.Context) {
	// Check if we have a session
	profile, _ := s.getProfileFromContext(c)
	if profile == nil {
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
		return
	}

	// If we are here, we have a valid session
	// Return all claims in the token to the user
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Status(http.StatusOK)

	fmt.Fprint(c.Writer, "Authenticated\n\n")
	fmt.Fprint(c.Writer, "Provider: "+profile.Provider+"\n")
	fmt.Fprint(c.Writer, "ID: "+profile.ID+"\n")
	fmt.Fprint(c.Writer, "Name:\n")
	fmt.Fprint(c.Writer, "   Full Name: "+profile.Name.FullName+"\n")
	if profile.Name.Nickname != "" {
		fmt.Fprint(c.Writer, "   Nickname: "+profile.Name.Nickname+"\n")
	}
	if profile.Name.First != "" {
		fmt.Fprint(c.Writer, "   First: "+profile.Name.First+"\n")
	}
	if profile.Name.Middle != "" {
		fmt.Fprint(c.Writer, "   Middle: "+profile.Name.Middle+"\n")
	}
	if profile.Name.Last != "" {
		fmt.Fprint(c.Writer, "   Last: "+profile.Name.Last+"\n")
	}
	if profile.Email != nil {
		fmt.Fprint(c.Writer, "Email:\n")
		fmt.Fprint(c.Writer, "   Address: "+profile.Email.Value+"\n")
		if profile.Email.Verified {
			fmt.Fprint(c.Writer, "   Verified: true\n")
		}
	}
	if profile.Picture != "" {
		fmt.Fprint(c.Writer, "Picture: "+profile.Picture+"\n")
	}
	if profile.Locale != "" {
		fmt.Fprint(c.Writer, "Locale: "+profile.Locale+"\n")
	}
	if profile.Timezone != "" {
		fmt.Fprint(c.Writer, "Timezone: "+profile.Timezone+"\n")
	}

	switch {
	case len(profile.Groups) > 1:
		fmt.Fprint(c.Writer, "Groups:\n")
		for _, v := range profile.Groups {
			fmt.Fprint(c.Writer, "  - "+v+"\n")
		}
	case len(profile.Groups) == 1:
		fmt.Fprint(c.Writer, "Group: "+profile.Groups[0]+"\n")
	}

	switch {
	case len(profile.Roles) > 1:
		fmt.Fprint(c.Writer, "Roles:\n")
		for _, v := range profile.Roles {
			fmt.Fprint(c.Writer, "  - "+v+"\n")
		}
	case len(profile.Roles) == 1:
		fmt.Fprint(c.Writer, "Role: "+profile.Roles[0]+"\n")
	}

	if len(profile.AdditionalClaims) > 0 {
		fmt.Fprint(c.Writer, "Additional claims:\n")
		for k, v := range profile.AdditionalClaims {
			if reflect.TypeOf(v).Kind() == reflect.Slice {
				vs := cast.ToStringSlice(v)
				switch {
				case len(vs) > 1:
					fmt.Fprint(c.Writer, "   "+k+":\n")
					for _, v := range vs {
						fmt.Fprint(c.Writer, "     - "+v+"\n")
					}
				case len(vs) == 1:
					fmt.Fprint(c.Writer, "   "+k+": "+profile.Roles[0]+"\n")
				}
			} else {
				fmt.Fprint(c.Writer, "   "+k+": "+cast.ToString(v)+"\n")
			}
		}
	}
}

// RouteGetProfileJSON is the handler for GET /profile.json
// This handler serves the profile of authenticated users in JSON format
func (s *Server) RouteGetProfileJSON(c *gin.Context) {
	// Check if we have a session
	profile, _ := s.getProfileFromContext(c)
	if profile == nil {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
		return
	}

	// If we are here, we have a valid session
	// Return all claims in the token to the user
	type responseDataName struct {
		Full     string `json:"full"`
		Nickname string `json:"nickname,omitempty"`
		First    string `json:"first,omitempty"`
		Middle   string `json:"middle,omitempty"`
		Last     string `json:"last,omitempty"`
	}
	type responseDataEmail struct {
		Address  string `json:"address"`
		Verified bool   `json:"verified"`
	}
	type responseData struct {
		Authenticated    bool               `json:"authenticated"`
		Provider         string             `json:"provider"`
		ID               string             `json:"id"`
		Name             responseDataName   `json:"name"`
		Email            *responseDataEmail `json:"email,omitempty"`
		Picture          string             `json:"picture,omitempty"`
		Locale           string             `json:"local,omitempty"`
		Timezone         string             `json:"timezone,omitempty"`
		Groups           []string           `json:"groups,omitempty"`
		Roles            []string           `json:"roles,omitempty"`
		AdditionalClaims map[string]any     `json:"additionalClaims,omitempty"`
	}
	res := responseData{
		Authenticated: true,
		Provider:      profile.Provider,
		ID:            profile.ID,
		Name: responseDataName{
			Full:     profile.Name.FullName,
			Nickname: profile.Name.Nickname,
			First:    profile.Name.First,
			Middle:   profile.Name.Middle,
			Last:     profile.Name.Last,
		},
		Picture:  profile.Picture,
		Locale:   profile.Locale,
		Timezone: profile.Timezone,
	}
	if profile.Email != nil {
		res.Email = &responseDataEmail{
			Address:  profile.Email.Value,
			Verified: profile.Email.Verified,
		}
	}
	if len(profile.Groups) > 0 {
		res.Groups = profile.Groups
	}
	if len(profile.Roles) > 0 {
		res.Roles = profile.Roles
	}
	if len(profile.AdditionalClaims) > 0 {
		res.AdditionalClaims = profile.AdditionalClaims
	}
	c.JSON(http.StatusOK, res)
}
