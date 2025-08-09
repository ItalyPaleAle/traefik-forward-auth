//go:build unit

// This file is only built when the "unit" tag is set
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// TestProviderOAuth2 is a test Provider that implements OAuth2 with a fake IdP
type TestProviderOAuth2 struct {
	baseProvider
}

func NewTestProviderOAuth2() *TestProviderOAuth2 {
	return &TestProviderOAuth2{
		baseProvider: baseProvider{
			metadata: ProviderMetadata{
				DisplayName: "TesT Oauth2",
				Name:        "testoauth2",
			},
		},
	}
}

func (a *TestProviderOAuth2) GetProviderType() string {
	return "testoauth2"
}

// Use as "state" the name of a user template, as supported by getTestUserProfile
func (a *TestProviderOAuth2) OAuth2AuthorizeURL(state string, redirectURL string) (string, error) {
	if state == "" {
		return "", errors.New("parameter state is required")
	}

	params := url.Values{
		"client_id":     []string{"test-client-id"},
		"redirect_uri":  []string{redirectURL},
		"response_type": []string{"code"},
		"scope":         []string{"test"},
		"state":         []string{state},
	}

	return "https://idp.example.com/oauth2/auth?" + params.Encode(), nil
}

// Use as "state" the name of a user template, as supported by getTestUserProfile
func (a *TestProviderOAuth2) OAuth2ExchangeCode(ctx context.Context, state string, code string, redirectURL string) (OAuth2AccessToken, error) {
	if code == "" {
		return OAuth2AccessToken{}, errors.New("parameter code is required")
	}

	if state == "bad-user" {
		return OAuth2AccessToken{}, errors.New("unauthorized")
	}

	return OAuth2AccessToken{
		Provider: a.GetProviderType(),
		IDToken:  state, // Name of the user template
		Expires:  time.Now().Add(time.Hour),
		Scopes:   []string{"test"},
	}, nil
}

func (a *TestProviderOAuth2) OAuth2RetrieveProfile(ctx context.Context, at OAuth2AccessToken) (*user.Profile, error) {
	profile := getTestUserProfile(at.IDToken, a.GetProviderName())
	if profile == nil {
		return nil, fmt.Errorf("cannot find template for user '%s'", at.IDToken)
	}
	return profile, nil
}

// TestProviderSeamless is a test Provider that implements seamless auth
type TestProviderSeamless struct {
	baseProvider
}

func NewTestProviderSeamless() *TestProviderSeamless {
	return &TestProviderSeamless{
		baseProvider: baseProvider{
			metadata: ProviderMetadata{
				DisplayName: "Test Seamless",
				Name:        "testseamless",
			},
		},
	}
}

func (a *TestProviderSeamless) GetProviderType() string {
	return "testseamless"
}

func (a *TestProviderSeamless) SeamlessAuth(r *http.Request) (*user.Profile, error) {
	// This test provider uses the user passed as X-Seamless-User to authenticate, containing the template
	template := r.Header.Get("X-Seamless-User")
	if template == "" {
		return nil, errors.New("no 'X-Seamless-User' header found")
	}

	if template == "bad-user" {
		return nil, errors.New("unauthorized")
	}

	profile := getTestUserProfile(template, a.GetProviderName())
	if profile == nil {
		return nil, fmt.Errorf("cannot find template for user '%s'", template)
	}
	return profile, nil
}

// Compile-time interface assertions
var _ OAuth2Provider = &TestProviderOAuth2{}
var _ SeamlessProvider = &TestProviderSeamless{}

func getTestUserProfile(template string, provider string) *user.Profile {
	switch template {
	case "test-user-1":
		return &user.Profile{
			Provider: provider,
			ID:       "test-user-1",
			Name: user.ProfileName{
				FullName: "Test User 1",
			},
			Email: &user.ProfileEmail{
				Value:    "test1@example.com",
				Verified: true,
			},
			Groups: []string{"test-users"},
			Roles:  []string{"test-users"},
		}
	}

	return nil
}
