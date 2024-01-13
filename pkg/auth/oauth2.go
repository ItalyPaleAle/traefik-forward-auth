package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// oAuth2 is a Provider for authenticating with OAuth2.
// This Provider cannot be used directly; instead, other providers can embed this struct and implement OAuth2RetrieveProfile.
type oAuth2 struct {
	config         OAuth2Config
	providerName   string
	endpoints      OAuth2Endpoints
	tokenIssuer    string
	scopes         string
	requestTimeout time.Duration

	httpClient *http.Client
}

type OAuth2Config struct {
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
}

type OAuth2Endpoints struct {
	// Authorization URL
	Authorization string `json:"authorization_endpoint"`
	// Token URL
	Token string `json:"token_endpoint"`
	// User Info URL
	UserInfo string `json:"userinfo_endpoint"`
}

// NewOAuth2Options is the options for NewOAuth2
type NewOAuth2Options struct {
	Config    OAuth2Config
	Endpoints OAuth2Endpoints
	// Optional value for the issuer claim
	TokenIssuer string
	// Scopes for requesting the token
	// This is optional and defaults to "openid profile email"
	Scopes string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

// NewOAuth2 returns a new OAuth2 provider
func NewOAuth2(providerName string, opts NewOAuth2Options) (p oAuth2, err error) {
	if opts.Config.ClientID == "" {
		return p, errors.New("value for clientId is required in config for auth provider")
	}
	if opts.Config.ClientSecret == "" {
		return p, errors.New("value for clientSecret is required in config for auth provider")
	}
	if providerName == "" {
		return p, errors.New("missing parameter providerName")
	}
	if !opts.Endpoints.Valid() {
		return p, errors.New("all endpoints must be specified")
	}

	scopes := opts.Scopes
	if scopes == "" {
		scopes = "openid profile email"
	}
	reqTimeout := opts.RequestTimeout
	if reqTimeout < time.Second {
		reqTimeout = 10 * time.Second
	}

	p = oAuth2{
		config:         opts.Config,
		providerName:   providerName,
		endpoints:      opts.Endpoints,
		tokenIssuer:    opts.TokenIssuer,
		scopes:         scopes,
		httpClient:     &http.Client{},
		requestTimeout: reqTimeout,
	}
	return p, nil
}

func (a oAuth2) GetProviderName() string {
	return a.providerName
}

func (a oAuth2) OAuth2AuthorizeURL(state string, redirectURL string) (string, error) {
	if state == "" {
		return "", errors.New("parameter state is required")
	}
	params := url.Values{}
	params.Add("client_id", a.config.ClientID)
	params.Add("redirect_uri", redirectURL)
	params.Add("response_type", "code")
	params.Add("scope", a.scopes)
	params.Add("state", state)

	return a.endpoints.Authorization + "?" + params.Encode(), nil
}

func (a oAuth2) OAuth2ExchangeCode(ctx context.Context, code string, redirectURL string) (OAuth2AccessToken, error) {
	if code == "" {
		return OAuth2AccessToken{}, errors.New("parameter code is required")
	}

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", a.config.ClientID)
	data.Set("client_secret", a.config.ClientSecret)
	data.Set("redirect_uri", redirectURL)
	data.Set("grant_type", "authorization_code")

	reqCtx, cancel := context.WithTimeout(ctx, a.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, a.endpoints.Token, strings.NewReader(data.Encode()))
	if err != nil {
		return OAuth2AccessToken{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := a.httpClient.Do(req)
	if err != nil {
		return OAuth2AccessToken{}, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return OAuth2AccessToken{}, fmt.Errorf("invalid response status code: %d", res.StatusCode)
	}

	var tokenResponse oAuth2TokenResponse
	err = json.NewDecoder(res.Body).Decode(&tokenResponse)
	if err != nil {
		return OAuth2AccessToken{}, fmt.Errorf("invalid response body: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return OAuth2AccessToken{}, errors.New("missing access_token in response")
	}

	expires := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	return OAuth2AccessToken{
		Provider:     a.providerName,
		AccessToken:  tokenResponse.AccessToken,
		Expires:      expires,
		IDToken:      tokenResponse.IDToken,
		RefreshToken: tokenResponse.RefreshToken,
		Scopes:       strings.Split(tokenResponse.Scope, " "),
	}, nil
}

type oAuth2TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func (a oAuth2) OAuth2RetrieveProfile(ctx context.Context, at OAuth2AccessToken) (profile *user.Profile, err error) {
	// This method needs to be implemented in structs that embed OAuth2
	panic("Method OAuth2RetrieveProfile must be implemented by a struct inheriting OAuth2")
}

func (a oAuth2) ValidateRequestClaims(r *http.Request, profile *user.Profile) error {
	// This implementation doesn't need performing additional validation on the claims
	return nil
}

func (a oAuth2) UserIDFromProfile(profile *user.Profile) string {
	return profile.ID
}

func (a oAuth2) PopulateAdditionalClaims(claims map[string]any, setClaimFn func(key, val string)) {
	// Nop
}

// Valid returns true if all fields are set
func (e OAuth2Endpoints) Valid() bool {
	return e.Authorization != "" && e.Token != "" && e.UserInfo != ""
}

// Compile-time interface assertion
var _ OAuth2Provider = oAuth2{}
