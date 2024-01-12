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

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// OAuth2 is a Provider for authenticating with a generic OAuth2 provider.
type OAuth2 struct {
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
	Authorization string
	// Token URL
	Token string
	// User Info URL
	UserInfo string
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
func NewOAuth2(providerName string, opts NewOAuth2Options) (p OAuth2, err error) {
	if opts.Config.ClientID == "" {
		return p, errors.New("value for clientId is required in config for auth provider")
	}
	if opts.Config.ClientSecret == "" {
		return p, errors.New("value for clientSecret is required in config for auth provider")
	}
	if providerName == "" {
		return p, errors.New("missing parameter providerName")
	}
	if opts.Endpoints.Authorization == "" || opts.Endpoints.Token == "" || opts.Endpoints.UserInfo == "" {
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

	p = OAuth2{
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

func (a OAuth2) GetProviderName() string {
	return a.providerName
}

func (a OAuth2) AuthorizeURL(state string, redirectURL string) (string, error) {
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

func (a OAuth2) ExchangeCode(ctx context.Context, code string, redirectURL string) (AccessToken, error) {
	if code == "" {
		return AccessToken{}, errors.New("parameter code is required")
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
		return AccessToken{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := a.httpClient.Do(req)
	if err != nil {
		return AccessToken{}, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return AccessToken{}, fmt.Errorf("invalid response status code: %d", err)
	}

	var tokenResponse oAuth2TokenResponse
	err = json.NewDecoder(res.Body).Decode(&tokenResponse)
	if err != nil {
		return AccessToken{}, fmt.Errorf("invalid response body: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return AccessToken{}, errors.New("missing access_token in response")
	}

	expires := time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	return AccessToken{
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

func (a OAuth2) RetrieveProfile(ctx context.Context, at AccessToken) (profile user.Profile, err error) {
	if at.AccessToken == "" {
		return user.Profile{}, errors.New("Missing parameter at")
	}

	// Check if we have an ID token to get the profile from
	if at.IDToken != "" && a.tokenIssuer != "" {
		// We do not verify the JWT's signature since we just retrieved it from the identity server
		// We limit ourselves to parsing it
		token, err := jwt.Parse(
			[]byte(at.IDToken),
			jwt.WithIssuer(a.tokenIssuer),
			jwt.WithAudience(a.config.ClientID),
			jwt.WithVerify(false),
			jwt.WithToken(openid.New()),
		)
		if err != nil {
			return profile, fmt.Errorf("failed to parse ID token: %w", err)
		}
		oidToken, ok := token.(openid.Token)
		if !ok {
			return profile, errors.New("failed to parse ID token: included claims cannot be cast to openid.Token")
		}

		profile, err = user.NewProfileFromOpenIDToken(oidToken)
		if err != nil {
			return profile, fmt.Errorf("invalid claims in token: %w", err)
		}
		return profile, nil
	}

	// Retrieve the profile with an API call
	if at.AccessToken == "" {
		return profile, errors.New("missing AccessToken in parameter at")
	}

	reqCtx, cancel := context.WithTimeout(ctx, a.requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, a.endpoints.UserInfo, nil)
	if err != nil {
		return profile, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+at.AccessToken)

	res, err := a.httpClient.Do(req)
	if err != nil {
		return profile, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return profile, fmt.Errorf("invalid response status code: %d", err)
	}

	claims := map[string]any{}
	err = json.NewDecoder(res.Body).Decode(&claims)
	if err != nil {
		return profile, fmt.Errorf("invalid response body: %w", err)
	}

	return profile, nil
}

func (a OAuth2) ValidateRequestClaims(c *gin.Context, claims map[string]any) error {
	// This implementation doesn't need performing additional validation on the claims
	return nil
}

func (a OAuth2) UserIDFromProfile(profile user.Profile) string {
	return profile.ID
}

// Compile-time interface assertion
var _ Provider = OAuth2{}
