package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const ghGraphQLEndpoint = "https://api.github.com/graphql"

// GitHub manages authentication with GitHub.
// It is based on the OAuth 2 provider.
type GitHub struct {
	OAuth2
}

// NewGitHubOptions is the options for NewGitHub
type NewGitHubOptions struct {
	// Client ID
	ClientID string
	// Client secret
	ClientSecret string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

// NewGitHub returns a new GitHub provider
func NewGitHub(opts NewGitHubOptions) (p GitHub, err error) {
	if opts.ClientID == "" {
		return p, errors.New("value for clientId is required in config for auth with provider 'github'")
	}
	if opts.ClientSecret == "" {
		return p, errors.New("value for clientSecret is required in config for auth with provider 'github'")
	}

	oauth2, err := NewOAuth2("github", NewOAuth2Options{
		Config: OAuth2Config{
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
		},
		Endpoints: OAuth2Endpoints{
			Authorization: "https://github.com/login/oauth/authorize",
			Token:         "https://github.com/login/oauth/access_token",
			UserInfo:      "https://api.github.com/user",
		},
		Scopes:         "user",
		RequestTimeout: opts.RequestTimeout,
	})
	if err != nil {
		return p, err
	}

	return GitHub{
		OAuth2: oauth2,
	}, nil
}

func (a GitHub) RetrieveProfile(ctx context.Context, at AccessToken) (UserProfile, error) {
	if at.AccessToken == "" {
		return UserProfile{}, errors.New("missing AccessToken in parameter at")
	}

	reqCtx, cancel := context.WithTimeout(ctx, a.requestTimeout)
	defer cancel()
	reqBody := strings.NewReader(`{"query": "query { viewer { id, login, avatarUrl, name } }"}`)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, ghGraphQLEndpoint, reqBody)
	if err != nil {
		return UserProfile{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "token "+at.AccessToken)
	req.Header.Set("User-Agent", "photobox/1")

	res, err := a.httpClient.Do(req)
	if err != nil {
		return UserProfile{}, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return UserProfile{}, fmt.Errorf("invalid response status code: %d", err)
	}

	var resBody struct {
		Data struct {
			Viewer struct {
				ID        string `json:"id"`
				Login     string `json:"login"`
				AvatarUrl string `json:"avatarUrl"`
				Name      string `json:"name"`
			} `json:"viewer"`
		} `json:"data"`
	}
	err = json.NewDecoder(res.Body).Decode(&resBody)
	if err != nil {
		return UserProfile{}, err
	}

	userData := resBody.Data.Viewer
	if userData.ID == "" || userData.Login == "" {
		return UserProfile{}, errors.New("missing required fields in user profile response")
	}

	fn := userData.Name
	if fn == "" {
		fn = userData.Login
	}

	return UserProfile{
		ID:      userData.ID,
		Picture: userData.AvatarUrl,
		Name: UserProfileName{
			Nickname: userData.Login,
			FullName: fn,
		},
	}, nil
}

// Compile-time interface assertion
var _ Provider = GitHub{}
