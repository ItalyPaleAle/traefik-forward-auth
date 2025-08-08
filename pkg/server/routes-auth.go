package server

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// RouteGetOAuth2Root is the handler for GET / when using an OAuth2-based provider
// This handles requests from Traefik and redirects users to auth servers if needed
func (s *Server) RouteGetOAuth2Root(provider auth.OAuth2Provider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Check if we have a session
		profile := s.getProfileFromContext(c)
		if profile == nil {
			s.oAuth2RedirectToAuth(c, provider)
			return
		}

		// If we are here, we have a valid session, so respond with a 200 status code
		// Include the user name in the response body in case a visitor is hitting the auth server directly
		s.metrics.RecordAuthentication(true)
		user := s.auth.UserIDFromProfile(profile)
		c.Header("X-Forwarded-User", user)
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(`You're authenticated as '`+user+`'`))
	}
}

// RouteGetOAuth2Callback is the handler for GET /oauth2/callback when using an OAuth2-based provider
// This handles redirects from OAuth2 identity providers after successful callbacks
func (s *Server) RouteGetOAuth2Callback(provider auth.OAuth2Provider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Check if there's an error in the query string
		if qsErr := c.Query("error"); qsErr != "" {
			c.Set("log-message", "Error from the app server: "+qsErr)
			AbortWithError(c, NewResponseError(http.StatusFailedDependency, "The auth server returned an error"))
			return
		}

		// Ensure that we have a state and code parameters
		stateParam := c.Query("state")
		codeParam := c.Query("code")
		if stateParam == "" || codeParam == "" {
			AbortWithError(c, NewResponseError(http.StatusBadRequest, "The parameters 'state' and 'code' are required in the query string"))
			return
		}
		stateCookieID, expectedNonce, ok := strings.Cut(stateParam, "~")
		if !ok {
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Query string parameter 'state' is invalid"))
			return
		}

		// Get the state cookie
		nonce, returnURL, err := s.getStateCookie(c, stateCookieID)
		if err != nil {
			AbortWithError(c, fmt.Errorf("invalid state cookie: %w", err))
			return
		} else if nonce == "" {
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "State cookie not found"))
			return
		}

		// Clear the state cookie
		s.deleteStateCookies(c)

		// Check if the nonce matches
		if nonce != expectedNonce {
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Parameters in state cookie do not match state token"))
			return
		}

		// Exchange the code for a token
		at, err := provider.OAuth2ExchangeCode(c.Request.Context(), stateParam, codeParam, getOAuth2RedirectURI(c))
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to exchange code for access token: %w", err))
			return
		}

		// Retrieve the user profile
		profile, err := provider.OAuth2RetrieveProfile(c.Request.Context(), at)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to retrieve user profile: %w", err))
			return
		}

		// Check if the user is allowed per rules
		err = provider.UserAllowed(profile)
		if err != nil {
			_ = c.Error(fmt.Errorf("access denied per allowlist rules: %w", err))
			AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Access denied per allowlist rules"))
			return
		}

		// Set the profile in the cookie
		err = s.setSessionCookie(c, profile)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to set session cookie: %w", err))
			return
		}

		// Use a custom redirect code to write a response in the body
		// We use a 307 redirect here so the client can re-send the request with the original method
		c.Header("Location", returnURL)
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Writer.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = c.Writer.WriteString(`Redirecting to application: ` + returnURL)
	}
}

// RouteGetSeamlessAuthRoot is the handler for GET / when using a seamless auth provider
// This handles requests from Traefik
func (s *Server) RouteGetSeamlessAuthRoot(provider auth.SeamlessProvider) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Check if we have a session already
		profile := s.getProfileFromContext(c)
		if profile == nil {
			// Try to authenticate with the seamless auth
			var err error
			profile, err = provider.SeamlessAuth(c.Request)
			if err != nil {
				c.Set("log-message", "Seamless authentication failed: "+err.Error())
				s.metrics.RecordAuthentication(false)
				s.deleteSessionCookie(c)
				AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
				return
			}

			// Check if the user is allowed per rules
			err = provider.UserAllowed(profile)
			if err != nil {
				_ = c.Error(fmt.Errorf("access denied per allowlist rules: %w", err))
				AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Access denied per allowlist rules"))
				return
			}

			// Set the profile in the cookie
			err = s.setSessionCookie(c, profile)
			if err != nil {
				AbortWithError(c, fmt.Errorf("failed to set session cookie: %w", err))
				return
			}

			// We need to do a redirect to be able to have the cookies actually set
			// Also see: https://github.com/traefik/traefik/issues/3660
			returnURL := getReturnURL(c)
			c.Header("Location", returnURL)
			c.Header("Content-Type", "text/plain; charset=utf-8")
			c.Writer.WriteHeader(http.StatusSeeOther)
			_, _ = c.Writer.WriteString(`Redirecting to application: ` + returnURL)
		}

		// If we are here, we have a valid session, so respond with a 200 status code
		// Include the user name in the response body in case a visitor is hitting the auth server directly
		s.metrics.RecordAuthentication(true)
		user := s.auth.UserIDFromProfile(profile)
		c.Header("X-Forwarded-User", user)
		c.Header("Content-Type", "text/plain; charset=utf-8")
		_, _ = c.Writer.WriteString("You're authenticated as '" + user + "'")
	}
}

// RouteGetLogout is the handler for GET /logout
// This removes the session cookie
func (s *Server) RouteGetLogout(c *gin.Context) {
	// Delete the state and session cookies
	s.deleteSessionCookie(c)
	s.deleteStateCookies(c)

	// Respond with a success message
	c.Header("Content-Type", "text/plain; charset=utf-8")
	_, _ = c.Writer.WriteString("You've logged out")
}

func (s *Server) oAuth2RedirectToAuth(c *gin.Context, provider auth.OAuth2Provider) {
	var err error

	s.metrics.RecordAuthentication(false)

	// Get the return URL
	returnURL := getReturnURL(c)

	// Each state cookie is unique per return URL
	// This is
	// This avoids issues when there's more than one browser tab that's trying to authenticate, for example because of some background refresh
	stateCookieID := getStateCookieID(returnURL)

	// Check if there's already a state cookie that's recent, so we can re-use the same nonce
	nonce, _, _ := s.getStateCookie(c, stateCookieID)

	if nonce == "" {
		// If there's no nonce, generate a new one
		nonce, err = s.generateNonce()
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to generate nonce: %w", err))
			return
		}
	}

	// Create a new state and set the cookie
	err = s.setStateCookie(c, nonce, returnURL, stateCookieID)
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to set state cookie: %w", err))
		return
	}

	// Redirect to the authorization URL
	authURL, err := provider.OAuth2AuthorizeURL(stateCookieID+"~"+nonce, getOAuth2RedirectURI(c))
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to get authorize URL: %w", err))
		return
	}

	// Use a custom redirect code to write a response in the body
	c.Header("Location", authURL)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Writer.WriteHeader(http.StatusSeeOther)
	_, _ = c.Writer.WriteString(`Redirecting to 
	authentication server: ` + authURL)
}

func (s *Server) getProfileFromContext(c *gin.Context) *user.Profile {
	if !c.GetBool("session-auth") {
		return nil
	}
	profileAny, ok := c.Get("session-profile")
	if !ok {
		return nil
	}
	profile, ok := profileAny.(*user.Profile)
	if !ok || profile == nil || profile.ID == "" {
		return nil
	}
	return profile
}

// Get the return URL, to redirect users to after a successful auth
func getReturnURL(c *gin.Context) string {
	// Here we use  X-Forwarded-* headers which have the data of the original request
	reqURL := c.Request.URL
	if slice, ok := c.Request.Header["X-Forwarded-Uri"]; ok {
		var val string
		if len(slice) > 0 {
			val = slice[0]
		}
		reqURL, _ = url.Parse(val)
	}
	
	// Map WebSocket protocols to HTTP protocols for redirect URLs
	// This ensures browsers can navigate to the redirect URL after authentication
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	switch proto {
	case "ws":
		proto = "http"
	case "wss":
		proto = "https"
	}
	
	return proto + "://" + c.Request.Header.Get("X-Forwarded-Host") + reqURL.Path
}

// Computes the state cookie ID for the given return URL
func getStateCookieID(returnURL string) string {
	h := sha256.New()
	h.Write([]byte("tf_return_url:"))
	h.Write([]byte(returnURL))
	digest := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(digest[:8])
}

// Get the redirect URI, which is sent to the OAuth2 authentication server and indicates where to return users after a successful auth with the IdP
func getOAuth2RedirectURI(c *gin.Context) string {
	cfg := config.Get()
	
	// Map WebSocket protocols to HTTP protocols for OAuth2 redirect URI
	// OAuth2 callback URLs must be HTTP/HTTPS for browsers to navigate to
	proto := c.GetHeader("X-Forwarded-Proto")
	switch proto {
	case "ws":
		proto = "http"
	case "wss":
		proto = "https"
	}
	
	return proto + "://" + cfg.Hostname + cfg.BasePath + "/oauth2/callback"
}
