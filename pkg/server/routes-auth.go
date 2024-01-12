package server

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// RouteGetRoot is the handler for GET /
// This handles requests from Traefik and redirects users to auth servers if needed.
func (s *Server) RouteGetRoot(c *gin.Context) {
	// Check if we have a session
	if !c.GetBool("session-auth") {
		s.redirectToAuth(c)
		return
	}
	profileAny, ok := c.Get("session-profile")
	if !ok {
		s.redirectToAuth(c)
		return
	}
	profile, ok := profileAny.(user.Profile)
	if !ok || profile.ID == "" {
		s.redirectToAuth(c)
		return
	}

	// If we are here, we have a valid session, so respond with a 200 status code
	// Include the user name in the response body in case a visitor is hitting the auth server directly
	s.metrics.RecordAuthentication(true)
	user := s.auth.UserIDFromProfile(profile)
	c.Header("X-Forwarded-User", user)
	c.Data(http.StatusOK, "text/plain", []byte(`You're authenticated as '`+user+`'`))
}

// RouteGetOAuth2Callback is the handler for GET /oauth2/callback
// This handles redirects from OAuth2 identity providers after successful callbacks
func (s *Server) RouteGetOAuth2Callback(c *gin.Context) {
	// Check if there's an error in the query string
	if qsErr := c.Query("error"); qsErr != "" {
		c.Set("log-message", "Error from the app server: "+qsErr)
		AbortWithErrorJSON(c, NewResponseError(http.StatusFailedDependency, "The auth server returned an error"))
		return
	}

	// Ensure that we have a state and code parameters
	stateParam := c.Query("state")
	codeParam := c.Query("code")
	if stateParam == "" || codeParam == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusBadRequest, "The parameters 'state' and 'code' are required in the query string"))
		return
	}

	// Get the state cookie
	nonce, returnURL, err := getStateCookie(c)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("invalid state cookie: %w", err))
		return
	} else if nonce == "" {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "State cookie not found"))
		return
	}

	// Clear the state cookie
	deleteStateCookie(c)

	// Check if the nonce matches
	if nonce != stateParam {
		AbortWithErrorJSON(c, NewResponseError(http.StatusUnauthorized, "Parameters in state cookie do not match state token"))
		return
	}

	// Exchange the code for a token
	at, err := s.auth.ExchangeCode(c.Request.Context(), codeParam, getOAuth2RedirectURI(c))
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to exchange code for access token: %w", err))
		return
	}

	// Retrieve the user profile
	profile, err := s.auth.RetrieveProfile(c.Request.Context(), at)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to retrieve user profile: %w", err))
		return
	}

	// Set the profile in the cookie
	err = setSessionCookie(c, &profile)
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to set session cookie: %w", err))
		return
	}

	// Use a custom redirect code to write a response in the body
	c.Header("Location", returnURL)
	c.Data(http.StatusSeeOther, "text/html; charset=utf-8", []byte(`Redirecting to application: <a href="`+returnURL+`">`+returnURL+`</a>`))
}

// RouteGetLogout is the handler for GET /logout
// This removes the session cookie
func (s *Server) RouteGetLogout(c *gin.Context) {
	// Delete the state and session cookies
	deleteSessionCookie(c)
	deleteStateCookie(c)

	// Respond with a success message
	c.Data(http.StatusOK, "text/plain", []byte("You've logged out"))
}

func (s *Server) redirectToAuth(c *gin.Context) {
	s.metrics.RecordAuthentication(false)

	// Create a new state and set the cookie
	nonce, err := setStateCookie(c, getReturnURL(c))
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to set state cookie: %w", err))
		return
	}

	// Redirect to the authorization URL
	authURL, err := s.auth.AuthorizeURL(nonce, getOAuth2RedirectURI(c))
	if err != nil {
		AbortWithErrorJSON(c, fmt.Errorf("failed to get authorize URL: %w", err))
		return
	}

	// Use a custom redirect code to write a response in the body
	c.Header("Location", authURL)
	c.Data(http.StatusSeeOther, "text/html; charset=utf-8", []byte(`Redirecting to authentication server: <a href="`+authURL+`">`+authURL+`</a>`))
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
	return c.Request.Header.Get("X-Forwarded-Proto") + "://" + c.Request.Header.Get("X-Forwarded-Host") + reqURL.Path
}

// Get the redirect URI, which is sent to the OAuth2 authentication server and indicates where to return users after a successful auth with the IdP
func getOAuth2RedirectURI(c *gin.Context) string {
	return c.GetHeader("X-Forwarded-Proto") + "://" + config.Get().Hostname + config.Get().BasePath + "/oauth2/callback"
}
