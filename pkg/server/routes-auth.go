package server

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// RouteGetAuthRoot is the handler for GET /portals/:portal
// This handles requests from Traefik and redirects users if needed
func (s *Server) RouteGetAuthRoot(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Check if we have a session
	profile, provider := s.getProfileFromContext(c)
	if profile == nil || provider == nil {
		// We don't have a session, so redirect to the sign-in page
		s.metrics.RecordAuthentication(false)

		// Get the return URL
		returnURL := getReturnURL(c, portal.Name)

		// Each state cookie is unique per return URL
		// This avoids issues when there's more than one browser tab that's trying to authenticate, for example because of some background refresh
		stateCookieID := getStateCookieID(returnURL)

		// Check if there's already a state cookie that's recent, so we can re-use the same nonce
		content, _ := s.getStateCookie(c, portal, stateCookieID)

		// If there's no nonce, generate a new one
		nonce := content.nonce
		if content.nonce == "" {
			nonce, err = s.generateNonce()
			if err != nil {
				AbortWithError(c, fmt.Errorf("failed to generate nonce: %w", err))
				return
			}
		}

		// Create a new state and set the cookie
		err = s.setStateCookie(c, portal, nonce, returnURL, stateCookieID)
		if err != nil {
			AbortWithError(c, fmt.Errorf("failed to set state cookie: %w", err))
			return
		}

		// Redirect the user
		signInURL := getPortalURI(c, portal.Name) + "/signin?state=" + stateCookieID + "~" + nonce
		c.Header("Location", signInURL)
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Writer.WriteHeader(http.StatusSeeOther)
		_, _ = c.Writer.WriteString(`Redirecting to sign-in page: ` + signInURL)
		return
	}

	// If we are here, we have a valid session, so respond with a 200 status code
	// Include the user name in the response body in case a visitor is hitting the auth server directly
	s.metrics.RecordAuthentication(true)
	userID := provider.UserIDFromProfile(profile)
	c.Header("X-Forwarded-User", userID)
	c.Header("X-Authenticated-User", auth.AuthenticatedUserFromProfile(provider, profile))
	c.Header("Content-Type", "text/plain; charset=utf-8")
	_, _ = c.Writer.WriteString("You're authenticated with provider '" + provider.GetProviderName() + "' as '" + userID + "'")
}

// RouteGetAuthSignin is the handler for GET /portals/:portal/signin
// It displays the list of providers
func (s *Server) RouteGetAuthSignin(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Ensure we have a state parameter
	content, stateCookieID, err := s.parseStateParamPreAuth(c, portal)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Render the template
	s.renderSigninTemplate(c, portal, stateCookieID, content.nonce)
}

func (s *Server) renderSigninTemplate(c *gin.Context, portal Portal, stateCookieID string, nonce string) {
	conf := config.Get()

	type signingTemplateData_Provider struct {
		Color       string
		DisplayName string
		Href        string
		Svg         template.HTML
	}

	type signinTemplateData struct {
		Title     string
		BaseUrl   string
		Providers []signingTemplateData_Provider
	}

	data := signinTemplateData{
		Title:     portal.DisplayName,
		BaseUrl:   conf.Server.BasePath,
		Providers: make([]signingTemplateData_Provider, 0, len(portal.Providers)),
	}
	for _, name := range portal.ProvidersList {
		provider := portal.Providers[name]

		pd := signingTemplateData_Provider{
			Color:       provider.GetProviderColor(),
			DisplayName: provider.GetProviderDisplayName(),
			Href:        getPortalURI(c, portal.Name) + "/provider/" + name + "?state=" + stateCookieID + "~" + nonce,
		}

		iconStr, ok := s.icons[provider.GetProviderIcon()]
		if ok && iconStr != "" {
			pd.Svg = template.HTML(iconStr)
		} else {
			// Default is to add an empty svg, to ensure elements are aligned
			pd.Svg = template.HTML(`<svg class="provider-icon" aria-hidden="true"></svg>`)
		}

		data.Providers = append(data.Providers, pd)
	}

	c.HTML(http.StatusOK, "signin.html.tpl", data)
}

func (s *Server) parseStateParamPreAuth(c *gin.Context, portal Portal) (stateCookieContent, string, error) {
	// Ensure we have a state parameter
	stateParam := c.Query("state")
	if stateParam == "" {
		return stateCookieContent{}, "", NewResponseError(http.StatusBadRequest, "The parameter 'state' is required in the query string")
	}

	stateCookieID, expectedNonce, ok := strings.Cut(stateParam, "~")
	if !ok {
		return stateCookieContent{}, "", NewResponseError(http.StatusUnauthorized, "Query string parameter 'state' is invalid")
	}

	// Get the state cookie
	content, err := s.getStateCookie(c, portal, stateCookieID)
	if err != nil {
		return stateCookieContent{}, "", fmt.Errorf("invalid state cookie: %w", err)
	} else if content.nonce == "" {
		return stateCookieContent{}, "", NewResponseError(http.StatusUnauthorized, "State cookie not found")
	}

	// Check if the nonce matches
	if content.nonce != expectedNonce {
		return stateCookieContent{}, "", NewResponseError(http.StatusUnauthorized, "Parameters in state cookie do not match state token")
	}

	return content, stateCookieID, nil
}

// RouteGetAuthProvider is the handler for GET /portals/:portal/provider/:provider
// This redirects users to auth servers
func (s *Server) RouteGetAuthProvider(c *gin.Context) {
	portal, provider, err := s.getProvider(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Ensure we have a state parameter
	content, stateCookieID, err := s.parseStateParamPreAuth(c, portal)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	switch provider := provider.(type) {
	case auth.OAuth2Provider:
		s.handleGetAuthProviderOAuth2(c, portal, stateCookieID, content.nonce, provider)
	case auth.SeamlessProvider:
		s.handleGetAuthProviderSeamlessAuth(c, portal, content.returnURL, provider)
	}
}

// Handles GET /portals/:portal/provider/:provider when using an OAuth2-based provider
// This redirects users to the OAuth2 Identity Provider
func (s *Server) handleGetAuthProviderOAuth2(c *gin.Context, portal Portal, stateCookieID string, nonce string, provider auth.OAuth2Provider) {
	var err error

	// Redirect to the authorization URL
	stateParam := provider.GetProviderName() + "~" + stateCookieID + "~" + nonce
	authURL, err := provider.OAuth2AuthorizeURL(stateParam, getOAuth2RedirectURI(c, portal.Name))
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to get authorize URL: %w", err))
		return
	}

	// Use a custom redirect code to write a response in the body
	c.Header("Location", authURL)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Writer.WriteHeader(http.StatusSeeOther)
	_, _ = c.Writer.WriteString(`Redirecting to authentication server: ` + authURL)
}

// RouteGetOAuth2Callback is the handler for GET /portals/:portal/oauth2/callback
// This handles redirects from OAuth2 identity providers after successful callbacks
func (s *Server) RouteGetOAuth2Callback(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Check if there's an error in the query string
	qsErr := c.Query("error")
	if qsErr != "" {
		c.Set(logMessageContextKey, "Error from the app server: "+qsErr)
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
	// Format is: "Provider~StateCookieID~Nonce"
	parts := strings.SplitN(stateParam, "~", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Query string parameter 'state' is invalid"))
		return
	}

	// Get the state cookie
	content, err := s.getStateCookie(c, portal, parts[1])
	if err != nil {
		AbortWithError(c, fmt.Errorf("invalid state cookie: %w", err))
		return
	} else if content.nonce == "" {
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "State cookie not found"))
		return
	}

	// Get the provider
	providerI, ok := portal.Providers[parts[0]]
	if !ok {
		AbortWithError(c, NewResponseError(http.StatusConflict, "Auth provider not found"))
		return
	}
	provider, ok := providerI.(auth.OAuth2Provider)
	if !ok {
		AbortWithError(c, NewResponseError(http.StatusConflict, "Auth provider does not implement OAuth2"))
		return
	}

	// Clear the state cookie for the portal
	s.deleteStateCookies(c, portal.Name)

	// Check if the nonce matches
	if content.nonce != parts[2] {
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Parameters in state cookie do not match state token"))
		return
	}

	// Exchange the code for a token
	at, err := provider.OAuth2ExchangeCode(c.Request.Context(), stateParam, codeParam, getOAuth2RedirectURI(c, portal.Name))
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
	err = s.setSessionCookie(c, portal.Name, profile)
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to set session cookie: %w", err))
		return
	}

	// Use a custom redirect code to write a response in the body
	// We use a 307 redirect here so the client can re-send the request with the original method
	c.Header("Location", content.returnURL)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Writer.WriteHeader(http.StatusTemporaryRedirect)
	_, _ = c.Writer.WriteString(`Redirecting to application: ` + content.returnURL)
}

// Handles GET /portals/:portal/provider/:provider when using a seamless auth provider
// This performs seamless auth
func (s *Server) handleGetAuthProviderSeamlessAuth(c *gin.Context, portal Portal, returnURL string, provider auth.SeamlessProvider) {
	// Try to authenticate with the seamless auth
	var err error
	profile, err := provider.SeamlessAuth(c.Request)
	if err != nil {
		c.Set(logMessageContextKey, "Seamless authentication failed: "+err.Error())
		s.deleteSessionCookie(c, portal.Name)
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
		return
	}

	// Clear the state cookie for the portal
	s.deleteStateCookies(c, portal.Name)

	// Check if the user is allowed per rules
	err = provider.UserAllowed(profile)
	if err != nil {
		_ = c.Error(fmt.Errorf("access denied per allowlist rules: %w", err))
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Access denied per allowlist rules"))
		return
	}

	// Set the profile in the cookie
	err = s.setSessionCookie(c, portal.Name, profile)
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to set session cookie: %w", err))
		return
	}

	// We need to do a redirect to be able to have the cookies actually set
	// Also see: https://github.com/traefik/traefik/issues/3660
	c.Header("Location", returnURL)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Writer.WriteHeader(http.StatusSeeOther)
	_, _ = c.Writer.WriteString(`Redirecting to application: ` + returnURL)
}

// RouteGetLogout is the handler for GET /portals/:portal/logout
// This removes the session cookie
func (s *Server) RouteGetLogout(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Delete the state and session cookies
	s.deleteSessionCookie(c, portal.Name)
	s.deleteStateCookies(c, portal.Name)

	// Respond with a success message
	c.Header("Content-Type", "text/plain; charset=utf-8")
	_, _ = c.Writer.WriteString("You've logged out")
}

func (s *Server) getProfileFromContext(c *gin.Context) (*user.Profile, auth.Provider) {
	if !c.GetBool(sessionAuthContextKey) {
		return nil, nil
	}

	profileAny, ok := c.Get(sessionProfileContextKey)
	if !ok {
		return nil, nil
	}
	profile, ok := profileAny.(*user.Profile)
	if !ok || profile == nil || profile.ID == "" {
		return nil, nil
	}

	providerAny, ok := c.Get(sessionProviderContextKey)
	if !ok {
		return nil, nil
	}
	provider, ok := providerAny.(auth.Provider)
	if !ok || provider == nil {
		return nil, nil
	}

	return profile, provider
}

// Get the return URL, to redirect users to after a successful auth
func getReturnURL(c *gin.Context, portal string) string {
	// Traefik docs: https://doc.traefik.io/traefik/middlewares/http/forwardauth/
	// If there's no "X-Forwarded-Uri" header, it means that the auth request was not initiated by Traefik originally
	// In this case, we redirect to the /portal/:portal/profile route
	forwardedURI := c.Request.Header.Get("X-Forwarded-Uri")
	if forwardedURI == "" {
		return getPortalURI(c, portal) + "/profile"
	}

	// Here we use  X-Forwarded-* headers which have the data of the original request
	reqURL, _ := url.Parse(forwardedURI)
	return c.Request.Header.Get("X-Forwarded-Proto") + "://" + c.Request.Header.Get("X-Forwarded-Host") + reqURL.Path
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
// The URI is specific to each portal
func getOAuth2RedirectURI(c *gin.Context, portal string) string {
	return getPortalURI(c, portal) + "/oauth2/callback"
}

// Get the URI for a portal
func getPortalURI(c *gin.Context, portal string) string {
	cfg := config.Get()
	return c.GetHeader("X-Forwarded-Proto") + "://" + cfg.Server.Hostname + cfg.Server.BasePath + "/portals/" + portal
}
