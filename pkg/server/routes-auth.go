package server

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/conditions"
)

// RouteGetAuthRoot is the handler for GET /portals/:portal
// This handles requests from Traefik and redirects users if needed
func (s *Server) RouteGetAuthRoot(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Check if we have a session already
	profile, provider := s.getProfileFromContext(c)
	if profile != nil && provider != nil {
		// We already have a session
		// We normally get to this point when Traefik is checking if the request can proceed
		s.handleAuthenticatedRoot(c, portal, provider, profile)
		return
	}

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
	// We also generate a new one if the cookie's sign-in has already completed, so a nonce is never used to start a new sign-in after it was consumed
	nonce := content.nonce
	if nonce == "" || content.consumed {
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
	signInURL := getSigninURL(c, portal.Name, stateCookieID, nonce)
	if utils.IsTruthy(c.Query("logout")) {
		// Check if the user has just logged out and forward the query string parameter to the signin page for the banner to be shown
		signInURL += "&logout=1"
	}

	c.Header(headerLocation, signInURL)
	c.Header(headerContentType, contentTypeTextPlain)
	c.Writer.WriteHeader(http.StatusSeeOther)
	_, _ = c.Writer.WriteString(`Redirecting to sign-in page: ` + signInURL)
}

func (s *Server) handleAuthenticatedRoot(c *gin.Context, portal *Portal, provider auth.Provider, profile *user.Profile) {
	// Check if there's any condition ("if" query string arg or "X-Forward-Auth-If" header) to check claims against, for AuthZ
	cond := c.Query("if")
	condHeader := headerValue(c.Request.Header, headerXForwardAuthIf)
	if cond != "" && condHeader != "" {
		_ = c.Error(errors.New("condition passed in both 'if' query string arg and '" + headerXForwardAuthIf + "' header"))
		AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Authorization condition passed in both 'if' query string arg and '"+headerXForwardAuthIf+"' header"))
		return
	} else if condHeader != "" {
		cond = condHeader
	}

	if cond != "" {
		ok, err := s.checkAuthzConditions(cond, profile)

		if err != nil {
			// Errors indicate thins such as invalid condition
			_ = c.Error(fmt.Errorf("failed to check authorization rules: %w", err))
			AbortWithError(c, NewResponseErrorf(http.StatusBadRequest, "Invalid authorization rules"))
			return
		} else if !ok {
			// The token is not authorized
			s.metrics.RecordAuthentication(false)
			AbortWithError(c, NewResponseErrorf(http.StatusForbidden, "Access denied per authorization rules"))
			return
		}
	}

	// If we are here, we have a valid session, so respond with a 200 status code
	// Include the user name in the response body in case a visitor is hitting the auth server directly
	s.metrics.RecordAuthentication(true)

	// Add authenticated headers to the response
	setAuthenticatedHeaders(c, portal, provider, profile)

	// Note: while ugly-ish, concatenating the response body is the cheapest option, considering this runs on every request Traefik forwards
	switch {
	case utils.IsTruthy(c.Query("html")):
		s.renderAuthenticatedTemplate(c, portal, provider, profile.ID)
	case profile.Name.FullName != "":
		_, _ = c.Writer.WriteString(`You are authenticated with provider '` + provider.GetProviderDisplayName() + `' as '` + profile.Name.FullName + `' ('` + profile.ID + `')`)
	default:
		_, _ = c.Writer.WriteString(`You are authenticated with provider '` + provider.GetProviderDisplayName() + `' as '` + profile.ID + `'`)
	}
}

func (s *Server) checkAuthzConditions(cond string, profile *user.Profile) (bool, error) {
	var err error

	// Get the predicate from the cache
	// Note: we use Get and Set separately, instead of atomic operations like GetOrCompute, because we need to be able to handle errors
	// This means there's a chance that we may compute the same predicate twice, if two requests happen in parallel, but it's acceptable in this case
	var predicate conditions.UserProfilePredicate
	cached, ok := s.predicates.Get(cond)
	if ok {
		predicate = cached.predicate
		cached.lastUsed.Store(time.Now().Unix())
	} else {
		predicate, err = conditions.NewPredicate(cond)
		if err != nil {
			return false, fmt.Errorf("authorization condition is not valid: %w", err)
		}

		cached := cachedPredicate{
			predicate: predicate,
			lastUsed:  &atomic.Int64{},
		}
		cached.lastUsed.Store(time.Now().Unix())
		s.predicates.Set(cond, cached)
	}

	// Evaluate the condition
	ok = predicate(profile)
	return ok, nil
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
	// If the nonce in the query string doesn't match the state cookie, we continue with the nonce from the cookie
	// That happens when another tab started a sign-in for the same return URL and the browser kept that tab's state cookie, so this tab joins the other sign-in
	// This doesn't let a request do anything it couldn't already do: RouteGetAuthRoot also redirects any request that includes the state cookie to this page with the cookie's nonce
	content, stateCookieID, _, err := s.parseStateParamPreAuth(c, portal)
	if err != nil {
		// In the signin page, if there's an error, it's probably due to something wrong with the cookie
		// For the best user experience, we redirect the user back to the portal's main page (after deleting the state cookie) so a new cookie can be set
		// Only the state cookie this request refers to is deleted, because other ones may belong to sign-ins in progress in other tabs
		_ = c.Error(err)

		if stateCookieID != "" {
			s.deleteStateCookie(c, portal.Name, stateCookieID)
		}

		redirectURL := getPortalURI(c, portal.Name)
		c.Header(headerLocation, redirectURL)
		c.Header(headerContentType, contentTypeTextPlain)
		c.Writer.WriteHeader(http.StatusSeeOther)
		_, _ = c.Writer.WriteString(`Redirecting to auth portal: ` + redirectURL)
		return
	}

	// Check if the user has just logged out, and if so, display the logged out banner
	logoutBanner := utils.IsTruthy(c.Query("logout"))

	// If there's a single provider, we redirect the user to that directly, unless AlwaysShowProvidersPage is true
	// We also always display the signing page if the user just logged out
	if len(portal.ProvidersList) == 1 && !portal.AlwaysShowSigninPage && !logoutBanner {
		providerName := portal.ProvidersList[0]
		redirectURL := getPortalURI(c, portal.Name) + "/providers/" + providerName + "?state=" + stateCookieID + "~" + content.nonce
		c.Header(headerLocation, redirectURL)
		c.Header(headerContentType, contentTypeTextPlain)
		c.Writer.WriteHeader(http.StatusSeeOther)
		_, _ = c.Writer.WriteString(`Redirecting to provider: ` + redirectURL)
		return
	}

	// Render the template
	s.renderSigninTemplate(c, portal, stateCookieID, content.nonce, logoutBanner)
}

// Parses the "state" query string parameter and loads the state cookie it refers to
// If the state cookie is valid but its nonce differs from the one in the query string, nonceMatches is false and the returned content describes the sign-in from the cookie
// That happens when several tabs start a sign-in for the same return URL at once, because they share a state cookie and the browser keeps the one it received last
// The state cookie ID is returned whenever the query string parameter can be parsed, even if loading the cookie fails
func (s *Server) parseStateParamPreAuth(c *gin.Context, portal *Portal) (content stateCookieContent, stateCookieID string, nonceMatches bool, err error) {
	// Ensure we have a valid state parameter
	state, err := getStateParam(c, portal, false)
	if err != nil {
		return stateCookieContent{}, "", false, err
	}
	stateCookieID = state.stateCookieID

	// Get the state cookie
	content, err = s.getStateCookie(c, portal, stateCookieID)
	if err != nil {
		return stateCookieContent{}, stateCookieID, false, fmt.Errorf("invalid state cookie: %w", err)
	} else if content.nonce == "" {
		return stateCookieContent{}, stateCookieID, false, NewResponseError(http.StatusUnauthorized, "State cookie not found")
	}

	return content, stateCookieID, content.nonce == state.nonce, nil
}

// stateParam is the parsed and validated "state" query string parameter
type stateParam struct {
	// Raw value of the query string parameter
	raw string
	// May be empty when the parameter does not includes the provider name
	provider      auth.Provider
	stateCookieID string
	nonce         string
}

// Parses and validates the "state" query string parameter
// The format is "StateCookieID~Nonce", or "Provider~StateCookieID~Nonce" when withProvider is true (OAuth2 callbacks)
// Every part is validated before it's used, so it's safe to include in cookie names, URLs, and responses
func getStateParam(c *gin.Context, portal *Portal, withProvider bool) (stateParam, error) {
	raw := c.Query("state")
	if raw == "" {
		return stateParam{}, NewResponseError(http.StatusBadRequest, "The parameter 'state' is required in the query string")
	}

	res := stateParam{raw: raw}
	rest := raw

	if withProvider {
		providerName, after, ok := strings.Cut(rest, "~")
		if !ok {
			return stateParam{}, NewResponseError(http.StatusUnauthorized, "Query string parameter 'state' is invalid")
		}
		rest = after

		// Validate the name against the portal's providers
		provider, ok := portal.Providers[providerName]
		if !ok {
			return stateParam{}, NewResponseError(http.StatusConflict, "Auth provider not found")
		}

		res.provider = provider
	}

	var ok bool
	res.stateCookieID, res.nonce, ok = strings.Cut(rest, "~")
	if !ok ||
		!isValidStateToken(res.stateCookieID, stateCookieIDLen) ||
		!isValidStateToken(res.nonce, stateNonceLen) {
		return stateParam{}, NewResponseError(http.StatusUnauthorized, "Query string parameter 'state' is invalid")
	}

	return res, nil
}

// Reports whether s has exactly the given length and only contains characters of the unpadded base64url alphabet
func isValidStateToken(s string, length int) bool {
	if len(s) != length {
		return false
	}

	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z',
			ch >= 'A' && ch <= 'Z',
			ch >= '0' && ch <= '9',
			ch == '-', ch == '_':
		default:
			return false
		}
	}

	return true
}

// RouteGetAuthProvider is the handler for GET /portals/:portal/providers/:provider
// This redirects users to auth servers
func (s *Server) RouteGetAuthProvider(c *gin.Context) {
	portal, provider, err := s.getProvider(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Ensure we have a state parameter
	content, stateCookieID, nonceMatches, err := s.parseStateParamPreAuth(c, portal)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// If the nonce doesn't match, another tab started a sign-in for the same return URL and the browser kept that tab's state cookie
	// We send the user back to the sign-in page with the nonce from the cookie, so this tab joins the other sign-in
	// We don't continue with the provider directly, so a request with a mismatched nonce can't choose the provider on the user's behalf
	if !nonceMatches {
		redirectURL := getSigninURL(c, portal.Name, stateCookieID, content.nonce)
		c.Header(headerLocation, redirectURL)
		c.Header(headerContentType, contentTypeTextPlain)
		c.Writer.WriteHeader(http.StatusSeeOther)
		_, _ = c.Writer.WriteString(`Redirecting to sign-in page: ` + redirectURL)
		return
	}

	switch provider := provider.(type) {
	case auth.OAuth2Provider:
		s.handleGetAuthProviderOAuth2(c, portal, stateCookieID, content.nonce, provider)
	case auth.SeamlessProvider:
		s.handleGetAuthProviderSeamlessAuth(c, portal, stateCookieID, content, provider)
	}
}

// Handles GET /portals/:portal/providers/:provider when using an OAuth2-based provider
// This redirects users to the OAuth2 Identity Provider
func (s *Server) handleGetAuthProviderOAuth2(c *gin.Context, portal *Portal, stateCookieID string, nonce string, provider auth.OAuth2Provider) {
	var err error

	// Redirect to the authorization URL
	stateParam := provider.GetProviderName() + "~" + stateCookieID + "~" + nonce
	authURL, err := provider.OAuth2AuthorizeURL(stateParam, getOAuth2RedirectURI(c, portal.Name))
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to get authorize URL: %w", err))
		return
	}

	// Use a custom redirect code to write a response in the body
	c.Header(headerLocation, authURL)
	c.Header(headerContentType, contentTypeTextPlain)
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
		setLogMessage(c, "Error from the app server: "+qsErr)
		AbortWithError(c, NewResponseError(http.StatusFailedDependency, "The auth server returned an error"))
		return
	}

	// Ensure that we have valid state and code parameters
	// Format of the state is: "Provider~StateCookieID~Nonce"
	state, err := getStateParam(c, portal, true)
	if err != nil {
		AbortWithError(c, err)
		return
	}
	codeParam := c.Query("code")
	if codeParam == "" {
		AbortWithError(c, NewResponseError(http.StatusBadRequest, "The parameter 'code' is required in the query string"))
		return
	}

	// Get the state cookie
	content, err := s.getStateCookie(c, portal, state.stateCookieID)
	if err != nil {
		AbortWithError(c, fmt.Errorf("invalid state cookie: %w", err))
		return
	} else if content.nonce == "" {
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "State cookie not found"))
		return
	}

	// The provider must support OAuth2
	provider, ok := state.provider.(auth.OAuth2Provider)
	if !ok {
		AbortWithError(c, NewResponseError(http.StatusConflict, "Auth provider does not implement OAuth2"))
		return
	}

	// Check if the nonce matches
	if content.nonce != state.nonce {
		// The state cookie is valid, but it belongs to a different sign-in than the one the identity provider returned
		// That happens when another tab started a sign-in for the same return URL and the browser kept that tab's state cookie
		// The authorization code is bound to this tab's state, so it can't be used with the cookie
		// Instead, we restart from the return URL saved in the cookie, and RouteGetAuthRoot will re-use the cookie's nonce so this tab joins the other sign-in
		// The authorization code is never exchanged, so this is also safe when the request is a login CSRF attempt
		setLogMessage(c, "Nonce in state token does not match state cookie: restarting sign-in from the return URL")
		c.Header(headerLocation, content.returnURL)
		c.Header(headerContentType, contentTypeTextPlain)
		c.Writer.WriteHeader(http.StatusSeeOther)
		_, _ = c.Writer.WriteString(`Redirecting to application: ` + content.returnURL)
		return
	}

	// Mark the state cookie as consumed
	// Other tabs that joined this sign-in can still finish for a short time, but the nonce can't be used to start a new sign-in
	// Other state cookies are left alone, because they may belong to sign-ins in progress in other tabs
	err = s.consumeStateCookie(c, portal, state.stateCookieID, content)
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to update state cookie: %w", err))
		return
	}

	// Exchange the code for a token
	at, err := provider.OAuth2ExchangeCode(c.Request.Context(), state.raw, codeParam, getOAuth2RedirectURI(c, portal.Name))
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

	// Set the profile in the cookie
	err = s.setSessionCookieForReturnURL(c, portal.Name, profile, portal.SessionLifetime, content.returnURL)
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to set session cookie: %w", err))
		return
	}

	// Use a custom redirect code to write a response in the body
	// We use a 307 redirect here so the client can re-send the request with the original method
	c.Header(headerLocation, content.returnURL)
	c.Header(headerContentType, contentTypeTextPlain)
	c.Writer.WriteHeader(http.StatusTemporaryRedirect)
	_, _ = c.Writer.WriteString(`Redirecting to application: ` + content.returnURL)
}

// Handles GET /portals/:portal/providers/:provider when using a seamless auth provider
// This performs seamless auth
func (s *Server) handleGetAuthProviderSeamlessAuth(c *gin.Context, portal *Portal, stateCookieID string, content stateCookieContent, provider auth.SeamlessProvider) {
	// Try to authenticate with the seamless auth
	var err error
	profile, err := provider.SeamlessAuth(c.Request)
	if err != nil {
		setLogMessage(c, "Seamless authentication failed: "+err.Error())
		s.deleteSessionCookie(c, portal.Name)
		AbortWithError(c, NewResponseError(http.StatusUnauthorized, "Not authenticated"))
		return
	}

	// Mark the state cookie as consumed
	// Other tabs that joined this sign-in can still finish for a short time, but the nonce can't be used to start a new sign-in
	// Other state cookies are left alone, because they may belong to sign-ins in progress in other tabs
	err = s.consumeStateCookie(c, portal, stateCookieID, content)
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to update state cookie: %w", err))
		return
	}

	// Set the profile in the cookie
	err = s.setSessionCookieForReturnURL(c, portal.Name, profile, portal.SessionLifetime, content.returnURL)
	if err != nil {
		AbortWithError(c, fmt.Errorf("failed to set session cookie: %w", err))
		return
	}

	// We need to do a redirect to be able to have the cookies actually set
	// Also see: https://github.com/traefik/traefik/issues/3660
	c.Header(headerLocation, content.returnURL)
	c.Header(headerContentType, contentTypeTextPlain)
	c.Writer.WriteHeader(http.StatusSeeOther)
	_, _ = c.Writer.WriteString(`Redirecting to application: ` + content.returnURL)
}

// RoutePostLogout is the handler for POST /portals/:portal/logout
// This removes the session cookie
func (s *Server) RoutePostLogout(c *gin.Context) {
	portal, err := s.getPortal(c)
	if err != nil {
		AbortWithError(c, err)
		return
	}

	// Delete the state and session cookies
	s.deleteSessionCookie(c, portal.Name)
	s.deleteStateCookies(c, portal.Name)

	// Respond with a success message
	portalURL := getPortalURI(c, portal.Name) + "?logout=1"
	c.Header(headerLocation, portalURL)
	c.Header(headerContentType, contentTypeTextPlain)
	c.Writer.WriteHeader(http.StatusSeeOther)
	_, _ = c.Writer.WriteString(`You've been logged out. Redirecting to portal: ` + portalURL)
}

func (s *Server) getProfileFromContext(c *gin.Context) (*user.Profile, auth.Provider) {
	rs := getRequestState(c)
	if rs == nil || !rs.authenticated {
		return nil, nil
	}

	if rs.profile == nil || rs.profile.ID == "" || rs.provider == nil {
		return nil, nil
	}

	return rs.profile, rs.provider
}

// Get the return URL, to redirect users to after a successful auth
func getReturnURL(c *gin.Context, portal string) string {
	// Traefik docs: https://doc.traefik.io/traefik/middlewares/http/forwardauth/
	// If there's no "X-Forwarded-Uri" header, it means that the auth request was not initiated by Traefik originally
	// In this case, we redirect to the /portal/:portal/profile route
	forwardedURI := headerValue(c.Request.Header, headerXForwardedURI)
	if forwardedURI == "" {
		return getPortalURI(c, portal) + "/profile"
	}

	// Parse the forwarded URI and rebuild the return URL using only the path-and-query portion
	// RequestURI() returns the unmodified request-URI form (path + "?" + raw query) and ignores any scheme/host the client may have included, so an absolute or scheme-relative X-Forwarded-Uri cannot redirect off-host
	// We deliberately preserve the query string
	reqURL, err := url.Parse(forwardedURI)
	if err != nil || reqURL == nil {
		return getPortalURI(c, portal) + "/profile"
	}

	return getForwardedProto(c) + "://" + headerValue(c.Request.Header, headerXForwardedHost) + reqURL.RequestURI()
}

const (
	stateCookieIDBytes = 8
	stateCookieIDLen   = 11 // Length of stateCookieIDBytes bytes encoded as unpadded base64
	stateNonceLen      = 16 // Length of nonceSize bytes encoded as unpadded base64
)

// Computes the state cookie ID for the given return URL
func getStateCookieID(returnURL string) string {
	h := sha256.New()
	h.Write([]byte("tf_return_url:"))
	h.Write([]byte(returnURL))
	digest := h.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(digest[:stateCookieIDBytes])
}

// Get the URL of the sign-in page for the sign-in identified by the state cookie ID and nonce
func getSigninURL(c *gin.Context, portalName string, stateCookieID string, nonce string) string {
	return getPortalURI(c, portalName) + "/signin?state=" + stateCookieID + "~" + nonce
}

// Get the redirect URI, which is sent to the OAuth2 authentication server and indicates where to return users after a successful auth with the IdP
// The URI is specific to each portal
func getOAuth2RedirectURI(c *gin.Context, portal string) string {
	return getPortalURI(c, portal) + "/oauth2/callback"
}

// Get the URI for a portal
// In "dedicated sub-domain" mode the matched domain has a configured `authHost` that differs from the request host (Traefik Forward Auth lives at e.g. auth.example.com while apps live at app.example.com)
// In "sub-path" mode the auth host equals the request host
func getPortalURI(c *gin.Context, portal string) string {
	cfg := config.Get()

	host := requestHost(c)
	_, authHost, ok := cfg.Server.DomainForHost(host)
	if ok && authHost != "" {
		host = authHost
	}

	baseURI := getForwardedProto(c) + "://" + host + cfg.Server.BasePath

	// If the user is visiting the default portal and they're using the "short" format, we omit the portal name in the URL
	if c.Param("portal") == "" && cfg.DefaultPortal == portal {
		return baseURI
	}

	return baseURI + "/portals/" + portal
}

// Returns the value from the X-Forwarded-Proto header, handling WebSockets
func getForwardedProto(c *gin.Context) string {
	// Map WebSocket protocols to HTTP protocols for OAuth2 redirect URI
	// OAuth2 callback URLs must be HTTP/HTTPS for browsers to navigate to
	switch headerValue(c.Request.Header, headerXForwardedProto) {
	case "ws":
		return "http"
	case "wss":
		return "https"
	case "https":
		return "https"
	default:
		// Fallback to HTTP for unknown protocols
		return "http"
	}
}

// Validates the header value before adding it to the response
func validateHeaderValue(value string) string {
	// Limit the value to 1KB
	const maxLen = 1 << 10

	if len(value) > maxLen {
		return ""
	}
	return value
}
