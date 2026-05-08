package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwt/openid"
	"golang.org/x/text/unicode/norm"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

const (
	jwtIssuer             = "traefik-forward-auth-v4"
	stateCookieNamePrefix = "tf_state"
	acceptableClockSkew   = 30 * time.Second
	nonceSize             = 12 // Nonce size in bytes
	portalNameClaim       = "tf_portal"
	nonceClaim            = "tf_nonce"
	sigClaim              = "tf_sig"
	returnURLClaim        = "tf_return_url"

	maxTokenCacheTTL = 5 * time.Minute // Maximum TTL for token validation cache

	// Cookie chunking constants
	// The maximum size of a cookie is 4096 bytes
	// We use 3500 bytes per chunk to leave room for cookie metadata (name, domain, path, secure, httponly, samesite, maxage)
	maxCookieChunkSize = 3500
	// Maximum total cookie size is constrained by the server's MaxHeaderBytes (1MB)
	// With 3500 bytes per chunk, we can fit ~280 chunks in 1MB
	// We set a conservative limit to ensure we don't exceed header limits
	maxCookieChunks = 200
)

func (s *Server) getSessionCookie(c *gin.Context, portalName string) (profile *user.Profile, provider auth.Provider, err error) {
	cfg := config.Get()
	cookieName := cfg.Cookies.CookieName(portalName)

	// Get the base cookie
	cookieValue, err := c.Cookie(cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("failed to get session cookie: %w", err)
	}
	if cookieValue == "" {
		return nil, nil, fmt.Errorf("session cookie %s is empty", cookieName)
	}

	// Check if there are chunked cookies and reassemble them
	// Look for cookies with suffixes _1, _2, etc.
	var combinedValue strings.Builder
	for i := 1; i < maxCookieChunks; i++ {
		chunkName := cookieName + "_" + strconv.Itoa(i)
		chunkValue, err := c.Cookie(chunkName)
		if errors.Is(err, http.ErrNoCookie) {
			// No more chunks
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to get session cookie chunk %s: %w", chunkName, err)
		}
		if chunkValue == "" {
			return nil, nil, fmt.Errorf("session cookie chunk %s is empty", chunkName)
		}
		combinedValue.WriteString(chunkValue)
	}

	// Reassemble the cookie value if it was chunked
	if combinedValue.Len() > 0 {
		cookieValue += combinedValue.String()
	}

	// Get the cookie domain
	cookieDomain, ok := cookieDomainForContext(c)
	if !ok {
		return nil, nil, errors.New("request host does not match any configured cookie domain")
	}

	// Parse the JWT in the cookie
	token, err := s.parseSessionToken(cookieValue, portalName, cookieDomain)
	if err != nil {
		return nil, nil, err
	}

	// Get the user profile from the claim
	var providerName string
	_ = token.Get(user.ProviderNameClaim, &providerName)
	if providerName == "" {
		return nil, nil, fmt.Errorf("claim %s is missing or empty", user.ProviderNameClaim)
	}
	profile, err = user.NewProfileFromOpenIDToken(token, providerName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse claims from session token JWT: %w", err)
	}

	provider = s.portals[portalName].Providers[profile.Provider]
	if provider == nil {
		return nil, nil, errors.New("invalid provider in session token JWT")
	}

	// Populate additional claims if any
	provider.PopulateAdditionalClaims(token, profile.SetAdditionalClaim)

	return profile, provider, nil
}

func (s *Server) parseSessionToken(val string, portalName string, cookieDomain string) (openid.Token, error) {
	cfg := config.Get()
	audience := cfg.GetTokenAudienceClaim(cookieDomain)

	// Compute the hash of the token and expected audience for use as cache key
	cacheKey := s.tokenCacheKey(val + "\x00" + audience)

	// Check if the token validation result is in the cache
	valid, ok := s.tokenCache.Get(cacheKey)
	if ok {
		if !valid {
			// Token failed validation (cached result)
			return nil, errors.New("failed to parse session token JWT: token validation failed (cached)")
		}

		// Token was valid (cached result), now parse without validation to extract claims
		token, err := jwt.Parse([]byte(val),
			jwt.WithValidate(false),
			jwt.WithVerify(false),
			jwt.WithToken(openid.New()),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pre-validated session token JWT: %w", err)
		}

		oidcToken, ok := token.(openid.Token)
		if !ok {
			return nil, fmt.Errorf("JWT parsing returned unexpected token type: %T, expected openid.Token", token)
		}
		return oidcToken, nil
	}

	// Token not in cache, validate it
	token, err := jwt.Parse([]byte(val),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer+":"+audience+":"+portalName),
		jwt.WithAudience(audience),
		jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey()),
		jwt.WithToken(openid.New()),
	)

	// Determine validation result
	valid = err == nil
	var oidcToken openid.Token
	if valid {
		var ok bool
		oidcToken, ok = token.(openid.Token)
		if !ok {
			// This indicates a programming error in the JWT library or incorrect usage
			// We handle it gracefully with an error rather than panicking since this involves user input
			valid = false
			err = fmt.Errorf("JWT parsing returned unexpected token type: %T, expected openid.Token", token)
		}
	}

	// Compute the TTL for the cache based on validation result and token expiration
	ttl := computeTokenCacheTTL(oidcToken, !valid)

	// Store validation result in cache
	s.tokenCache.Set(cacheKey, valid, ttl)

	if !valid {
		return nil, fmt.Errorf("failed to parse session token JWT: %w", err)
	}
	return oidcToken, nil
}

func (s *Server) setSessionCookie(c *gin.Context, portalName string, profile *user.Profile, expiration time.Duration) error {
	// Get the domain for the cookie
	cookieDomain, ok := cookieDomainForContext(c)
	if !ok {
		return errors.New("request host does not match any configured cookie domain")
	}

	return s.setSessionCookieForDomain(c, portalName, profile, expiration, cookieDomain)
}

func (s *Server) setSessionCookieForReturnURL(c *gin.Context, portalName string, profile *user.Profile, expiration time.Duration, returnURL string) error {
	// Get the domain for the cookie from the return URL
	cookieDomain, ok := cookieDomainForReturnURL(c, returnURL)
	if !ok {
		return errors.New("return URL host does not match any configured cookie domain")
	}

	return s.setSessionCookieForDomain(c, portalName, profile, expiration, cookieDomain)
}

func (s *Server) setSessionCookieForDomain(c *gin.Context, portalName string, profile *user.Profile, expiration time.Duration, cookieDomain string) error {
	if profile == nil {
		return errors.New("profile is nil")
	}

	expiration = expiration.Truncate(time.Second)
	if expiration < time.Minute {
		return errors.New("expiration must be at least 1 minute")
	}

	cfg := config.Get()

	// Claims for the JWT
	now := time.Now()
	audience := cfg.GetTokenAudienceClaim(cookieDomain)
	builder := jwt.NewBuilder()
	profile.AppendClaims(builder)
	token, err := builder.
		Issuer(jwtIssuer + ":" + audience + ":" + portalName).
		Audience([]string{audience}).
		IssuedAt(now).
		// Add 1 extra second to synchronize with cookie expiry
		Expiration(now.Add(expiration + time.Second)).
		NotBefore(now).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build JWT: %w", err)
	}

	// Generate the JWT
	cookieValue, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey())).
		Serialize(token)
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	cookieName := cfg.Cookies.CookieName(portalName)
	tokenStr := string(cookieValue)

	// Check if we need to chunk the cookie
	if len(tokenStr) <= maxCookieChunkSize {
		// Cookie fits in a single chunk, set it normally
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(cookieName, tokenStr, int(expiration.Seconds())-1, "/", cookieDomain, !cfg.Cookies.Insecure, true)
		// Expire any stale chunked cookies the browser may still hold from a previous, larger session
		expireStaleSessionChunks(c, cookieName, 1, cookieDomain, !cfg.Cookies.Insecure)
		return nil
	}

	// Cookie needs to be chunked
	numChunks := (len(tokenStr) + maxCookieChunkSize - 1) / maxCookieChunkSize
	if numChunks > maxCookieChunks {
		return fmt.Errorf("cookie is too large: requires %d chunks but maximum is %d (cookie size: %d bytes, max total size: ~%d bytes)", numChunks, maxCookieChunks, len(tokenStr), maxCookieChunks*maxCookieChunkSize)
	}

	// Split the cookie into chunks
	c.SetSameSite(http.SameSiteLaxMode)
	for i := range numChunks {
		start := i * maxCookieChunkSize
		end := min(start+maxCookieChunkSize, len(tokenStr))
		chunk := tokenStr[start:end]

		var chunkName string
		if i == 0 {
			// First chunk uses the base cookie name
			chunkName = cookieName
		} else {
			// Subsequent chunks use the base name with a suffix
			chunkName = cookieName + "_" + strconv.Itoa(i)
		}

		c.SetCookie(chunkName, chunk, int(expiration.Seconds())-1, "/", cookieDomain, !cfg.Cookies.Insecure, true)
	}

	// Expire any stale chunks beyond the ones we just wrote
	expireStaleSessionChunks(c, cookieName, numChunks, cookieDomain, !cfg.Cookies.Insecure)

	return nil
}

func (s *Server) deleteSessionCookie(c *gin.Context, portalName string) {
	cfg := config.Get()
	cookieName := cfg.Cookies.CookieName(portalName)
	cookieDomain, ok := cookieDomainForContext(c)
	if !ok {
		return
	}

	// Check if the base cookie exists
	_, err := c.Cookie(cookieName)
	if err != nil {
		// Cookie was not set in the request, nothing to unset
		return
	}

	// Delete the base cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, "", -1, "/", cookieDomain, !cfg.Cookies.Insecure, true)

	// Delete any chunked cookies present in the request
	// We iterate over actual request cookies rather than probing names sequentially so a missing chunk in the middle does not stop us early
	expireStaleSessionChunks(c, cookieName, 1, cookieDomain, !cfg.Cookies.Insecure)
}

// expireStaleSessionChunks emits Max-Age=-1 Set-Cookie headers for any chunked session cookies in the request whose numeric suffix is >= startIdx
// Used to clean up stale chunks from previous, larger sessions when the new session uses fewer (or zero) chunks
func expireStaleSessionChunks(c *gin.Context, cookieName string, startIdx int, domain string, secure bool) {
	prefix := cookieName + "_"
	for _, cookie := range c.Request.Cookies() {
		if cookie == nil || !strings.HasPrefix(cookie.Name, prefix) {
			continue
		}

		idx, err := strconv.Atoi(cookie.Name[len(prefix):])
		if err != nil || idx < startIdx || idx >= maxCookieChunks {
			continue
		}

		c.SetCookie(cookie.Name, "", -1, "/", domain, secure, true)
	}
}

type stateCookieContent struct {
	portal    string
	nonce     string
	returnURL string
}

func (s *Server) getStateCookie(c *gin.Context, portal Portal, stateCookieID string) (content stateCookieContent, err error) {
	cfg := config.Get()

	// Get the cookie
	cookieValue, err := c.Cookie(stateCookieName(portal.Name, stateCookieID))
	if errors.Is(err, http.ErrNoCookie) {
		return stateCookieContent{}, nil
	} else if err != nil {
		return stateCookieContent{}, fmt.Errorf("failed to get cookie: %w", err)
	}
	if cookieValue == "" {
		return stateCookieContent{}, fmt.Errorf("cookie %s is empty", cfg.Cookies.NamePrefix)
	}

	// Get the cookie domain and expected audience
	cookieDomain, ok := cookieDomainForContext(c)
	if !ok {
		return stateCookieContent{}, errors.New("request host does not match any configured cookie domain")
	}
	audience := cfg.GetTokenAudienceClaim(cookieDomain)

	// Parse the JWT in the cookie
	token, err := jwt.Parse([]byte(cookieValue),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer+":"+audience+":"+portal.Name),
		jwt.WithAudience(audience),
		jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey()),
	)
	if err != nil {
		return stateCookieContent{}, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get the portal name
	_ = token.Get(portalNameClaim, &content.portal)
	if content.portal == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", portalNameClaim)
	} else if content.portal != portal.Name {
		return stateCookieContent{}, errors.New("portal claim in JWT does not match expected value")
	}

	// Get the nonce
	_ = token.Get(nonceClaim, &content.nonce)
	if content.nonce == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", nonceClaim)
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(content.nonce)
	if err != nil || len(nonceBytes) != nonceSize {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", nonceClaim)
	}

	// Get the return URL
	_ = token.Get(returnURLClaim, &content.returnURL)
	if content.returnURL == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", returnURLClaim)
	}

	// Validate the signature inside the token
	var sig string
	expectSig := stateCookieSig(c, stateCookieID, content.portal, nonceBytes)
	_ = token.Get(sigClaim, &sig)
	if sig == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", sigClaim)
	} else if sig != expectSig {
		return stateCookieContent{}, fmt.Errorf("claim '%s' invalid in JWT", sigClaim)
	}

	return content, nil
}

func (s *Server) generateNonce() (string, error) {
	nonceBytes := make([]byte, nonceSize)
	_, err := io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		return "", fmt.Errorf("failed to get random data: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonceBytes), nil
}

func (s *Server) setStateCookie(c *gin.Context, portal Portal, nonce string, returnURL string, stateCookieID string) (err error) {
	cfg := config.Get()
	expiration := portal.AuthenticationTimeout

	// Computes a signature that includes certain properties from the request that are sufficiently stable
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}
	sig := stateCookieSig(c, stateCookieID, portal.Name, nonceBytes)

	// Get the cookie domain and audience
	cookieDomain, ok := cookieDomainForReturnURL(c, returnURL)
	if !ok {
		return errors.New("return URL host does not match any configured cookie domain")
	}
	audience := cfg.GetTokenAudienceClaim(cookieDomain)

	// Claims for the JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer+":"+audience+":"+portal.Name).
		Audience([]string{audience}).
		IssuedAt(now).
		// Add 1 extra second to synchronize with cookie expiry
		Expiration(now.Add(expiration+time.Second)).
		NotBefore(now).
		Claim(portalNameClaim, portal.Name).
		Claim(nonceClaim, nonce).
		Claim(sigClaim, sig).
		Claim(returnURLClaim, returnURL).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build JWT: %w", err)
	}

	// Generate the JWT
	cookieValue, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey())).
		Serialize(token)
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	// Set the cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(stateCookieName(portal.Name, stateCookieID), string(cookieValue), int(expiration.Seconds())-1, "/", cookieDomain, !cfg.Cookies.Insecure, true)

	// Return the nonce
	return nil
}

func (s *Server) deleteStateCookies(c *gin.Context, portalName string) {
	cfg := config.Get()
	prefix := stateCookieName(portalName, "")

	// Get the domain for the cookie
	cookieDomain, ok := cookieDomainForContext(c)
	if !ok {
		return
	}

	// Iterate through all cookies looking for state ones
	c.SetSameSite(http.SameSiteLaxMode)
	for _, cookie := range c.Request.Cookies() {
		if cookie == nil || !strings.HasPrefix(cookie.Name, prefix) {
			continue
		}

		// We found a state cookie; remove it
		c.SetCookie(cookie.Name, "", -1, "/", cookieDomain, !cfg.Cookies.Insecure, true)
	}
}

func cookieDomainForContext(c *gin.Context) (string, bool) {
	cfg := config.Get()

	// Prefer the request host so the selected cookie domain matches the app being accessed
	host := requestHost(c)
	if host != "" {
		return cfg.Cookies.DomainForHost(host)
	}

	// If no host is available and domains are not configured, fall back to a host-only cookie
	if len(cfg.Cookies.Domains) == 0 {
		return "", true
	}

	// Without a request host, use the first configured domain so cleanup paths can still expire cookies
	return cfg.Cookies.Domains[0], true
}

func cookieDomainForReturnURL(c *gin.Context, returnURL string) (string, bool) {
	// Return URLs identify the app that will receive the cookie after authentication
	// Matching against that host prevents setting cookies for an unrelated configured domain
	u, err := url.Parse(returnURL)
	if err == nil && u != nil && u.Host != "" {
		cfg := config.Get()
		return cfg.Cookies.DomainForHost(u.Host)
	}

	// Malformed or relative return URLs fall back to the current request context
	return cookieDomainForContext(c)
}

func requestHost(c *gin.Context) string {
	// Traefik sends the original application host in X-Forwarded-Host
	// That is the host cookies must be scoped to when this service is behind the forward-auth middleware
	host := c.Request.Header.Get(headerXForwardedHost)
	if host != "" {
		return host
	}

	// Direct requests and tests may not include X-Forwarded-Host, so fall back to the HTTP request host
	if c.Request != nil {
		host = c.Request.Host
		if host != "" {
			return host
		}
	}

	return ""
}

func stateCookieName(portalName string, stateCookieID string) string {
	return stateCookieNamePrefix + "_" + portalName + "_" + stateCookieID
}

func stateCookieSig(c *gin.Context, stateCookieID string, portalName string, nonce []byte) string {
	h := hmac.New(sha256.New224, nonce)
	h.Write([]byte("tfa-state-sig"))
	h.Write([]byte(stateCookieID))
	h.Write([]byte(strings.ToLower(norm.NFKD.String(c.GetHeader("User-Agent")))))
	h.Write([]byte(strings.ToLower(norm.NFKD.String(c.GetHeader("Accept-Language")))))
	h.Write([]byte(strings.ToLower(norm.NFKD.String(c.GetHeader("DNT")))))
	h.Write([]byte(portalName))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// tokenCacheKey computes the hash of the token string (using xxHash, variant XXH64) for use as a cache key
func (s *Server) tokenCacheKey(tokenStr string) uint64 {
	return xxhash.Sum64String(tokenStr)
}

// computeTokenCacheTTL computes the TTL for a token validation result in the cache
// For valid (unexpired) tokens, the TTL is the minimum of maxTokenCacheTTL or the token's expiration time
// For invalid tokens, the TTL is always maxTokenCacheTTL
func computeTokenCacheTTL(token openid.Token, invalid bool) time.Duration {
	// If the token validation failed, cache for maxTokenCacheTTL
	if invalid {
		return maxTokenCacheTTL
	}

	// Get the token's expiration time
	exp, ok := token.Expiration()
	if !ok || exp.IsZero() {
		// No expiration, cache for maxTokenCacheTTL
		return maxTokenCacheTTL
	}

	// Compute time until expiration
	ttl := time.Until(exp)
	if ttl <= 0 {
		// Token already expired but was successfully parsed
		// Cache for maxTokenCacheTTL since the token is expired
		return maxTokenCacheTTL
	}

	// Return the minimum of maxTokenCacheTTL and time until expiration
	return min(ttl, maxTokenCacheTTL)
}
