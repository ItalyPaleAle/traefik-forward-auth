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
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
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

// errCachedTokenValidationFailed indicates that the session token failed validation on a previous request and the negative result was served from the cache
var errCachedTokenValidationFailed = errors.New("session token validation failed (cached result)")

func (s *Server) getSessionCookie(c *gin.Context, portalName string) (profile *user.Profile, provider auth.Provider, err error) {
	cfg := config.Get()
	cookieName := cfg.Cookies.CookieName(portalName)

	// Read the session cookie, reassembling it from chunk cookies (suffixes _1, _2, ...) if needed
	// This parses the request's Cookie header only once
	cookieValue, err := readSessionCookieValue(c, cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, err
	}

	// Get the cookie domain
	cookieDomain, _, ok := cookieDomainForContext(c)
	if !ok {
		return nil, nil, errors.New("request host does not match any configured cookie domain")
	}

	// Parse the JWT in the cookie
	token, err := s.parseSessionToken(cookieValue, portalName, cookieDomain)
	if err != nil {
		return nil, nil, err
	}

	// Get the user profile from the claim
	providerName, _ := jwt.Get[string](token, user.ProviderNameClaim)
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

// readSessionCookieValue returns the session cookie value, reassembling it from the base cookie plus any chunk cookies ("<cookieName>_1", "<cookieName>_2", ...)
// It returns http.ErrNoCookie when the base cookie is not present
func readSessionCookieValue(c *gin.Context, cookieName string) (string, error) {
	// Parse the Cookie header once
	reqCookies := c.Request.Cookies()

	// Find the base cookie and collect any chunk cookies in a single pass
	// Chunks are rare, so the map stays nil for the common single-cookie case
	var (
		baseValue string
		haveBase  bool
		chunks    map[int]string
	)
	chunkPrefix := cookieName + "_"
	for _, ck := range reqCookies {
		switch {
		case ck.Name == cookieName:
			// Keep the first occurrence, matching net/http's Request.Cookie lookup
			if !haveBase {
				baseValue = ck.Value
				haveBase = true
			}
		case strings.HasPrefix(ck.Name, chunkPrefix):
			idx, aErr := strconv.Atoi(ck.Name[len(chunkPrefix):])
			if aErr != nil || idx < 1 || idx >= maxCookieChunks {
				continue
			}
			if chunks == nil {
				chunks = make(map[int]string, 4)
			}
			chunks[idx] = ck.Value
		}
	}

	if !haveBase {
		return "", http.ErrNoCookie
	}

	// Cookie values are URL-encoded when written (gin escapes them), so decode to match c.Cookie's behavior
	baseValue = cookieValueUnescape(baseValue)
	if baseValue == "" {
		return "", fmt.Errorf("session cookie %s is empty", cookieName)
	}

	// Fast path: the cookie was not chunked
	if len(chunks) == 0 {
		return baseValue, nil
	}

	// Reassemble the base value with contiguous chunks starting at index 1, stopping at the first gap
	var sb strings.Builder
	sb.WriteString(baseValue)
	for i := 1; ; i++ {
		chunkValue, ok := chunks[i]
		if !ok {
			break
		}
		chunkValue = cookieValueUnescape(chunkValue)
		if chunkValue == "" {
			return "", fmt.Errorf("session cookie chunk %s%d is empty", chunkPrefix, i)
		}
		sb.WriteString(chunkValue)
	}
	return sb.String(), nil
}

// cookieValueUnescape decodes a cookie value the same way gin's c.Cookie does
// url.QueryUnescape returns the input unchanged when there is nothing to decode (the regular case for our base64url JWT values)
func cookieValueUnescape(v string) string {
	unescaped, _ := url.QueryUnescape(v)
	return unescaped
}

// invalidSessionCookieIsSuspicious reports whether an error returned by getSessionCookie is "suspicious" (worth a security warning).
// An expired token is a normal, expected event and returns false.
// A cached negative validation result also returns false, so that repeatedly presenting the same invalid cookie doesn't flood the logs (the first, uncached attempt is what gets logged).
// Anything else (a bad signature, a malformed JWT, a wrong issuer/audience, etc) may indicate a tampered cookie and returns true.
func invalidSessionCookieIsSuspicious(err error) bool {
	return !errors.Is(err, jwt.TokenExpiredError{}) && !errors.Is(err, errCachedTokenValidationFailed)
}

// tokenCacheEntry is the result of a session token validation, stored in the token cache
// valid reports whether the token passed validation; token holds the parsed token when valid, so subsequent requests can reuse it without re-parsing
type tokenCacheEntry struct {
	token openid.Token
	valid bool
}

func (s *Server) parseSessionToken(val string, portalName string, cookieDomain string) (openid.Token, error) {
	cfg := config.Get()
	audience := cfg.GetTokenAudienceClaim(cookieDomain)

	// Compute the cache key from the token, expected audience, and portal
	cacheKey := s.tokenCacheKey(val, audience, portalName)

	// Check if we have a cached validation result for this token
	cached, ok := s.tokenCache.Get(cacheKey)
	if ok {
		if !cached.valid {
			return nil, errCachedTokenValidationFailed
		}
		return cached.token, nil
	}

	// Not in the cache: validate the token's signature and claims
	token, err := jwt.Parse([]byte(val),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer+":"+audience+":"+portalName),
		jwt.WithAudience(audience),
		jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey()),
		jwt.WithToken(openid.New()),
	)

	// Extract the concrete openid.Token from a successful parse
	var oidcToken openid.Token
	if err == nil {
		var typeOk bool
		oidcToken, typeOk = token.(openid.Token)
		if !typeOk {
			// This indicates a programming error in the JWT library or incorrect usage
			// We handle it gracefully with an error rather than panicking since this involves user input
			err = fmt.Errorf("JWT parsing returned unexpected token type: %T, expected openid.Token", token)
			oidcToken = nil
		}
	}

	// Cache the result so subsequent requests can skip re-parsing, which is the dominant cost on the session-validation hot path
	// openid.Token guards all reads with a RWMutex, so the cached token is safe to share across concurrent requests
	ttl := computeTokenCacheTTL(oidcToken, err != nil)
	s.tokenCache.Set(cacheKey, tokenCacheEntry{token: oidcToken, valid: err == nil}, ttl)

	if err != nil {
		return nil, fmt.Errorf("failed to parse session token JWT: %w", err)
	}
	return oidcToken, nil
}

func (s *Server) setSessionCookie(c *gin.Context, portalName string, profile *user.Profile, expiration time.Duration) error {
	// Get the domain for the cookie
	cookieDomain, _, ok := cookieDomainForContext(c)
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
	cookieDomain, _, ok := cookieDomainForContext(c)
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
	cookieDomain, _, ok := cookieDomainForContext(c)
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
	content.portal, _ = jwt.Get[string](token, portalNameClaim)
	if content.portal == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", portalNameClaim)
	} else if content.portal != portal.Name {
		return stateCookieContent{}, errors.New("portal claim in JWT does not match expected value")
	}

	// Get the nonce
	content.nonce, _ = jwt.Get[string](token, nonceClaim)
	if content.nonce == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", nonceClaim)
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(content.nonce)
	if err != nil || len(nonceBytes) != nonceSize {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", nonceClaim)
	}

	// Get the return URL
	content.returnURL, _ = jwt.Get[string](token, returnURLClaim)
	if content.returnURL == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", returnURLClaim)
	}

	// Validate the signature inside the token
	expectSig := stateCookieSig(c, stateCookieID, content.portal, nonceBytes)
	sig, _ := jwt.Get[string](token, sigClaim)
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
	cookieDomain, _, ok := cookieDomainForContext(c)
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

// cookieDomainForContext resolves the cookie domain and the auth host for the current request
// `cookieDomain` is what gets set on the Set-Cookie header (empty string for a host-only cookie)
// `authHost` is the public hostname Traefik Forward Auth uses for redirects to itself
// `ok` is false when the request host does not match any configured domain
func cookieDomainForContext(c *gin.Context) (cookieDomain string, authHost string, ok bool) {
	cfg := config.Get()

	// Prefer the request host so the selected cookie domain matches the app being accessed
	host := requestHost(c)
	if host != "" {
		return cfg.Server.DomainForHost(host)
	}

	// If no host is available and domains are not configured, fall back to a host-only cookie
	if len(cfg.Server.Domains) == 0 {
		return "", "", true
	}

	// Without a request host, use the first configured domain so cleanup paths can still expire cookies
	first := cfg.Server.Domains[0]
	return first.Domain, first.AuthHost, true
}

// cookieDomainForReturnURL resolves the cookie domain to use for cookies that will be read by the app at `returnURL`
// Falls back to the current request context when the return URL is missing or relative
func cookieDomainForReturnURL(c *gin.Context, returnURL string) (cookieDomain string, ok bool) {
	// Return URLs identify the app that will receive the cookie after authentication
	// Matching against that host prevents setting cookies for an unrelated configured domain
	u, err := url.Parse(returnURL)
	if err == nil && u != nil && u.Host != "" {
		cfg := config.Get()
		domain, _, ok := cfg.Server.DomainForHost(u.Host)
		return domain, ok
	}

	// Malformed or relative return URLs fall back to the current request context
	domain, _, ok := cookieDomainForContext(c)
	return domain, ok
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

// tokenCacheKey computes the cache key for a session token (using xxHash, variant XXH64)
// The key combines the token, the expected audience, and the portal name
// The parts are hashed incrementally to avoid allocating an intermediate concatenated string
func (s *Server) tokenCacheKey(val string, audience string, portalName string) uint64 {
	var d xxhash.Digest
	d.Reset()
	_, _ = d.WriteString(val)
	_, _ = d.WriteString("\x00")
	_, _ = d.WriteString(audience)
	_, _ = d.WriteString("\x00")
	_, _ = d.WriteString(portalName)
	return d.Sum64()
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
