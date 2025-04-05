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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
)

func (s *Server) getSessionCookie(c *gin.Context, portalName string) (profile *user.Profile, provider auth.Provider, err error) {
	cfg := config.Get()

	// Get the cookie
	cookieValue, err := c.Cookie(cfg.Cookies.CookieName(portalName))
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("failed to get session cookie: %w", err)
	}
	if cookieValue == "" {
		return nil, nil, fmt.Errorf("session cookie %s is empty", cfg.Cookies.CookieName(portalName))
	}

	// Parse the JWT in the cookie
	token, err := s.parseSessionToken(cookieValue, portalName)
	if err != nil {
		return nil, nil, err
	}

	// Get the user profile from the claim
	claims, err := token.AsMap(c.Request.Context())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get claims from session token JWT: %w", err)
	}
	profile, err = user.NewProfileFromClaims(claims)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse claims from session token JWT: %w", err)
	}

	provider = s.portals[portalName].Providers[profile.Provider]
	if provider == nil {
		return nil, nil, errors.New("invalid provider in session token JWT")
	}

	// Populate additional claims if any
	if len(claims) > 0 {
		provider.PopulateAdditionalClaims(claims, profile.SetAdditionalClaim)
	}

	return profile, provider, nil
}

func (s *Server) parseSessionToken(val string, portalName string) (jwt.Token, error) {
	cfg := config.Get()
	token, err := jwt.Parse([]byte(val),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer+":"+cfg.Server.Hostname+cfg.Server.BasePath+":"+portalName),
		jwt.WithAudience(cfg.Server.Hostname+cfg.Server.BasePath),
		jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session token JWT: %w", err)
	}
	return token, nil
}

func (s *Server) setSessionCookie(c *gin.Context, portalName string, profile *user.Profile) error {
	cfg := config.Get()
	expiration := cfg.Tokens.SessionLifetime

	// Claims for the JWT
	now := time.Now()
	builder := jwt.NewBuilder()
	profile.AppendClaims(builder)
	token, err := builder.
		Issuer(jwtIssuer + ":" + cfg.Server.Hostname + cfg.Server.BasePath + ":" + portalName).
		Audience([]string{cfg.Server.Hostname + cfg.Server.BasePath}).
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
		Sign(jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey())).
		Serialize(token)
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	// Set the cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cfg.Cookies.CookieName(portalName), string(cookieValue), int(expiration.Seconds())-1, "/", cfg.Cookies.Domain, !cfg.Cookies.Insecure, true)

	return nil
}

func (s *Server) deleteSessionCookie(c *gin.Context, portalName string) {
	cfg := config.Get()
	cookieName := cfg.Cookies.CookieName(portalName)

	_, err := c.Cookie(cookieName)
	if err != nil {
		// Cookie was not set in the request, nothing to unset
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(cookieName, "", -1, "/", cfg.Cookies.Domain, !cfg.Cookies.Insecure, true)
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

	// Parse the JWT in the cookie
	token, err := jwt.Parse([]byte(cookieValue),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer+":"+cfg.Server.Hostname+cfg.Server.BasePath+":"+portal.Name),
		jwt.WithAudience(cfg.Server.Hostname+cfg.Server.BasePath),
		jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey()),
	)
	if err != nil {
		return stateCookieContent{}, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get the portal name
	portalAny, _ := token.Get(portalNameClaim)
	content.portal, _ = portalAny.(string)
	if content.portal == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", portalNameClaim)
	} else if content.portal != portal.Name {
		return stateCookieContent{}, errors.New("portal claim in JWT does not match expected value")
	}

	// Get the nonce
	nonceAny, _ := token.Get(nonceClaim)
	content.nonce, _ = nonceAny.(string)
	if content.nonce == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", nonceClaim)
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(content.nonce)
	if err != nil || len(nonceBytes) != nonceSize {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", nonceClaim)
	}

	// Get the return URL
	returnURLAny, _ := token.Get(returnURLClaim)
	content.returnURL, _ = returnURLAny.(string)
	if content.returnURL == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", returnURLClaim)
	}

	// Validate the signature inside the token
	expectSig := stateCookieSig(c, stateCookieID, content.portal, nonceBytes)
	sigAny, _ := token.Get(sigClaim)
	sig, _ := sigAny.(string)
	if sig == "" {
		return stateCookieContent{}, fmt.Errorf("claim '%s' not found in JWT", sigClaim)
	}
	if sig != expectSig {
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

	// Claims for the JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer+":"+cfg.Server.Hostname+cfg.Server.BasePath+":"+portal.Name).
		Audience([]string{cfg.Server.Hostname + cfg.Server.BasePath}).
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
		Sign(jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey())).
		Serialize(token)
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	// Set the cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(stateCookieName(portal.Name, stateCookieID), string(cookieValue), int(expiration.Seconds())-1, "/", cfg.Cookies.Domain, !cfg.Cookies.Insecure, true)

	// Return the nonce
	return nil
}

func (s *Server) deleteStateCookies(c *gin.Context, portalName string) {
	cfg := config.Get()
	prefix := stateCookieName(portalName, "")

	// Iterate through all cookies looking for state ones
	c.SetSameSite(http.SameSiteLaxMode)
	for _, cookie := range c.Request.Cookies() {
		if cookie == nil || !strings.HasPrefix(cookie.Name, prefix) {
			continue
		}

		// We found a state cookie; remove it
		c.SetCookie(cookie.Name, "", -1, "/", cfg.Cookies.Domain, !cfg.Cookies.Insecure, true)
	}
}

func stateCookieName(portalName string, stateCookieID string) string {
	return stateCookieNamePrefix + "_" + portalName + "_" + stateCookieID
}

func stateCookieSig(c *gin.Context, portalName string, stateCookieID string, nonce []byte) string {
	h := hmac.New(sha256.New224, nonce)
	h.Write([]byte("tfa-state-sig"))
	h.Write([]byte(stateCookieID))
	h.Write([]byte(strings.ToLower(norm.NFKD.String(c.GetHeader("User-Agent")))))
	h.Write([]byte(strings.ToLower(norm.NFKD.String(c.GetHeader("Accept-Language")))))
	h.Write([]byte(strings.ToLower(norm.NFKD.String(c.GetHeader("DNT")))))
	h.Write([]byte(portalName))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
