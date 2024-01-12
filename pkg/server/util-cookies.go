package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

const (
	jwtIssuer           = "traefik-forward-auth"
	nonceCookieName     = "tf_nonce"
	acceptableClockSkew = 30 * time.Second
	nonceSize           = 12 // Nonce size in bytes
)

func getSessionCookie(c *gin.Context) (profile user.Profile, claims map[string]any, err error) {
	cfg := config.Get()

	// Get the cookie
	cookieValue, err := c.Cookie(cfg.CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return profile, nil, nil
	} else if err != nil {
		return profile, nil, fmt.Errorf("failed to get cookie: %w", err)
	}
	if cookieValue == "" {
		return profile, nil, fmt.Errorf("cookie %s is empty", cfg.CookieName)
	}

	// Parse the JWT in the cookie
	token, err := jwt.Parse([]byte(cookieValue),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(cfg.Hostname),
		jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey()),
	)
	if err != nil {
		return profile, nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get the user profile from the claim
	claims, err = token.AsMap(c.Request.Context())
	if err != nil {
		return profile, nil, fmt.Errorf("failed to get claims from JWT: %w", err)
	}
	profile, err = user.NewProfileFromClaims(claims)
	if err != nil {
		return profile, nil, fmt.Errorf("failed to parse claims from JWT: %w", err)
	}

	return profile, claims, nil
}

func setSessionCookie(c *gin.Context, profile *user.Profile) error {
	cfg := config.Get()
	expiration := cfg.SessionLifetime

	// Claims for the JWT
	now := time.Now()
	builder := jwt.NewBuilder()
	profile.AppendClaims(builder)
	token, err := builder.
		Issuer(jwtIssuer).
		Audience([]string{cfg.Hostname}).
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
	c.SetCookie(cfg.CookieName, string(cookieValue), int(expiration.Seconds()), "/", cfg.CookieDomain, !cfg.CookieInsecure, true)

	return nil
}

func deleteSessionCookie(c *gin.Context) {
	cfg := config.Get()
	c.SetCookie(cfg.CookieName, "", -1, "/", cfg.CookieDomain, !cfg.CookieInsecure, true)
}

func getStateCookie(c *gin.Context) (nonce string, returnURL string, err error) {
	cfg := config.Get()

	// Get the cookie
	cookieValue, err := c.Cookie(nonceCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return "", "", nil
	} else if err != nil {
		return "", "", fmt.Errorf("failed to get cookie: %w", err)
	}
	if cookieValue == "" {
		return "", "", fmt.Errorf("cookie %s is empty", cfg.CookieName)
	}

	// Parse the JWT in the cookie
	token, err := jwt.Parse([]byte(cookieValue),
		jwt.WithAcceptableSkew(acceptableClockSkew),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(cfg.Hostname),
		jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey()),
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	// Get the nonce
	nonceAny, _ := token.Get("nonce")
	nonce, _ = nonceAny.(string)
	if nonce == "" {
		return "", "", errors.New("claim 'nonce' not found in JWT")
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(nonceBytes) != nonceSize {
		return "", "", errors.New("claim 'nonce' not found in JWT")
	}

	// Get the return URL
	returnURLAny, _ := token.Get("return_url")
	returnURL, _ = returnURLAny.(string)
	if returnURL == "" {
		return "", "", errors.New("claim 'return_url' not found in JWT")
	}

	// Validate the signature inside the token
	expectSig := nonceCookieSig(c, nonceBytes)
	sigAny, ok := token.Get("sig")
	if !ok {
		return "", "", errors.New("claim 'sig' not found in JWT")
	}
	sig, _ := sigAny.(string)
	if sig != expectSig {
		return "", "", errors.New("claim 'sig' invalid in JWT")
	}

	return nonce, returnURL, nil
}

func setStateCookie(c *gin.Context, returnURL string) (nonce string, err error) {
	cfg := config.Get()
	expiration := cfg.AuthenticationTimeout

	// Generate a nonce
	nonceBytes := make([]byte, nonceSize)
	_, err = io.ReadFull(rand.Reader, nonceBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce = base64.RawURLEncoding.EncodeToString(nonceBytes)

	// Computes a signature that includes certain properties from the request that are sufficiently stable
	sig := nonceCookieSig(c, nonceBytes)

	// Claims for the JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(jwtIssuer).
		Audience([]string{cfg.Hostname}).
		IssuedAt(now).
		// Add 1 extra second to synchronize with cookie expiry
		Expiration(now.Add(expiration+time.Second)).
		NotBefore(now).
		Claim("nonce", nonce).
		Claim("sig", sig).
		Claim("return_url", returnURL).
		Build()
	if err != nil {
		return "", fmt.Errorf("failed to build JWT: %w", err)
	}

	// Generate the JWT
	cookieValue, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256, cfg.GetTokenSigningKey())).
		Serialize(token)
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	// Set the cookie
	host, _, _ := net.SplitHostPort(cfg.Hostname)
	if host == "" {
		host = cfg.Hostname
	}
	c.SetCookie(nonceCookieName, string(cookieValue), int(expiration.Seconds()), "/", host, !cfg.CookieInsecure, true)

	// Return the nonce
	return nonce, nil
}

func deleteStateCookie(c *gin.Context) {
	cfg := config.Get()

	host, _, _ := net.SplitHostPort(cfg.Hostname)
	if host == "" {
		host = cfg.Hostname
	}

	c.SetCookie(nonceCookieName, "", -1, "/", host, !cfg.CookieInsecure, true)
}

func nonceCookieSig(c *gin.Context, nonce []byte) string {
	h := hmac.New(sha256.New224, nonce)
	h.Write([]byte("tfa-nonce-sig"))
	h.Write([]byte(c.GetHeader("User-Agent")))
	h.Write([]byte(c.GetHeader("Accept-Language")))
	h.Write([]byte(c.GetHeader("DNT")))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
