package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/italypaleale/go-kit/ttlcache"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// newBenchServer builds a minimal Server for exercising the hot-path methods
// It avoids NewServer/init so the benchmark does not depend on the compiled client assets
func newBenchServer(b *testing.B) *Server {
	b.Helper()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := config.Get()
	err := cfg.Process(log)
	if err != nil {
		b.Fatalf("failed to process config: %v", err)
	}

	portals, err := GetPortalsConfig(context.Background(), cfg)
	if err != nil {
		b.Fatalf("failed to get portals config: %v", err)
	}

	srv := &Server{
		portals: portals,
		tokenCache: ttlcache.NewCache[uint64, openid.Token](&ttlcache.CacheOptions{
			CleanupInterval: 2 * time.Minute,
		}),
	}

	return srv
}

func benchSessionToken(b *testing.B, portalName, cookieDomain string, profile *user.Profile, expiration time.Duration) string {
	b.Helper()

	cfg := config.Get()
	now := time.Now()
	audience := cfg.GetTokenAudienceClaim(cookieDomain)

	builder := jwt.NewBuilder()
	profile.AppendClaims(builder)

	token, err := builder.
		Issuer(jwtIssuer + ":" + audience + ":" + portalName).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(expiration)).
		NotBefore(now).
		Build()
	if err != nil {
		b.Fatalf("failed to build token: %v", err)
	}

	tokenBytes, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey())).
		Serialize(token)
	if err != nil {
		b.Fatalf("failed to serialize token: %v", err)
	}

	return string(tokenBytes)
}

func benchContextWithCookie(cookieName, token string) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(headerXForwardedHost, "example.com")
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	c.Request = req
	return c
}

// BenchmarkParseSessionToken benchmarks the JWT parse step on a warm cache (validation cached)
func BenchmarkParseSessionToken(b *testing.B) {
	srv := newBenchServer(b)
	const portalName = "test1"
	const cookieDomain = "example.com"

	profile := createFullTestProfile()
	token := benchSessionToken(b, portalName, cookieDomain, profile, time.Hour)

	// Warm the cache
	_, err := srv.parseSessionToken(token, portalName, cookieDomain)
	if err != nil {
		b.Fatalf("failed to warm cache: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := srv.parseSessionToken(token, portalName, cookieDomain)
		if err != nil {
			b.Fatalf("parseSessionToken failed: %v", err)
		}
	}
}

// BenchmarkGetSessionCookie benchmarks the full session cookie load on a warm cache
func BenchmarkGetSessionCookie(b *testing.B) {
	srv := newBenchServer(b)
	const portalName = "test1"
	const cookieDomain = "example.com"

	cfg := config.Get()
	cookieName := cfg.Cookies.CookieName(portalName)

	profile := createFullTestProfile()
	token := benchSessionToken(b, portalName, cookieDomain, profile, time.Hour)
	c := benchContextWithCookie(cookieName, token)

	// Warm the cache
	_, _, err := srv.getSessionCookie(c, portalName)
	if err != nil {
		b.Fatalf("failed to warm cache: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _, err := srv.getSessionCookie(c, portalName)
		if err != nil {
			b.Fatalf("getSessionCookie failed: %v", err)
		}
	}
}
