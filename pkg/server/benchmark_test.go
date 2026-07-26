package server

import (
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

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

// newBenchServer builds a minimal Server for exercising the hot-path methods
// It avoids NewServer/init so the benchmark does not depend on the compiled client assets
func newBenchServer(b *testing.B) *Server {
	b.Helper()

	log := slog.New(slog.DiscardHandler)

	cfg := config.Get()
	err := cfg.Process(log)
	if err != nil {
		b.Fatalf("failed to process config: %v", err)
	}

	portals, err := GetPortalsConfig(b.Context(), cfg)
	if err != nil {
		b.Fatalf("failed to get portals config: %v", err)
	}

	srv := &Server{
		portals: portals,
		tokenCache: ttlcache.NewCache[uint64, tokenCacheEntry](&ttlcache.CacheOptions{
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
	req.AddCookie(&http.Cookie{Name: cookieName, Value: token}) //nolint:gosec
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

// BenchmarkHotPathForwardAuth benchmarks the complete request Traefik makes on every
// proxied request: the full middleware chain plus the portal root route, for a request
// that carries a valid session cookie.
// This is the end-to-end hot path, not an individual method.
func BenchmarkHotPathForwardAuth(b *testing.B) {
	const portalName = "test1"
	const cookieDomain = "example.com"

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := config.Get()
	err := cfg.Process(log)
	if err != nil {
		b.Fatalf("failed to process config: %v", err)
	}

	portals, err := GetPortalsConfig(b.Context(), cfg)
	if err != nil {
		b.Fatalf("failed to get portals config: %v", err)
	}

	srv, err := NewServer(NewServerOpts{Portals: portals, log: log})
	if err != nil {
		b.Fatalf("failed to create the server: %v", err)
	}

	profile := createFullTestProfile()
	token := benchSessionToken(b, portalName, cookieDomain, profile, time.Hour)
	cookieName := cfg.Cookies.CookieName(portalName)

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/portals/"+portalName+"/", nil)
		req.Header.Set(headerXForwardedFor, "203.0.113.10")
		req.Header.Set(headerXForwardedPort, "443")
		req.Header.Set(headerXForwardedProto, "https")
		req.Header.Set(headerXForwardedHost, cookieDomain)
		req.Header.Set(headerXForwardedServer, "traefik@docker")
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token}) //nolint:gosec
		return req
	}

	// Warm the token cache and make sure the route actually authenticates
	warm := httptest.NewRecorder()
	srv.appRouter.ServeHTTP(warm, newReq())
	if warm.Code != http.StatusOK {
		b.Fatalf("expected the request to be authenticated, got status %d: %s", warm.Code, warm.Body.String())
	}

	req := newReq()
	w := &benchResponseWriter{h: make(http.Header, 16)}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		clear(w.h)
		srv.appRouter.ServeHTTP(w, req)
	}
}

// benchResponseWriter discards the response so the benchmark measures the server, not the recorder
type benchResponseWriter struct {
	h http.Header
}

func (b *benchResponseWriter) Header() http.Header         { return b.h }
func (b *benchResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (b *benchResponseWriter) WriteHeader(int)             {}
