package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/bufconn"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/ptr"
)

const (
	// Servers are started on in-memory listeners so these ports aren't actually used for TCP sockets
	testServerPort = 5701

	// Size for the in-memory buffer for bufconn
	bufconnBufSize = 1 << 20 // 1MB
)

func TestMain(m *testing.M) {
	_ = config.SetTestConfig(func(c *config.Config) {
		c.Server.Hostname = "tfa.example.com"
		c.Server.Port = testServerPort
		c.Server.Bind = "127.0.0.1"
		c.Server.BasePath = ""
		c.DefaultPortal = ""
		c.Portals = []config.ConfigPortal{
			{
				Name:        "test1",
				DisplayName: "Test 1",
				Providers: []config.ConfigPortalProvider{
					{TestProvider: ptr.Of("testoauth2")},
				},
				AuthenticationTimeout:   10 * time.Second,
				AlwaysShowProvidersPage: false,
			},
		}
	})

	gin.SetMode(gin.ReleaseMode)

	os.Exit(m.Run())
}

func newTestServer(t *testing.T) (srv *Server, logBuf *bytes.Buffer) {
	t.Helper()

	cfg := config.Get()

	// Logging: we log to stdout and to a buffer, so we can capture logs if needed
	logBuf = &bytes.Buffer{}
	logDest := io.MultiWriter(os.Stdout, logBuf)

	log := slog.
		New(slog.NewTextHandler(logDest, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})).
		With(slog.String("app", "test"))

	// Process config
	err := cfg.Process(log)
	require.NoError(t, err)
	portals, err := GetPortalsConfig(t.Context(), cfg)
	require.NoError(t, err)

	// Create the server object
	srv, err = NewServer(NewServerOpts{
		Log:           log,
		Portals:       portals,
		addTestRoutes: nil,
	})
	require.NoError(t, err)

	// Set the listener
	srv.appListener = bufconn.Listen(bufconnBufSize)

	return srv, logBuf
}

func startTestServer(t *testing.T, srv *Server) func(t *testing.T) {
	t.Helper()

	// Start the server in a background goroutine
	srvCtx, srvCancel := context.WithCancel(t.Context())
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Run(srvCtx)
	}()

	// Ensure the server has started and there's no error
	// This may report false positives if the server just takes longer to start, but we'll still catch those errors later on
	select {
	case <-time.After(100 * time.Millisecond):
		// all good
	case err := <-startErrCh:
		t.Fatalf("Received an unexpected error in startErrCh: %v", err)
	}

	// Return a function to tear down the test server, which must be invoked at the end of the test
	return func(t *testing.T) {
		t.Helper()

		// Shutdown the server
		srvCancel()

		// At the end of the test, there should be no error
		require.NoError(t, <-startErrCh, "received an unexpected error in startErrCh")
	}
}

func clientForListener(ln net.Listener) *http.Client {
	//nolint:forcetypeassert
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		bl, ok := ln.(*bufconn.Listener)
		if !ok {
			return nil, errors.New("failed to cast listener to bufconn.Listener")
		}
		return bl.DialContext(ctx)
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

//nolint:unused
func assertResponseError(t *testing.T, res *http.Response, expectStatusCode int, expectErr string) {
	t.Helper()

	require.Equal(t, expectStatusCode, res.StatusCode, "Response has an unexpected status code")
	require.Equal(t, "application/json", res.Header.Get("Content-Type"), "Content-Type header is invalid")

	data := struct {
		Error string `json:"error"`
	}{}
	err := json.NewDecoder(res.Body).Decode(&data)
	require.NoError(t, err, "Error parsing response body as JSON")

	require.Equal(t, expectErr, data.Error, "Error message does not match")
}

func populateRequiredProxyHeaders(t *testing.T, req *http.Request) {
	t.Helper()

	req.Header.Set(headerXForwardedProto, "https")
	req.Header.Set(headerXForwardedPort, "443")
	req.Header.Set(headerXForwardedFor, "1.1.1.1")
	req.Header.Set(headerXForwardedHost, "example.com")
}

func assertResponseNoContent(t *testing.T, res *http.Response) {
	t.Helper()

	require.Equal(t, http.StatusNoContent, res.StatusCode, "Response has an unexpected status code")
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err, "Error reading response body")
	assert.Empty(t, body, "Response body is not empty")
}

// createTestSessionToken creates a valid session token with a specific profile for testing
func createTestSessionToken(t *testing.T, portalName string, profile *user.Profile, expiration time.Duration) string {
	t.Helper()

	cfg := config.Get()
	now := time.Now()

	builder := jwt.NewBuilder()
	profile.AppendClaims(builder)

	token, err := builder.
		Issuer(jwtIssuer + ":" + cfg.GetTokenAudienceClaim() + ":" + portalName).
		Audience([]string{cfg.GetTokenAudienceClaim()}).
		IssuedAt(now).
		Expiration(now.Add(expiration)).
		NotBefore(now).
		Build()
	require.NoError(t, err)

	// Sign the token
	tokenBytes, err := jwt.NewSerializer().
		Sign(jwt.WithKey(jwa.HS256(), cfg.GetTokenSigningKey())).
		Serialize(token)
	require.NoError(t, err)

	return string(tokenBytes)
}

// Closes a HTTP response body making sure to drain it first
// Normally invoked as a defer'd function
func closeBody(res *http.Response) {
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

// Internal function that returns true if the value matches the context.Context interface
// This can be used as an argument for mock.MatchedBy
//
//nolint:unused
func matchContextInterface(v any) bool {
	_, ok := v.(context.Context)
	return ok
}

func cookiePair(setCookie string) string {
	for i, r := range setCookie {
		if r == ';' {
			return setCookie[:i]
		}
	}
	return setCookie
}

func urlMustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	require.NotEmpty(t, raw)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}
