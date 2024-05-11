package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils/bufconn"
)

const (
	// Servers are started on in-memory listeners so these ports aren't actually used for TCP sockets
	testServerPort  = 5701
	testMetricsPort = 5702

	// Size for the in-memory buffer for bufconn
	bufconnBufSize = 1 << 20 // 1MB
)

func TestMain(m *testing.M) {
	_ = config.SetTestConfig(map[string]any{
		"port":          testServerPort,
		"bind":          "127.0.0.1",
		"enableMetrics": false,
		"metricsBind":   "127.0.0.1",
		"metricsPort":   testMetricsPort,
	})

	gin.SetMode(gin.ReleaseMode)

	os.Exit(m.Run())
}

func TestServerLifecycle(t *testing.T) {
	testFn := func(metricsEnabled bool) func(t *testing.T) {
		return func(t *testing.T) {
			t.Cleanup(config.SetTestConfig(map[string]any{
				"enableMetrics": metricsEnabled,
			}))

			// Create the server
			// This will create in-memory listeners with bufconn too
			srv, _ := newTestServer(t)
			require.NotNil(t, srv)
			stopServerFn := startTestServer(t, srv)
			defer stopServerFn(t)

			// Make a request to the /healthz endpoint in the app server
			appClient := clientForListener(srv.appListener)
			reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
				fmt.Sprintf("http://localhost:%d/healthz", testServerPort), nil)
			require.NoError(t, err)
			res, err := appClient.Do(req)
			require.NoError(t, err)
			defer closeBody(res)

			assert.Equal(t, http.StatusNoContent, res.StatusCode)
			healthzRes, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			assert.Empty(t, healthzRes)

			// Make a request to the /healthz endpoint in the metrics server
			if metricsEnabled {
				metricsClient := clientForListener(srv.metricsListener)
				reqCtx, reqCancel = context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err = http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("http://localhost:%d/healthz", testMetricsPort), nil)
				require.NoError(t, err)
				res, err = metricsClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				assert.Equal(t, http.StatusNoContent, res.StatusCode)
				healthzRes, err = io.ReadAll(res.Body)
				require.NoError(t, err)
				assert.Empty(t, healthzRes)
			}
		}
	}

	t.Run("run the server without metrics", testFn(false))

	t.Run("run the server with metrics enabled", testFn(true))
}

func newTestServer(t *testing.T) (srv *Server, logBuf *bytes.Buffer) {
	t.Helper()

	logBuf = &bytes.Buffer{}
	logDest := io.MultiWriter(os.Stdout, logBuf)

	log := zerolog.New(zerolog.SyncWriter(logDest)).
		With().
		Str("app", "test").
		Logger()

	srv, err := NewServer(NewServerOpts{
		Log:           &log,
		addTestRoutes: nil,
	})
	require.NoError(t, err)

	srv.appListener = bufconn.Listen(bufconnBufSize)
	srv.metricsListener = bufconn.Listen(bufconnBufSize)

	return srv, logBuf
}

func startTestServer(t *testing.T, srv *Server) func(t *testing.T) {
	t.Helper()

	// Start the server in a background goroutine
	srvCtx, srvCancel := context.WithCancel(context.Background())
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

func assertResponseNoContent(t *testing.T, res *http.Response) {
	t.Helper()

	require.Equal(t, http.StatusNoContent, res.StatusCode, "Response has an unexpected status code")
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err, "Error reading response body")
	assert.Empty(t, body, "Response body is not empty")
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
