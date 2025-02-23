package server

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServerHealthzRoutes(t *testing.T) {
	// Create the server
	// This will create in-memory listeners with bufconn too
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	// Test the healthz endpoints
	t.Run("healthz", func(t *testing.T) {
		// Make a request to the /healthz endpoint
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d/healthz", testServerPort), nil)
		require.NoError(t, err)
		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		assertResponseNoContent(t, res)

		// Reset the log buffer
		logBuf.Reset()
	})
}
