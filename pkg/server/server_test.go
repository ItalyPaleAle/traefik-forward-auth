package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerLifecycle(t *testing.T) {
	// Create the server
	// This will create in-memory listeners with bufconn too
	srv, _ := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)

	// Make a request to the /healthz endpoint in the app server
	appClient := clientForListener(srv.appListener)
	reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
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
}
