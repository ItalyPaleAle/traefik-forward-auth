package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareAddRequestState(t *testing.T) {
	s := &Server{}

	newContext := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		return c
	}

	t.Run("attaches a state that handlers can read", func(t *testing.T) {
		c := newContext()
		require.Nil(t, getRequestState(c), "there should be no state before the middleware runs")

		s.MiddlewareAddRequestState(c)

		rs := getRequestState(c)
		require.NotNil(t, rs)
		assert.Empty(t, rs.requestID)
		assert.Nil(t, rs.portal)
		assert.False(t, rs.authenticated)
	})

	t.Run("writes are visible to everything later in the request", func(t *testing.T) {
		c := newContext()
		s.MiddlewareAddRequestState(c)

		getRequestState(c).requestID = "req-123"

		// A handler reading the state again, and anything reading it straight from the context, must see the same value
		assert.Equal(t, "req-123", getRequestState(c).requestID)
		assert.Equal(t, "req-123", requestStateFromContext(c.Request.Context()).requestID)
	})

	t.Run("each request gets its own state", func(t *testing.T) {
		first := newContext()
		second := newContext()
		s.MiddlewareAddRequestState(first)
		s.MiddlewareAddRequestState(second)

		getRequestState(first).requestID = "first"
		getRequestState(second).requestID = "second"

		assert.Equal(t, "first", getRequestState(first).requestID)
		assert.Equal(t, "second", getRequestState(second).requestID)
	})

	t.Run("does not allocate Gin's key map", func(t *testing.T) {
		c := newContext()
		s.MiddlewareAddRequestState(c)
		getRequestState(c).requestID = "req-123"

		assert.Nil(t, c.Keys, "the request state replaces Gin's context map, which should stay unused")
	})
}

func TestGetRequestState(t *testing.T) {
	t.Run("returns nil when the middleware did not run", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		assert.Nil(t, getRequestState(c))
	})

	t.Run("returns nil when the context has no request", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())

		assert.Nil(t, getRequestState(c))
	})

	t.Run("requestStateFromContext returns nil for a plain context", func(t *testing.T) {
		assert.Nil(t, requestStateFromContext(context.Background()))
	})
}

func TestSetLogMessage(t *testing.T) {
	t.Run("sets the message on the request state", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		(&Server{}).MiddlewareAddRequestState(c)

		setLogMessage(c, "something happened")

		assert.Equal(t, "something happened", getRequestState(c).logMessage)
	})

	t.Run("does nothing when there is no request state", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		assert.NotPanics(t, func() {
			setLogMessage(c, "something happened")
		})
	})
}
