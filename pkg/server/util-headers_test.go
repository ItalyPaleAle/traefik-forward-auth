package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// headerValue and setResponseHeader index the header map directly, which is only correct if every header name we pass them is already canonical
func TestHeaderConstantsAreCanonical(t *testing.T) {
	names := []string{
		headerContentType,
		headerLocation,
		headerXForwardedDisplayName,
		headerXForwardedFor,
		headerXForwardedPort,
		headerXForwardedProto,
		headerXForwardedHost,
		headerXForwardedServer,
		headerXForwardedURI,
		headerXForwardedUser,
		headerXAuthenticatedUser,
		headerXForwardAuthIf,
		headerXRequestID,
	}

	for _, name := range names {
		assert.Equal(t, http.CanonicalHeaderKey(name), name, "header name constant %q is not in canonical form", name)
	}
}

func TestHeaderValue(t *testing.T) {
	t.Run("returns the value set on the request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(headerXForwardedHost, "example.com")

		assert.Equal(t, "example.com", headerValue(req.Header, headerXForwardedHost))
	})

	t.Run("returns an empty string when the header is absent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		assert.Empty(t, headerValue(req.Header, headerXForwardedHost))
	})

	t.Run("matches Header.Get for headers written in non-canonical form", func(t *testing.T) {
		// net/http canonicalizes header names as it parses a request, so a lowercase name on the wire is still found
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("x-forwarded-host", "example.com") //nolint:canonicalheader

		require.Equal(t, req.Header.Get(headerXForwardedHost), headerValue(req.Header, headerXForwardedHost))
	})
}

func TestSetResponseHeader(t *testing.T) {
	t.Run("sets a header that Header.Get can read back", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		setResponseHeader(c, headerXForwardedUser, "user123")

		assert.Equal(t, "user123", w.Header().Get(headerXForwardedUser))
	})

	t.Run("replaces a previously set value", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		setResponseHeader(c, headerXForwardedUser, "first")
		setResponseHeader(c, headerXForwardedUser, "second")

		assert.Equal(t, []string{"second"}, w.Header().Values(headerXForwardedUser))
	})

	t.Run("an empty value removes the header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		setResponseHeader(c, headerXForwardedUser, "user123")
		setResponseHeader(c, headerXForwardedUser, "")

		assert.Empty(t, w.Header().Get(headerXForwardedUser))
		assert.NotContains(t, w.Header(), headerXForwardedUser)
	})
}
