package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectFavicon(t *testing.T) {
	t.Run("png", func(t *testing.T) {
		data := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}
		f, err := detectFavicon(data)
		require.NoError(t, err)
		assert.Equal(t, "favicon.png", f.Path)
		assert.Equal(t, "image/png", f.ContentType)
		assert.Equal(t, "image/png", f.LinkType)
		assert.Empty(t, f.LinkSizes)
	})

	t.Run("ico", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x01, 0x00, 0x10}
		f, err := detectFavicon(data)
		require.NoError(t, err)
		assert.Equal(t, "favicon.ico", f.Path)
		assert.Equal(t, "image/x-icon", f.ContentType)
		assert.Empty(t, f.LinkType)
		assert.Empty(t, f.LinkSizes)
	})

	t.Run("svg", func(t *testing.T) {
		data := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`)
		f, err := detectFavicon(data)
		require.NoError(t, err)
		assert.Equal(t, "favicon.svg", f.Path)
		assert.Equal(t, "image/svg+xml", f.ContentType)
		assert.Equal(t, "image/svg+xml", f.LinkType)
		assert.Equal(t, "any", f.LinkSizes)
	})

	t.Run("unsupported", func(t *testing.T) {
		_, err := detectFavicon([]byte("GIF89a"))
		require.Error(t, err)
		assert.ErrorContains(t, err, "unsupported favicon file format")
	})
}

func TestDecodeFaviconBase64(t *testing.T) {
	pngData := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}
	padded := base64.StdEncoding.EncodeToString(pngData)
	unpadded := strings.TrimRight(padded, "=")

	t.Run("padded", func(t *testing.T) {
		data, err := decodeFaviconBase64(padded)
		require.NoError(t, err)
		assert.Equal(t, pngData, data)
	})

	t.Run("unpadded", func(t *testing.T) {
		data, err := decodeFaviconBase64(unpadded)
		require.NoError(t, err)
		assert.Equal(t, pngData, data)
	})

	t.Run("whitespace", func(t *testing.T) {
		withWhitespace := " \n\t" + unpadded + "\r\n "
		data, err := decodeFaviconBase64(withWhitespace)
		require.NoError(t, err)
		assert.Equal(t, pngData, data)
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := decodeFaviconBase64("%%%")
		require.Error(t, err)
		assert.ErrorContains(t, err, "failed to decode favicon base64 value")
	})

	t.Run("empty", func(t *testing.T) {
		_, err := decodeFaviconBase64(" \n\t ")
		require.Error(t, err)
		assert.ErrorContains(t, err, "decoded favicon base64 value is empty")
	})
}

func TestFaviconRouteHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	favicon, err := detectFavicon(svg)
	require.NoError(t, err)

	srv := &Server{
		appRouter: gin.New(),
		favicon:   favicon,
		startTime: time.Now(),
	}
	srv.appRouter.Use(srv.MiddlewareSecurityHeaders)
	srv.addFaviconRoute("/")

	rec := httptest.NewRecorder()
	srv.appRouter.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.svg", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "image/svg+xml", rec.Header().Get("Content-Type"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, svg, rec.Body.Bytes())
}
