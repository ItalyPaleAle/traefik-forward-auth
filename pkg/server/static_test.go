package server

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMinifySVG(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "removes newlines",
			input:    []byte("<svg>\n  <path />\n</svg>"),
			expected: "<svg>  <path /></svg>",
		},
		{
			name:     "removes carriage returns",
			input:    []byte("<svg>\r\n  <path />\r\n</svg>"),
			expected: "<svg>  <path /></svg>",
		},
		{
			name:     "removes single line comment",
			input:    []byte("<svg><!-- comment --><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "removes multi-line comment",
			input:    []byte("<svg><!-- \ncomment\n --><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "removes multiple comments",
			input:    []byte("<svg><!-- first --><!-- second --><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "removes newlines and comments together",
			input:    []byte("<svg>\n<!-- comment -->\n<path />\n</svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name:     "handles empty input",
			input:    []byte(""),
			expected: "",
		},
		{
			name:     "handles input with no newlines or comments",
			input:    []byte("<svg><path /></svg>"),
			expected: "<svg><path /></svg>",
		},
		{
			name: "handles complex SVG",
			input: []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24">
  <!-- Icon definition -->
  <g fill="none" stroke="currentColor">
    <path d="M12 2L2 7l10 5 10-5-10-5z"/>
    <!-- Second path -->
    <path d="M2 17l10 5 10-5"/>
  </g>
</svg>`),
			expected: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24">    <g fill="none" stroke="currentColor">    <path d="M12 2L2 7l10 5 10-5-10-5z"/>        <path d="M2 17l10 5 10-5"/>  </g></svg>`,
		},
		{
			name:     "handles comment without closing tag",
			input:    []byte("<svg><!-- unclosed<path /></svg>"),
			expected: "<svg><!-- unclosed<path /></svg>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := minifySVG(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAcceptsGzip(t *testing.T) {
	newCtx := func(headerValue string, set bool) *gin.Context {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		if set {
			c.Request.Header.Set("Accept-Encoding", headerValue)
		}
		return c
	}

	cases := []struct {
		name   string
		header string
		set    bool
		want   bool
	}{
		{"no header", "", false, false},
		{"empty header", "", true, false},
		{"exact gzip", "gzip", true, true},
		{"uppercase GZIP", "GZIP", true, true},
		{"mixed case GzIp", "GzIp", true, true},
		{"gzip with q-value", "gzip;q=0.8", true, true},
		{"gzip with whitespace before q", "gzip ;q=0.8", true, true},
		{"gzip first in list", "gzip, deflate", true, true},
		{"gzip last in list", "deflate, gzip", true, true},
		{"gzip in middle of list", "br, gzip, deflate", true, true},
		{"gzip without space after comma", "deflate,gzip", true, true},
		{"gzip with q-value in list", "deflate, gzip;q=0.5", true, true},
		{"gzip with leading whitespace", " gzip", true, true},
		{"gzip with trailing whitespace", "gzip ", true, true},
		{"tab-separated tokens", "deflate,\tgzip", true, true},
		{"only deflate", "deflate", true, false},
		{"only br", "br", true, false},
		{"identity", "identity", true, false},
		{"x-gzip is not gzip", "x-gzip", true, false},
		{"gzipper is not gzip", "gzipper", true, false},
		{"agzip is not gzip", "agzip", true, false},
		{"gzip2 is not gzip", "gzip2", true, false},
		{"too short", "gzi", true, false},
		{"prefix substring within larger token", "x-gzip, deflate", true, false},
		{"suffix substring within larger token", "deflate, gzipper", true, false},
		{"realistic Chrome header", "gzip, deflate, br, zstd", true, true},
		{"realistic Firefox header", "gzip, deflate, br", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCtx(tc.header, tc.set)
			got := acceptsGzip(c)
			assert.Equal(t, tc.want, got, "header=%q set=%v", tc.header, tc.set)
		})
	}
}

func TestServerStaticAssets(t *testing.T) {
	srv, logBuf := newTestServer(t)
	require.NotNil(t, srv)
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	defer logBuf.Reset()

	require.NotEmpty(t, srv.styleAsset, "manifest must populate styleAsset")
	require.True(t, strings.HasPrefix(srv.styleAsset, "style."), "styleAsset should be hashed style.<hash>.css")
	require.True(t, strings.HasSuffix(srv.styleAsset, ".css"), "styleAsset should be hashed style.<hash>.css")

	appClient := clientForListener(srv.appListener)

	doRequest := func(t *testing.T, path string, acceptEncoding string) *http.Response {
		t.Helper()
		reqCtx, reqCancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(reqCancel)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("http://localhost:%d%s", testServerPort, path), nil)
		require.NoError(t, err)
		// Always set Accept-Encoding explicitly so the http.Transport does not auto-add gzip and auto-decompress for us
		req.Header.Set("Accept-Encoding", acceptEncoding)
		res, err := appClient.Do(req)
		require.NoError(t, err)
		return res
	}

	t.Run("style.css served gzipped when client accepts gzip", func(t *testing.T) {
		res := doRequest(t, "/"+srv.styleAsset, "gzip")
		defer closeBody(res)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "text/css", res.Header.Get("Content-Type"))
		assert.Equal(t, "gzip", res.Header.Get("Content-Encoding"))
		assert.Equal(t, "Accept-Encoding", res.Header.Get("Vary"))

		gz, err := gzip.NewReader(res.Body)
		require.NoError(t, err)
		defer gz.Close()
		body, err := io.ReadAll(gz)
		require.NoError(t, err)
		// The compiled Tailwind output should reference selectors we own
		assert.Contains(t, string(body), ".layout")
	})

	t.Run("style.css served uncompressed when client does not accept gzip", func(t *testing.T) {
		res := doRequest(t, "/"+srv.styleAsset, "identity")
		defer closeBody(res)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "text/css", res.Header.Get("Content-Type"))
		assert.Empty(t, res.Header.Get("Content-Encoding"))
		assert.Equal(t, "Accept-Encoding", res.Header.Get("Vary"))

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), ".layout")
	})

	t.Run("icons.js gzipped with all icons by default", func(t *testing.T) {
		res := doRequest(t, "/icons.js", "gzip")
		defer closeBody(res)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "application/javascript", res.Header.Get("Content-Type"))
		assert.Equal(t, "gzip", res.Header.Get("Content-Encoding"))
		assert.Equal(t, "Accept-Encoding", res.Header.Get("Vary"))

		gz, err := gzip.NewReader(res.Body)
		require.NoError(t, err)
		defer gz.Close()
		body, err := io.ReadAll(gz)
		require.NoError(t, err)
		bodyStr := string(body)

		require.NotEmpty(t, srv.icons, "test pre-condition: server should have at least one icon loaded")
		for name := range srv.icons {
			assert.Contains(t, bodyStr, "'"+name+"':", "icon %s should be in body", name)
		}
	})

	t.Run("icons.js gzipped with filtered ?include", func(t *testing.T) {
		res := doRequest(t, "/icons.js?include=github,google", "gzip")
		defer closeBody(res)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "gzip", res.Header.Get("Content-Encoding"))
		assert.Equal(t, "Accept-Encoding", res.Header.Get("Vary"))

		gz, err := gzip.NewReader(res.Body)
		require.NoError(t, err)
		defer gz.Close()
		body, err := io.ReadAll(gz)
		require.NoError(t, err)
		bodyStr := string(body)

		assert.Contains(t, bodyStr, "'github':")
		assert.Contains(t, bodyStr, "'google':")
		// Excluded icons should not appear
		assert.NotContains(t, bodyStr, "'firefox':")
		assert.NotContains(t, bodyStr, "'apple':")
	})

	t.Run("icons.js served uncompressed when client does not accept gzip", func(t *testing.T) {
		res := doRequest(t, "/icons.js?include=github", "identity")
		defer closeBody(res)

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "application/javascript", res.Header.Get("Content-Type"))
		assert.Empty(t, res.Header.Get("Content-Encoding"))
		assert.Equal(t, "Accept-Encoding", res.Header.Get("Vary"))

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		bodyStr := string(body)
		assert.Contains(t, bodyStr, "'github':")
		assert.NotContains(t, bodyStr, "'apple':")
	})
}
