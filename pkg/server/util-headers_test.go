package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// TestRangeRequestCookiesMatchesNetHTTP checks that rangeRequestCookies parses a Cookie header exactly the way http.Request.Cookies does, since it exists only to avoid that method's allocations
func TestRangeRequestCookiesMatchesNetHTTP(t *testing.T) {
	collect := func(h http.Header) [][2]string {
		var got [][2]string
		rangeRequestCookies(h, func(name, value string) bool {
			got = append(got, [2]string{name, value})
			return true
		})
		return got
	}

	expected := func(h http.Header) [][2]string {
		req := &http.Request{Header: h}
		var want [][2]string
		for _, ck := range req.Cookies() {
			want = append(want, [2]string{ck.Name, ck.Value})
		}
		return want
	}

	headerLines := [][]string{
		{"tfa_session=abc123"},
		{"tfa_session=abc.def.ghi; other=1"},
		{"  tfa_session = abc123  ;  other =  2  "},
		{`tfa_session="quoted-value"`},
		{`tfa_session="unbalanced`},
		{`tfa_session=unbalanced"`},
		{"tfa_session=abc; tfa_session=def"},
		{"tfa_session=abc; ; ;other=1;"},
		{"tfa_session="},
		{"=novalue"},
		{"novalue"},
		{"tfa_session=abc", "tfa_session_1=def"},
		{"tfa_session=with space"},
		{"tfa_session=with\ttab"},
		{"bad name=value; tfa_session=ok"},
		{"bad(name)=value; tfa_session=ok"},
		{"bad@name=value"},
		{"tfa_session=back\\slash"},
		{"tfa_session=del\x7f"},
		{"tfa_session=hi\x01there"},
		{"!#$%&'*+-.^_`|~=oddbutvalid"},
		{""},
		{"   "},
		{";"},
		{"a=1;b=2;c=3;d=4"},
		{"tfa_session=abc=def"},
	}

	for _, lines := range headerLines {
		t.Run(strings.Join(lines, "|"), func(t *testing.T) {
			h := http.Header{"Cookie": lines}
			assert.Equal(t, expected(h), collect(h))
		})
	}

	t.Run("no cookie header", func(t *testing.T) {
		h := http.Header{}
		assert.Empty(t, collect(h))
		assert.Empty(t, expected(h))
	})

	t.Run("too many cookies are ignored, like net/http", func(t *testing.T) {
		parts := make([]string, maxRequestCookies+1)
		for i := range parts {
			parts[i] = "c" + strconv.Itoa(i) + "=v"
		}
		h := http.Header{"Cookie": []string{strings.Join(parts, "; ")}}

		assert.Empty(t, expected(h), "net/http should drop every cookie past its limit")
		assert.Empty(t, collect(h))
	})

	t.Run("stops early when the callback returns false", func(t *testing.T) {
		h := http.Header{"Cookie": []string{"a=1; b=2; c=3"}}

		var seen []string
		rangeRequestCookies(h, func(name, _ string) bool {
			seen = append(seen, name)
			return name != "b"
		})

		assert.Equal(t, []string{"a", "b"}, seen)
	})
}
