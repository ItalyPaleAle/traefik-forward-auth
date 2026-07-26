package server

import (
	"net/http"
	"net/textproto"
	"strings"

	"github.com/gin-gonic/gin"
)

// headerValue returns the first value of a request header, whose name must already be in canonical form
func headerValue(h http.Header, canonicalName string) string {
	// Reading the map directly skips the key canonicalization that http.Header.Get performs on every call
	v := h[canonicalName]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// setResponseHeader sets a response header, skipping the canonicalization http.Header.Set performs
// The name must already be in canonical form
// An empty value removes the header, matching the behavior of gin's Context.Header
func setResponseHeader(c *gin.Context, canonicalName string, value string) {
	h := c.Writer.Header()
	if value == "" {
		delete(h, canonicalName)
		return
	}
	h[canonicalName] = []string{value}
}

// maxRequestCookies is the number of cookies past which a request's Cookie header is ignored entirely
// This mirrors net/http's own limit, so that a request rejected by http.Request.Cookies is rejected here too
const maxRequestCookies = 3000

// rangeRequestCookies calls fn for each cookie in the request's Cookie header, stopping early if fn returns false.
//
// It exists because http.Request.Cookies allocates a slice and an http.Cookie for every cookie the client sent, only for the caller to look at one or two of them.
// Requests carry the session cookie on every call Traefik forwards, so that showed up as one of the largest sources of allocations on the hot path.
// Parsing here follows net/http's readCookies exactly, minus the allocations; TestRangeRequestCookiesMatchesNetHTTP checks the two agree.
func rangeRequestCookies(h http.Header, fn func(name string, value string) bool) {
	lines := h["Cookie"]
	if len(lines) == 0 {
		return
	}

	// net/http drops every cookie once a request carries too many of them, so a request it would reject must not authenticate here either
	cookieCount := 0
	for _, line := range lines {
		cookieCount += strings.Count(line, ";") + 1
	}
	if cookieCount > maxRequestCookies {
		return
	}

	for _, line := range lines {
		line = textproto.TrimString(line)

		var part string
		for len(line) > 0 {
			part, line, _ = strings.Cut(line, ";")
			part = textproto.TrimString(part)
			if part == "" {
				continue
			}

			name, value, _ := strings.Cut(part, "=")
			name = textproto.TrimString(name)
			if !isHTTPToken(name) {
				continue
			}

			value, ok := parseRequestCookieValue(value)
			if !ok {
				continue
			}

			if !fn(name, value) {
				return
			}
		}
	}
}

// parseRequestCookieValue strips the optional surrounding double quotes from a cookie value and rejects values containing bytes that are not allowed in one
// It is the equivalent of net/http's parseCookieValue with allowDoubleQuote set
func parseRequestCookieValue(raw string) (string, bool) {
	if len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}

	for i := range len(raw) {
		// Same set as net/http's validCookieValueByte
		if b := raw[i]; b < 0x20 || b >= 0x7f || b == '"' || b == ';' || b == '\\' {
			return "", false
		}
	}

	return raw, true
}

// tokenChars marks the characters that may appear in an HTTP token (RFC 9110, section 5.6.2)
var tokenChars = func() (t [256]bool) {
	const chars = "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range len(chars) {
		t[chars[i]] = true
	}
	return t
}()

// isHTTPToken reports whether v is a valid HTTP token, which is the check net/http applies to a cookie's name before accepting it
func isHTTPToken(v string) bool {
	if v == "" {
		return false
	}

	for i := range len(v) {
		if !tokenChars[v[i]] {
			return false
		}
	}

	return true
}
