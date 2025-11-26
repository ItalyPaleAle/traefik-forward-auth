package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

func TestGetCSPOriginFromUrl(t *testing.T) {
	t.Run("https URL", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("https://example.com/path/to/image.jpg")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com", result)
	})

	t.Run("https URL with port", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("https://cdn.example.com:8443/images/bg.png")
		require.NoError(t, err)
		assert.Equal(t, "https://cdn.example.com:8443", result)
	})

	t.Run("http URL", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("http://example.com/image.jpg")
		require.NoError(t, err)
		// For HTTP URLs, only the host is returned (no protocol)
		assert.Equal(t, "example.com", result)
	})

	t.Run("http URL with port", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("http://localhost:8080/bg.jpg")
		require.NoError(t, err)
		assert.Equal(t, "localhost:8080", result)
	})

	t.Run("URL with query parameters", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("https://cdn.example.com/image.jpg?size=large&quality=high")
		require.NoError(t, err)
		assert.Equal(t, "https://cdn.example.com", result)
	})

	t.Run("URL with fragment", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("https://example.com/path#fragment")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com", result)
	})

	t.Run("URL with subdomain", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("https://static.cdn.example.com/bg.jpg")
		require.NoError(t, err)
		assert.Equal(t, "https://static.cdn.example.com", result)
	})

	t.Run("empty string", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("")
		require.NoError(t, err)
		// Empty URL parses but has empty host
		assert.Empty(t, result)
	})

	t.Run("relative URL", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("/path/to/image.jpg")
		require.NoError(t, err)
		// Relative URLs have empty host
		assert.Empty(t, result)
	})

	t.Run("URL with IPv4 address", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("https://192.168.1.100/image.jpg")
		require.NoError(t, err)
		assert.Equal(t, "https://192.168.1.100", result)
	})

	t.Run("URL with IPv6 address", func(t *testing.T) {
		result, err := getCSPOriginFromUrl("https://[2001:db8::1]/image.jpg")
		require.NoError(t, err)
		assert.Equal(t, "https://[2001:db8::1]", result)
	})
}

func TestSetPagesPortalConfig(t *testing.T) {
	t.Run("both backgrounds empty - use defaults", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, defaultPagesBackgroundMedium, portal.PagesBackgroundMedium)
		assert.Equal(t, defaultPagesBackgroundLarge, portal.PagesBackgroundLarge)
		// When no external images are used, the CSP header should just have 'self'
		const expectedHeader = `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("custom large background only", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge: "https://cdn.example.com/large-bg.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, defaultPagesBackgroundMedium, portal.PagesBackgroundMedium)
		assert.Equal(t, "https://cdn.example.com/large-bg.jpg", portal.PagesBackgroundLarge)
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn.example.com; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("custom medium background only", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundMedium: "https://images.example.com/medium-bg.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "https://images.example.com/medium-bg.jpg", portal.PagesBackgroundMedium)
		assert.Equal(t, defaultPagesBackgroundLarge, portal.PagesBackgroundLarge)
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' https://images.example.com; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("both backgrounds from same origin", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge:  "https://cdn.example.com/large.jpg",
			BackgroundMedium: "https://cdn.example.com/medium.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "https://cdn.example.com/medium.jpg", portal.PagesBackgroundMedium)
		assert.Equal(t, "https://cdn.example.com/large.jpg", portal.PagesBackgroundLarge)
		// Should only include the origin once in CSP
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn.example.com; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("both backgrounds from different origins", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge:  "https://cdn1.example.com/large.jpg",
			BackgroundMedium: "https://cdn2.example.com/medium.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "https://cdn2.example.com/medium.jpg", portal.PagesBackgroundMedium)
		assert.Equal(t, "https://cdn1.example.com/large.jpg", portal.PagesBackgroundLarge)
		// Should include both origins in CSP
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn1.example.com https://cdn2.example.com; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("HTTP backgrounds from different origins", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge:  "http://cdn1.example.com/large.jpg",
			BackgroundMedium: "http://cdn2.example.com/medium.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "http://cdn2.example.com/medium.jpg", portal.PagesBackgroundMedium)
		assert.Equal(t, "http://cdn1.example.com/large.jpg", portal.PagesBackgroundLarge)
		// HTTP URLs should not include the protocol in CSP
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' cdn1.example.com cdn2.example.com; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("mixed HTTP and HTTPS backgrounds", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge:  "https://cdn1.example.com/large.jpg",
			BackgroundMedium: "http://cdn2.example.com/medium.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "http://cdn2.example.com/medium.jpg", portal.PagesBackgroundMedium)
		assert.Equal(t, "https://cdn1.example.com/large.jpg", portal.PagesBackgroundLarge)
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn1.example.com cdn2.example.com; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("backgrounds with ports", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge:  "https://cdn.example.com:8443/large.jpg",
			BackgroundMedium: "https://cdn.example.com:9443/medium.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "https://cdn.example.com:9443/medium.jpg", portal.PagesBackgroundMedium)
		assert.Equal(t, "https://cdn.example.com:8443/large.jpg", portal.PagesBackgroundLarge)
		// Different ports mean different origins
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn.example.com:8443 https://cdn.example.com:9443; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("relative URL backgrounds", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge:  "/images/large.jpg",
			BackgroundMedium: "/images/medium.jpg",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "/images/medium.jpg", portal.PagesBackgroundMedium)
		assert.Equal(t, "/images/large.jpg", portal.PagesBackgroundLarge)
		// Relative URLs have empty host, so CSP should just have img-src 'self'
		expectedHeader := `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
	})

	t.Run("backgrounds with query parameters", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{
			BackgroundLarge:  "https://cdn.example.com/large.jpg?width=1920&height=1080",
			BackgroundMedium: "https://cdn.example.com/medium.jpg?width=1280&height=720",
		}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		assert.Equal(t, "https://cdn.example.com/medium.jpg?width=1280&height=720", portal.PagesBackgroundMedium)
		assert.Equal(t, "https://cdn.example.com/large.jpg?width=1920&height=1080", portal.PagesBackgroundLarge)
		// Query parameters should not affect the origin in CSP
		const expectedHeader = `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn.example.com; font-src 'self'`
		assert.Equal(t, expectedHeader, portal.PagesCSPHeader("NONCE"))
		assert.NotContains(t, portal.PagesCSPHeader("NONCE"), "width=")
		assert.NotContains(t, portal.PagesCSPHeader("NONCE"), "height=")
	})

	t.Run("CSP header format check", func(t *testing.T) {
		portal := &Portal{}
		configPortal := config.ConfigPortal{}

		err := setPagesPortalConfig(configPortal, portal)
		require.NoError(t, err)

		// Verify the CSP header contains all required directives
		cspHeader := portal.PagesCSPHeader("NONCE")
		assert.Contains(t, cspHeader, "default-src 'none'")
		assert.Contains(t, cspHeader, "script-src 'nonce-NONCE'")
		assert.Contains(t, cspHeader, "style-src 'self' 'unsafe-inline'")
		assert.Contains(t, cspHeader, "img-src 'self'")
		assert.Contains(t, cspHeader, "font-src 'self'")
	})
}

func TestGetPagesCSPHeaderFn(t *testing.T) {
	t.Run("Empty cspImgSrc", func(t *testing.T) {
		fn := getPagesCSPHeaderFn("")
		nonce := "test-nonce"
		header := fn(nonce)

		assert.Contains(t, header, "script-src 'nonce-test-nonce'")
		assert.Contains(t, header, "img-src 'self'")
		assert.NotContains(t, header, "NONCE")
	})

	t.Run("With cspImgSrc", func(t *testing.T) {
		fn := getPagesCSPHeaderFn(" https://example.com")
		nonce := "another-nonce"
		header := fn(nonce)

		assert.Contains(t, header, "script-src 'nonce-another-nonce'")
		assert.Contains(t, header, "img-src 'self' https://example.com")
		assert.NotContains(t, header, "NONCE")
	})
}
