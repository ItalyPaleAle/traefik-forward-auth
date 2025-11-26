package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

const (
	defaultPagesBackgroundMedium = "img/greta-farnedi-EAt30ojfzOI-unsplash-md.webp"
	defaultPagesBackgroundLarge  = "img/greta-farnedi-EAt30ojfzOI-unsplash-lg.webp"

	// Format string for the Content-Security-Policy header for templated pages
	pagesContentSecurityHeaderFmt = `default-src 'none'; script-src 'nonce-NONCE'; style-src 'self' 'unsafe-inline'; img-src 'self'%s; font-src 'self'`
)

func getCSPOriginFromUrl(str string) (string, error) {
	u, err := url.Parse(str)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	src := u.Host

	// If the URL is for a resource served via HTTPS, make sure we add the protocol
	if u.Scheme == "https" {
		src = "https://" + src
	}

	return src, nil
}

func setPagesPortalConfig(p config.ConfigPortal, portal *Portal) error {
	// If nothing is set for backgrounds, return the default value
	// Otherwise, we need to get the domain name so we can set the CSP header
	var cspImgSrc string
	if p.BackgroundLarge == "" {
		portal.PagesBackgroundLarge = defaultPagesBackgroundLarge
	} else {
		src, err := getCSPOriginFromUrl(p.BackgroundLarge)
		if err != nil {
			return fmt.Errorf("invalid value for the BackgroundLarge property: %w", err)
		}
		cspImgSrc = src

		portal.PagesBackgroundLarge = p.BackgroundLarge
	}

	if p.BackgroundMedium == "" {
		portal.PagesBackgroundMedium = defaultPagesBackgroundMedium
	} else {
		src, err := getCSPOriginFromUrl(p.BackgroundMedium)
		if err != nil {
			return fmt.Errorf("invalid value for the portal's BackgroundMedium property: %w", err)
		}

		// Add only if the value is different
		if cspImgSrc == "" {
			cspImgSrc = src
		} else if cspImgSrc != src {
			cspImgSrc += " " + src
		}

		portal.PagesBackgroundMedium = p.BackgroundMedium
	}

	if cspImgSrc != "" {
		cspImgSrc = " " + cspImgSrc
	}

	portal.PagesCSPHeader = getPagesCSPHeaderFn(cspImgSrc)

	return nil
}

func getPagesCSPHeaderFn(cspImgSrc string) func(nonce string) string {
	// Pre-calculate the parts of the CSP header to avoid allocations during requests
	const noncePlaceholder = "NONCE"
	cspParts := strings.Split(fmt.Sprintf(pagesContentSecurityHeaderFmt, cspImgSrc), noncePlaceholder)
	if len(cspParts) < 2 {
		// Should not happen...
		panic("failed to find NONCE placeholder in CSP header template")
	}

	return func(nonce string) string {
		return strings.Join(cspParts, nonce)
	}
}

func setPageSecurityHeaders(c *gin.Context, portal *Portal) string {
	nonce := generateNonce()

	// Set the CSP header and the legacy X-Frame-Options
	c.Header("Content-Security-Policy", portal.PagesCSPHeader(nonce))
	c.Header("X-Frame-Options", "DENY")

	// Disable FLOC
	c.Header("Permissions-Policy", "interest-cohort=()")

	// Disable indexing by search engines
	c.Header("X-Robots-Tag", "noindex, nofollow")

	return nonce
}

func generateNonce() string {
	nonceBytes := make([]byte, 5)
	// Per documentation, this never returns an error
	// On some legacy Linux systems, it could cause a panic if there's no sufficient entropy
	_, _ = rand.Read(nonceBytes)
	return hex.EncodeToString(nonceBytes)
}

func (s *Server) renderSigninTemplate(c *gin.Context, portal *Portal, stateCookieID string, nonce string, logoutBanner bool) {
	conf := config.Get()

	//nolint:revive
	type signingTemplateData_Provider struct {
		Color       string
		DisplayName string
		Href        string
		Icon        string
	}

	type signinTemplateData struct {
		Title            string
		BaseUrl          string
		Providers        []signingTemplateData_Provider
		LogoutBanner     bool
		BackgroundLarge  string
		BackgroundMedium string
		UsedIcons        string
		CspNonce         string
	}

	data := signinTemplateData{
		Title:            portal.DisplayName,
		BaseUrl:          conf.Server.BasePath,
		Providers:        make([]signingTemplateData_Provider, len(portal.Providers)),
		LogoutBanner:     logoutBanner,
		BackgroundLarge:  portal.PagesBackgroundLarge,
		BackgroundMedium: portal.PagesBackgroundMedium,
	}

	var i int
	usedIcons := make(map[string]struct{}, len(portal.ProvidersList))
	for _, name := range portal.ProvidersList {
		provider := portal.Providers[name]

		icon := provider.GetProviderIcon()
		if icon != "" {
			_, present := usedIcons[icon]
			if !present {
				usedIcons[icon] = struct{}{}
				if data.UsedIcons == "" {
					data.UsedIcons = icon
				} else {
					data.UsedIcons += "," + icon
				}
			}
		}

		data.Providers[i] = signingTemplateData_Provider{
			Color:       provider.GetProviderColor(),
			DisplayName: provider.GetProviderDisplayName(),
			Href:        getPortalURI(c, portal.Name) + "/providers/" + name + "?state=" + stateCookieID + "~" + nonce,
			Icon:        icon,
		}
		i++
	}

	data.CspNonce = setPageSecurityHeaders(c, portal)
	c.HTML(http.StatusOK, "signin.html.tpl", data)
}

func (s *Server) renderAuthenticatedTemplate(c *gin.Context, portal *Portal, provider auth.Provider, userID string) {
	conf := config.Get()

	// Respond with 200, indicating Traefik that the user is successfully-authenticated
	// Display a nice-looking body in case a visitor is hitting the auth server directly
	type authenticatedTemplateData struct {
		Title            string
		BaseUrl          string
		Provider         string
		User             string
		LogoutUrl        string
		BackgroundLarge  string
		BackgroundMedium string
		CspNonce         string
	}

	nonce := setPageSecurityHeaders(c, portal)
	c.HTML(http.StatusOK, "authenticated.html.tpl", authenticatedTemplateData{
		Title:            portal.DisplayName,
		BaseUrl:          conf.Server.BasePath,
		Provider:         provider.GetProviderDisplayName(),
		User:             userID,
		LogoutUrl:        getPortalURI(c, portal.Name) + "/logout",
		BackgroundLarge:  portal.PagesBackgroundLarge,
		BackgroundMedium: portal.PagesBackgroundMedium,
		CspNonce:         nonce,
	})
}
