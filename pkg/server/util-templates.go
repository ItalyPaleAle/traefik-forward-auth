package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

const (
	defaultPagesBackgroundMedium = "img/greta-farnedi-EAt30ojfzOI-unsplash-md.webp"
	defaultPagesBackgroundLarge  = "img/greta-farnedi-EAt30ojfzOI-unsplash-lg.webp"

	// Format string for the Content-Security-Policy header for templated pages
	pagesContentSecurityHeaderFmt = `default-src 'none'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'%s; font-src 'self'`
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

	portal.PagesCSPHeader = fmt.Sprintf(pagesContentSecurityHeaderFmt, cspImgSrc)

	return nil
}

func setPageSecurityHeaders(c *gin.Context, portal *Portal) {
	// Set the CSP header and the legacy X-Frame-Options
	c.Header("Content-Security-Policy", portal.PagesCSPHeader)
	c.Header("X-Frame-Options", "DENY")

	// Disable FLOC
	c.Header("Permissions-Policy", "interest-cohort=()")

	// Disable indexing by search engines
	c.Header("X-Robots-Tag", "noindex, nofollow")
}

func (s *Server) renderSigninTemplate(c *gin.Context, portal *Portal, stateCookieID string, nonce string, logoutBanner bool) {
	conf := config.Get()

	//nolint:revive
	type signingTemplateData_Provider struct {
		Color       string
		DisplayName string
		Href        string
		Svg         template.HTML
	}

	type signinTemplateData struct {
		Title            string
		BaseUrl          string
		Providers        []signingTemplateData_Provider
		LogoutBanner     bool
		BackgroundLarge  string
		BackgroundMedium string
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
	for _, name := range portal.ProvidersList {
		provider := portal.Providers[name]

		pd := signingTemplateData_Provider{
			Color:       provider.GetProviderColor(),
			DisplayName: provider.GetProviderDisplayName(),
			Href:        getPortalURI(c, portal.Name) + "/providers/" + name + "?state=" + stateCookieID + "~" + nonce,
		}

		iconStr, ok := s.icons[provider.GetProviderIcon()]
		if ok && iconStr != "" {
			//nolint:gosec
			pd.Svg = template.HTML(iconStr)
		} else {
			// Default is to add an empty svg, to ensure elements are aligned
			//nolint:gosec
			pd.Svg = template.HTML(`<svg class="provider-icon" aria-hidden="true"></svg>`)
		}

		data.Providers[i] = pd
		i++
	}

	setPageSecurityHeaders(c, portal)
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
	}

	setPageSecurityHeaders(c, portal)
	c.HTML(http.StatusOK, "authenticated.html.tpl", authenticatedTemplateData{
		Title:            portal.DisplayName,
		BaseUrl:          conf.Server.BasePath,
		Provider:         provider.GetProviderDisplayName(),
		User:             userID,
		LogoutUrl:        getPortalURI(c, portal.Name) + "/logout",
		BackgroundLarge:  portal.PagesBackgroundLarge,
		BackgroundMedium: portal.PagesBackgroundMedium,
	})
}
