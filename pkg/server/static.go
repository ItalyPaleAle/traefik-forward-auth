package server

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/italypaleale/traefik-forward-auth/client"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/utils"

	"github.com/gin-gonic/gin"
)

func (s *Server) addStaticRoutes(basePath string) error {
	// Static images
	imgPath := path.Join(basePath, "img")
	if !strings.HasPrefix(imgPath, "/") {
		imgPath = "/" + imgPath
	}
	imgFS, err := client.StaticImg()
	if err != nil {
		return fmt.Errorf("failed to open embedded static assets FS: %w", err)
	}
	imgHandler := http.StripPrefix(imgPath, http.FileServer(newStaticFS(imgFS)))

	// Compiled assets
	assetsFS, err := client.Assets()
	if err != nil {
		return fmt.Errorf("failed to open embedded assets FS: %w", err)
	}
	assetsHandler := http.FileServer(newStaticFS(assetsFS))

	// icons.js
	err = s.addIconsJSRoute(basePath, assetsFS)
	if err != nil {
		return fmt.Errorf("failed to add route for icons.js: %w", err)
	}

	// Use custom static file handler with cache control headers
	// Gin's Serve* methods do not allow setting custom headers
	s.appRouter.GET(
		imgPath+"/*filepath",
		// Add cache-control header for static assets to cache for 30 days
		s.addClientCacheHeaders(30*86400),
		gin.WrapH(imgHandler),
	)

	// Add a route for static compiled assets
	s.addStaticAssetRoute(basePath, "style.css", "text/css", assetsHandler)

	return nil
}

func (s *Server) addStaticAssetRoute(basePath string, assetName string, contentType string, assetsHandler http.Handler) {
	s.appRouter.GET(
		path.Join(basePath, assetName),
		// Replace the path in the request with just the file name
		// This way, assetsHandler can find it in its virtual FS
		replaceRequestPath(assetName),
		// Add the content-type header
		s.addContentType(contentType),
		// Add cache-control header for static assets to cache for 30 days
		s.addClientCacheHeaders(30*86400),
		// Serve the asset
		gin.WrapH(assetsHandler),
	)
}

func (s *Server) addContentType(contentType string) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Header("Content-Type", contentType)
	}
}

func (s *Server) addClientCacheHeaders(cacheMaxAge int64) func(c *gin.Context) {
	cfg := config.Get()

	cacheControlHeader := fmt.Sprintf("public, max-age=%d", cacheMaxAge)

	// Go does not save the last modification time for embedded files
	// As a workaround, we set the time the app started as modification time
	lastModifiedHeader := s.startTime.Format(time.RFC1123)

	if cfg.Dev.DisableClientCache {
		return func(c *gin.Context) {
			c.Header("Cache-Control", "no-cache")
		}
	}

	return func(c *gin.Context) {
		if s.isNotModified(c) {
			// Request has already been aborted
			return
		}

		// Add cache-control and last-modified header
		c.Header("Cache-Control", cacheControlHeader)
		c.Header("Last-Modified", lastModifiedHeader)
	}
}

func (s *Server) addIconsJSRoute(basePath string, assetsFS fs.FS) error {
	iconsJSData, err := utils.ReadFileFromFS(assetsFS, "icons.js")
	if err != nil {
		return fmt.Errorf("failed to read embedded 'icons.js': %w", err)
	}
	iconsJSStart, iconsJSEnd, ok := bytes.Cut(iconsJSData, []byte("process.env.ICONS_DATA"))
	if !ok || len(iconsJSStart) == 0 || len(iconsJSEnd) == 0 {
		return errors.New("embedded 'icons.js' does not include the 'process.env.ICONS_DATA' token for replacing")
	}
	// Append curly brackets
	iconsJSStart = append(iconsJSStart, '{')
	iconsJSEnd = append([]byte{'}'}, iconsJSEnd...)

	// Path is <base>/icons.js
	// Optional query parameter ?include contains a comma-separated list of icons to include (by default it includes all)
	s.appRouter.GET(
		path.Join(basePath, "icons.js"),
		// Set the content type explicitly
		s.addContentType("application/javascript"),
		// Add cache-control header for static assets to cache for 30 days
		s.addClientCacheHeaders(30*86400),
		// Serve the JS file
		func(c *gin.Context) {
			// Write the initial part of the data
			c.Writer.Write(iconsJSStart)

			// Write the JSON-serialized list of icons
			if q := c.Query("include"); q != "" {
				for name := range strings.SplitSeq(q, ",") {
					if s.icons[name] == "" {
						// Skip icons that don't exist
						continue
					}
					c.Writer.WriteString("'" + name + "':`" + s.icons[name] + "`,")
				}
			} else {
				// No list requested, write all icons
				for name := range s.icons {
					c.Writer.WriteString("'" + name + "':`" + s.icons[name] + "`,")
				}
			}

			// Write the final part of the data
			c.Writer.Write(iconsJSEnd)
		},
	)

	return nil
}

func (s *Server) isNotModified(c *gin.Context) bool {
	// Check if there's an If-Modified-Since header
	ims := c.Request.Header.Get("If-Modified-Since")
	if ims == "" {
		return false
	}

	imsDate, err := time.Parse(time.RFC1123, ims)
	// Ignore headers with invalid dates
	if err != nil || !imsDate.After(s.startTime) {
		return false
	}

	c.AbortWithStatus(http.StatusNotModified)
	return true
}

func replaceRequestPath(path string) func(c *gin.Context) {
	return func(c *gin.Context) {
		r := new(http.Request)
		*r = *c.Request
		r.URL = new(url.URL)
		*r.URL = *c.Request.URL
		r.URL.Path = "/" + path
		r.URL.RawPath = "/" + path
		c.Request = r
	}
}

func (s *Server) loadTemplates(router *gin.Engine) error {
	// Templates
	assetsFS, err := client.Assets()
	if err != nil {
		return fmt.Errorf("failed to open embedded assets FS: %w", err)
	}

	// Parse all templates
	s.templates, err = template.ParseFS(assetsFS, "*.tpl")
	if err != nil {
		return fmt.Errorf("failed to parse templates: %w", err)
	}
	router.SetHTMLTemplate(s.templates)

	// Read all icons
	iconsFS := client.Icons()
	entries, err := iconsFS.ReadDir("icons")
	if err != nil {
		return fmt.Errorf("failed to read embedded icons directory: %w", err)
	}
	s.icons = make(map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			// There shouldn't be any directory
			continue
		}
		name := e.Name()
		ext := filepath.Ext(name)
		if ext != ".svg" {
			// All files should be SVGs
			continue
		}
		iconName := name[0 : len(name)-4]
		var iconData []byte
		iconData, err = iconsFS.ReadFile("icons/" + name)
		if err != nil {
			return fmt.Errorf("failed to read embedded icon '%s': %w", name, err)
		}
		s.icons[iconName] = minifySVG(iconData)
	}

	return nil
}

// minifySVG removes all newlines and XML comments from the input string
func minifySVG(inputData []byte) string {
	// Remove all newlines (both \n and \r)
	result := strings.ReplaceAll(string(inputData), "\n", "")
	result = strings.ReplaceAll(result, "\r", "")

	// Remove XML comments (<!-- ... -->)
	for {
		start := strings.Index(result, "<!--")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "-->")
		if end == -1 {
			break
		}
		end += start + 3
		result = result[:start] + result[end:]
	}

	return result
}

// staticFS extends http.FileSystem but does not list files in a directory
type staticFS struct {
	fs http.FileSystem
}

func newStaticFS(data fs.FS) staticFS {
	return staticFS{
		fs: http.FS(data),
	}
}

func (s staticFS) GetModifiedTime(path string) (time.Time, error) {
	f, err := s.fs.Open(path)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return time.Time{}, err
	}

	return stat.ModTime().UTC(), nil
}

func (s staticFS) Open(path string) (http.File, error) {
	// Open the file or directory
	f, err := s.fs.Open(path)
	if err != nil {
		return nil, err
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// If it's a directory, return the index.html file if present
	if stat.IsDir() {
		index := filepath.Join(path, "index.html")

		// If the index.html file doesn't exist, returns ErrNotExist which causes the server to respond with a 404
		_, err = s.fs.Open(index)
		if err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, closeErr
			}

			return nil, err
		}
	}

	// If we're here, we have a valid file descriptor, either for a file or folder
	return f, nil
}
