package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	issvg "github.com/h2non/go-is-svg"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

func (s *Server) loadFavicon() error {
	cfg := config.Get()
	faviconValue := strings.TrimSpace(cfg.Server.Favicon)
	if faviconValue == "" {
		s.favicon = nil
		return nil
	}

	var (
		data []byte
		err  error
	)

	// Check if the favicon is a URL
	if strings.HasPrefix(faviconValue, "http://") || strings.HasPrefix(faviconValue, "https://") {
		data, err = downloadFaviconFromURL(faviconValue)
	} else {
		// Assume it's an actual base64-encoded image
		data, err = decodeFaviconBase64(faviconValue)
	}
	if err != nil {
		return err
	}

	// Detect favicon type
	favicon, err := detectFavicon(data)
	if err != nil {
		return err
	}
	s.favicon = favicon

	return nil
}

func downloadFaviconFromURL(faviconURL string) ([]byte, error) {
	// Create the request
	req, err := http.NewRequest(http.MethodGet, faviconURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create the favicon request for URL '%s': %w", faviconURL, err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download favicon from '%s': %w", faviconURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to download favicon from '%s': received HTTP status %d", faviconURL, resp.StatusCode)
	}

	// Read the response, max 2MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read downloaded favicon data: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("downloaded favicon from '%s' is empty", faviconURL)
	}

	return data, nil
}

func decodeFaviconBase64(value string) ([]byte, error) {
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', ' ':
			return -1
		default:
			return r
		}
	}, value)

	// Try decoding using base64-standard first, then base64-url
	data, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode favicon base64 value: %w", err)
		}
	}
	if len(data) == 0 {
		return nil, errors.New("decoded favicon base64 value is empty")
	}

	return data, nil
}

func detectFavicon(data []byte) (*appFavicon, error) {
	// PNG magic bytes
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return &appFavicon{
			Path:        "favicon.png",
			ContentType: "image/png",
			LinkType:    "image/png",
			Data:        data,
		}, nil
	}

	// ICO magic bytes
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00 {
		return &appFavicon{
			Path:        "favicon.ico",
			ContentType: "image/x-icon",
			Data:        data,
		}, nil
	}

	// Check if it's a SVG
	if issvg.IsSVG(data) {
		return &appFavicon{
			Path:        "favicon.svg",
			ContentType: "image/svg+xml",
			LinkType:    "image/svg+xml",
			LinkSizes:   "any",
			Data:        data,
		}, nil
	}

	return nil, errors.New("unsupported favicon file format: only PNG, ICO, and SVG are allowed")
}

func (s *Server) addFaviconRoute(basePath string) {
	if s.favicon == nil {
		return
	}

	s.appRouter.GET(
		path.Join(basePath, s.favicon.Path),
		s.addClientCacheHeaders(30*86400),
		func(c *gin.Context) {
			c.Header("Content-Type", s.favicon.ContentType)
			// An SVG opened directly in the browser is rendered as a document, so any script in it would run on our origin
			// This policy stops that, and it has no effect when the browser loads the favicon as an image
			c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
			_, _ = c.Writer.Write(s.favicon.Data)
		},
	)
}
