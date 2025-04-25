package client

import (
	"embed"
	"io/fs"
)

var (
	//go:embed dist
	dist embed.FS
	//go:embed static
	static embed.FS
	//go:embed icons
	icons embed.FS
)

// Dist contains the templates and compiled assets
func Dist() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}

// StaticImg contains static images, and can be served as-is
func StaticImg() (fs.FS, error) {
	return fs.Sub(static, "static/img")
}

// Icons contains all SVG icons
func Icons() (fs.FS, error) {
	return fs.Sub(icons, "icons")
}
