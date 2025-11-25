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
)

// Assets contains the templates and compiled assets
func Assets() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}

// StaticImg contains static images, and can be served as-is
func StaticImg() (fs.FS, error) {
	return fs.Sub(static, "static/img")
}
