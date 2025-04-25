package server

import (
	"io/fs"
	"net/http"
	"path/filepath"
)

// staticFS extends http.FileSystem but does not list files in a directory
type staticFS struct {
	fs http.FileSystem
}

func newStaticFS(data fs.FS) staticFS {
	return staticFS{
		fs: http.FS(data),
	}
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
