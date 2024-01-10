package utils

import (
	"os"
	"strings"
)

// IsTruthy returns true if a string is truthy, such as "1", "on", "yes", "true", "t", "y"
func IsTruthy(str string) bool {
	if len(str) > 4 {
		// Short-circuit to avoid processing strings that can't be true
		return false
	}
	switch strings.ToLower(str) {
	case "1", "true", "t", "on", "yes", "y":
		return true
	default:
		return false
	}
}

// FileExists returns true if a file exists on disk and is a regular file
func FileExists(path string) (bool, error) {
	s, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return false, err
	}
	return !s.IsDir(), nil
}
