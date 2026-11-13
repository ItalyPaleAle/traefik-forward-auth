package utils

import (
	"fmt"
	"io"
	"io/fs"
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

// IsSubDomain returns true if sub is a sub-domain name of domain, or is equal to domain.
func IsSubDomain(domain, sub string) bool {
	return domain == sub ||
		strings.HasSuffix(sub, "."+domain)
}

// ClientIPFromXForwardedFor returns the client IP from an X-Forwarded-For header value
// X-Forwarded-For is a comma-separated chain "client, proxy1, proxy2...", where each proxy appends the address of the peer that connected to it
// We use the last entry because it's the only one added by Traefik itself: every entry before it was sent by an earlier proxy or by the client, so it can be spoofed
// When there are other proxies in front of Traefik, this means the IP is the one of the closest proxy rather than the user's
// The returned string is trimmed of surrounding whitespace and is the empty string if the header is empty
func ClientIPFromXForwardedFor(headerValue string) string {
	idx := strings.LastIndexByte(headerValue, ',')
	return strings.TrimSpace(headerValue[idx+1:])
}

// ReadFileFromFS reads a file from a fs.FS
func ReadFileFromFS(repo fs.FS, name string) ([]byte, error) {
	f, err := repo.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open embedded file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded file: %w", err)
	}

	return data, nil
}
