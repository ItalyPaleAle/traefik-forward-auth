package utils

import (
	"bytes"
	"sync"
)

// SafeBuffer is a concurrency-safe wrapper around bytes.Buffer
// bytes.Buffer is not safe for concurrent use by multiple goroutines, so SafeBuffer serializes all access to the underlying buffer with a mutex
// This lets it be shared across goroutines, for example as one of the destinations of an io.MultiWriter that a slog.Handler writes to concurrently
// It exposes the most commonly used methods of bytes.Buffer
type SafeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

// Write appends the contents of p to the buffer and returns len(p)
func (s *SafeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.b.Write(p)
}

// String returns the contents of the buffer as a string
func (s *SafeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.b.String()
}

// Reset resets the buffer to be empty, retaining the underlying storage for future use
func (s *SafeBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.b.Reset()
}
