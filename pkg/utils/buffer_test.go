package utils

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeBufferWriteStringReset(t *testing.T) {
	var b SafeBuffer

	assert.Empty(t, b.String(), "a new buffer should be empty")

	n, err := b.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", b.String())

	n, err = b.Write([]byte(" world"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.Equal(t, "hello world", b.String())

	b.Reset()
	assert.Empty(t, b.String(), "buffer should be empty after reset")
}

// TestSafeBufferConcurrent exercises concurrent writers, readers, and resets
// Run with -race: a plain bytes.Buffer would trigger a data race here
func TestSafeBufferConcurrent(t *testing.T) {
	var b SafeBuffer

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() {
			payload := []byte("g" + strconv.Itoa(i) + ";")
			for range iterations {
				_, _ = b.Write(payload)
				_ = b.String()
			}
		})
	}

	// A handful of goroutines that reset concurrently with the writers.
	for range goroutines / 10 {
		wg.Go(func() {
			for range iterations {
				b.Reset()
			}
		})
	}

	wg.Wait()

	// No data race and no panic means the buffer coordinated access correctly
}
