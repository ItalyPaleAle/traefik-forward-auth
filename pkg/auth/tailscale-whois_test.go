//go:build unit

package auth

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTailscaleWhois(t *testing.T) {
	tests := []struct {
		name            string
		opts            NewTailscaleWhoisOptions
		expectCapNames  []string
		expectAllowedTN string
	}{
		{
			name: "With capability names",
			opts: NewTailscaleWhoisOptions{
				CapabilityNames: []string{"example.com/cap1", "test.com/cap2"},
				AllowedTailnet:  "mytailnet.ts.net",
			},
			expectCapNames:  []string{"example.com/cap1", "test.com/cap2"},
			expectAllowedTN: "mytailnet.ts.net",
		},
		{
			name: "Empty capability names",
			opts: NewTailscaleWhoisOptions{
				CapabilityNames: []string{},
				AllowedTailnet:  "mytailnet.ts.net",
			},
			expectCapNames:  []string{},
			expectAllowedTN: "mytailnet.ts.net",
		},
		{
			name: "Nil capability names",
			opts: NewTailscaleWhoisOptions{
				CapabilityNames: nil,
			},
			expectCapNames:  nil,
			expectAllowedTN: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewTailscaleWhois(tt.opts)
			require.NoError(t, err)
			require.NotNil(t, provider)

			// Check that capability names were set correctly
			assert.Equal(t, tt.expectCapNames, provider.capabilityNames)

			// Check that allowed tailnet was set correctly
			assert.Equal(t, tt.expectAllowedTN, provider.allowedTailnet)
		})
	}
}

func TestTailscaleWhoisCapabilityExtraction(t *testing.T) {
	// Test that json.RawMessage can be properly created from string
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple JSON object",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "JSON array",
			input:    `["item1", "item2"]`,
			expected: `["item1", "item2"]`,
		},
		{
			name:     "Complex nested JSON",
			input:    `{"nested": {"key": "value"}, "array": [1, 2, 3]}`,
			expected: `{"nested": {"key": "value"}, "array": [1, 2, 3]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert string to json.RawMessage
			rawMsg := json.RawMessage(tt.input)

			// Verify it can be marshaled back
			marshaled, err := json.Marshal(rawMsg)
			require.NoError(t, err)
			require.JSONEq(t, tt.expected, string(marshaled))
		})
	}
}
