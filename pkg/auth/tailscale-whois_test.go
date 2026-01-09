//go:build unit

package auth

import (
	"encoding/json"
	"testing"
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, err := NewTailscaleWhois(test.opts)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if provider == nil {
				t.Fatal("Expected provider but got nil")
			}

			// Check that capability names were set correctly
			if len(provider.capabilityNames) != len(test.expectCapNames) {
				t.Errorf("Expected %d capability names, got %d", len(test.expectCapNames), len(provider.capabilityNames))
			}

			for i, expected := range test.expectCapNames {
				if i >= len(provider.capabilityNames) {
					break
				}
				if provider.capabilityNames[i] != expected {
					t.Errorf("Expected capability name[%d] = '%s', got '%s'", i, expected, provider.capabilityNames[i])
				}
			}

			// Check that allowed tailnet was set correctly
			if provider.allowedTailnet != test.expectAllowedTN {
				t.Errorf("Expected allowedTailnet = '%s', got '%s'", test.expectAllowedTN, provider.allowedTailnet)
			}
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Convert string to json.RawMessage
			rawMsg := json.RawMessage(test.input)

			// Verify it can be marshaled back
			marshaled, err := json.Marshal(rawMsg)
			if err != nil {
				t.Fatalf("Failed to marshal json.RawMessage: %v", err)
			}

			// Compare (note: marshaling may normalize formatting)
			var expected, actual interface{}
			if err := json.Unmarshal([]byte(test.expected), &expected); err != nil {
				t.Fatalf("Failed to unmarshal expected JSON: %v", err)
			}
			if err := json.Unmarshal(marshaled, &actual); err != nil {
				t.Fatalf("Failed to unmarshal actual JSON: %v", err)
			}

			// Deep comparison using JSON marshaling
			expectedBytes, _ := json.Marshal(expected)
			actualBytes, _ := json.Marshal(actual)
			if string(expectedBytes) != string(actualBytes) {
				t.Errorf("Expected JSON '%s', got '%s'", string(expectedBytes), string(actualBytes))
			}
		})
	}
}
