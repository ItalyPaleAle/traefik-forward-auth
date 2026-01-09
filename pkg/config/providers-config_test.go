package config

import (
	"testing"
)

func TestValidateAndNormalizeCapabilityName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  string
		expectErr bool
	}{
		{
			name:      "Valid capability name without prefix",
			input:     "example.com/capability",
			expected:  "example.com/capability",
			expectErr: false,
		},
		{
			name:      "Valid capability name with https:// prefix",
			input:     "https://example.com/capability",
			expected:  "example.com/capability",
			expectErr: false,
		},
		{
			name:      "Valid default capability",
			input:     "italypaleale.me/traefik-forward-auth",
			expected:  "italypaleale.me/traefik-forward-auth",
			expectErr: false,
		},
		{
			name:      "Valid with https prefix and multi-level path",
			input:     "https://example.com/path/to/cap",
			expected:  "example.com/path/to/cap",
			expectErr: false,
		},
		{
			name:      "Invalid - http:// prefix",
			input:     "http://example.com/capability",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Invalid - no path",
			input:     "example.com",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Invalid - https:// but no path",
			input:     "https://example.com",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Invalid - only path",
			input:     "/capability",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Invalid - empty string",
			input:     "",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Invalid - path with trailing slash only",
			input:     "example.com/",
			expected:  "",
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validateAndNormalizeCapabilityName(test.input)
			if test.expectErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != test.expected {
					t.Errorf("Expected '%s' but got '%s'", test.expected, result)
				}
			}
		})
	}
}
