package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateAndNormalizeCapabilityName(tt.input)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
