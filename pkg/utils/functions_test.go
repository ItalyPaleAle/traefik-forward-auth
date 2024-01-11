package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSubDomain(t *testing.T) {
	tests := []struct {
		domain string
		sub    string
		result bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "sub.example.com", true},
		{"example.com", "sub.sub.example.com", true},
		{"example.com", "example.org", false},
		{"example.com", "sub.example.org", false},
		{"example.com", "sub.sub.example.org", false},
	}

	for _, tc := range tests {
		result := IsSubDomain(tc.domain, tc.sub)
		assert.Equalf(t, tc.result, result, "domain='%s' sub='%s'", tc.domain, tc.sub)
	}
}
