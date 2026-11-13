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

func TestClientIPFromXForwardedFor(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"203.0.113.10", "203.0.113.10"},
		{" 203.0.113.10 ", "203.0.113.10"},
		{"203.0.113.10, 10.0.0.1", "10.0.0.1"},
		{"203.0.113.10,10.0.0.1", "10.0.0.1"},
		{"203.0.113.10 , 10.0.0.5 , 192.168.1.1", "192.168.1.1"},
		{"2001:db8::1, fd00::2", "fd00::2"},
		{"", ""},
		{"203.0.113.10,", ""},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			assert.Equal(t, tt.want, ClientIPFromXForwardedFor(tt.value))
		})
	}
}
