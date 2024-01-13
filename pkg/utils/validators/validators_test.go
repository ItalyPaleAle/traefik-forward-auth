package validators

import (
	"strings"
	"testing"
)

func TestEmail(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{
			name:   "Valid email",
			input:  "test@example.com",
			expect: true,
		},
		{
			name:   "Invalid email - missing @",
			input:  "testexample.com",
			expect: false,
		},
		{
			name:   "Invalid email - missing domain",
			input:  "test@",
			expect: false,
		},
		{
			name:   "Invalid email - missing local part",
			input:  "@example.com",
			expect: false,
		},
		{
			name:   "Invalid email - invalid characters",
			input:  "test:@example.com",
			expect: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Email(test.input)
			if result != test.expect {
				t.Errorf("Expected %v, but got %v", test.expect, result)
			}
		})
	}
}

func TestBase64URL(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    string
		expectLen int
		expect    bool
	}{
		{
			name:      "Valid API key",
			apiKey:    "PCa4uxUcKmbKNnTkQg-Os7_LkKsxgYRuTp1_83JhAlh",
			expectLen: 43,
			expect:    true,
		},
		{
			name:      "Invalid API key - invalid length",
			apiKey:    "123",
			expectLen: 43,
			expect:    false,
		},
		{
			name:      "Invalid API key - contains invalid characters",
			apiKey:    "PCa4uxUcKmbKNnTkQg-Os7_LkKsxgYRuTp1_83JhAl@",
			expectLen: 43,
			expect:    false,
		},
		{
			name:      "Invalid API key - base64 standard encoding",
			apiKey:    "PCa4uxUcKmbKNnTkQg/Os7+LkKsxgYRuTp1+83JhAlh=",
			expectLen: 43,
			expect:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Base64URL(test.apiKey, test.expectLen)
			if result != test.expect {
				t.Errorf("Expected %v, but got %v", test.expect, result)
			}
		})
	}
}

func TestIsIP(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{
			name:   "Valid IPv4",
			input:  "192.168.0.1",
			expect: true,
		},
		{
			name:   "Invalid IPv4 - missing octet",
			input:  "192.168.0",
			expect: false,
		},
		{
			name:   "Invalid IPv4 - invalid octet",
			input:  "192.168.0.256",
			expect: false,
		},
		{
			name:   "Invalid IPv4 - invalid format",
			input:  "192.168.0.1.2",
			expect: false,
		},
		{
			name:   "Invalid IPv4 - invalid characters",
			input:  "192.168.0.a",
			expect: false,
		},
		{
			name:   "Valid IPv6",
			input:  "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expect: true,
		},
		{
			name:   "Valid IPv6 - shortened format",
			input:  "2001:db8:85a3::8a2e:370:7334",
			expect: true,
		},
		{
			name:   "Invalid IPv6 - invalid hextet",
			input:  "2001:db8:85a3:gggg:0000:8a2e:0370:7334",
			expect: false,
		},
		{
			name:   "Invalid IPv6 - invalid format",
			input:  "2001:db8:85a3:::8a2e:0370:7334",
			expect: false,
		},
		{
			name:   "Invalid IPv6 - invalid characters",
			input:  "2001:db8:85a3::8a2e:0370:zzzz",
			expect: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsIP(test.input)
			if result != test.expect {
				t.Errorf("Expected %v, but got %v", test.expect, result)
			}
		})
	}
}

// Adapted from https://github.com/golang/go/blob/go1.21.6/src/net/dnsname_test.go
// Copyright 2009 The Go Authors
// License: BSD (https://github.com/golang/go/blob/go1.21.6/LICENSE)
func TestIsHostname(t *testing.T) {
	dnsNameTests := []struct {
		name   string
		result bool
	}{
		{"_xmpp-server._tcp.google.com", true},
		{"foo.com", true},
		{"1foo.com", true},
		{"26.0.0.73.com", true},
		{"10-0-0-1", true},
		{"fo-o.com", true},
		{"fo1o.com", true},
		{"foo1.com", true},
		{"a.b..com", false},
		{"a.b-.com", false},
		{"a.b.com-", false},
		{"a.b..", false},
		{"b.com.", true},
		{strings.Repeat("a", 63) + ".com", true},
		{strings.Repeat("a", 64) + ".com", false},
	}

	for _, tc := range dnsNameTests {
		if IsHostname(tc.name) != tc.result {
			t.Errorf("IsHostname(%q) = %v; want %v", tc.name, !tc.result, tc.result)
		}
	}
}
