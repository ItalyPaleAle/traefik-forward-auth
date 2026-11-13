package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

type mockTailscaleWhoIsClient struct {
	whoIsFn func(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

func (m *mockTailscaleWhoIsClient) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return m.whoIsFn(ctx, remoteAddr)
}

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

func TestTailscaleWhoisSeamlessAuth(t *testing.T) {
	const sourceIP = "100.64.0.1"

	provider, err := NewTailscaleWhois(NewTailscaleWhoisOptions{
		AllowedTailnet: "mytailnet.ts.net",
		tsClient: &mockTailscaleWhoIsClient{
			whoIsFn: func(_ context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
				if remoteAddr != sourceIP {
					return nil, fmt.Errorf("unexpected remote addr: %s", remoteAddr)
				}

				return &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						Name:         "device-1.mytailnet.ts.net.",
						ComputedName: "device-1",
						Hostinfo:     (&tailcfg.Hostinfo{}).View(),
					},
					UserProfile: &tailcfg.UserProfile{
						DisplayName:   "Alice Example",
						LoginName:     "alice@example.com",
						ProfilePicURL: "https://example.com/alice.png",
					},
				}, nil
			},
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set(headerXForwardedFor, sourceIP)

	profile, err := provider.SeamlessAuth(req)
	require.NoError(t, err)
	require.NotNil(t, profile.Email)
	assert.Equal(t, "alice", profile.ID)
	assert.Equal(t, "Alice Example", profile.Name.FullName)
	assert.Equal(t, "alice@example.com", profile.Email.Value)
	assert.Equal(t, "https://example.com/alice.png", profile.Picture)
	assert.Equal(t, "device-1.mytailnet.ts.net", profile.AdditionalClaims[tailscaleWhoisClaimHostname])
	assert.Equal(t, "mytailnet.ts.net", profile.AdditionalClaims[tailscaleWhoisClaimTailnet])
	assert.Equal(t, sourceIP, profile.AdditionalClaims[tailscaleWhoisClaimIP])
	assert.Equal(t, false, profile.AdditionalClaims[tailscaleWhoisClaimTaggedDevice])
}

func TestTailscaleWhoisValidateRequestClaims(t *testing.T) {
	provider, err := NewTailscaleWhois(NewTailscaleWhoisOptions{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set(headerXForwardedFor, "100.64.0.1")

	profile := &user.Profile{
		AdditionalClaims: map[string]any{tailscaleWhoisClaimIP: "100.64.0.1"},
	}
	require.NoError(t, provider.ValidateRequestClaims(req, profile))

	profile.AdditionalClaims[tailscaleWhoisClaimIP] = "100.64.0.2"
	err = provider.ValidateRequestClaims(req, profile)
	require.Error(t, err)
	require.ErrorContains(t, err, "token was issued for Tailscale IP")
}

// TestTailscaleWhoisSeamlessAuthRequiresSingleIP verifies that sign-in only works when X-Forwarded-For contains exactly one IP
// With other proxies in front of Traefik, the last entry would be a proxy and a WhoIs on it would sign every visitor in as that proxy's node
func TestTailscaleWhoisSeamlessAuthRequiresSingleIP(t *testing.T) {
	const clientIP = "100.64.0.1"

	whoIsCalls := 0
	provider, err := NewTailscaleWhois(NewTailscaleWhoisOptions{
		AllowedTailnet: "mytailnet.ts.net",
		tsClient: &mockTailscaleWhoIsClient{
			whoIsFn: func(_ context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
				whoIsCalls++
				if remoteAddr != clientIP {
					return nil, fmt.Errorf("unexpected remote addr: %s", remoteAddr)
				}
				return &apitype.WhoIsResponse{
					Node: &tailcfg.Node{
						Name:         "device-1.mytailnet.ts.net.",
						ComputedName: "device-1",
						Hostinfo:     (&tailcfg.Hostinfo{}).View(),
					},
					UserProfile: &tailcfg.UserProfile{
						DisplayName: "Alice Example",
						LoginName:   "alice@example.com",
					},
				}, nil
			},
		},
	})
	require.NoError(t, err)

	t.Run("single IP", func(t *testing.T) {
		for _, xff := range []string{clientIP, " " + clientIP + " "} {
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			req.Header.Set(headerXForwardedFor, xff)

			profile, authErr := provider.SeamlessAuth(req)
			require.NoError(t, authErr)
			assert.Equal(t, "alice", profile.ID)
			assert.Equal(t, clientIP, profile.AdditionalClaims[tailscaleWhoisClaimIP])
		}
	})

	rejected := []struct {
		name   string
		values []string
	}{
		{"client IP first", []string{clientIP + ", 10.0.0.5"}},
		{"client IP last", []string{"10.0.0.5, " + clientIP}},
		{"three hops", []string{clientIP + " , 10.0.0.5 , 192.168.1.1"}},
		{"no space after comma", []string{clientIP + ",10.0.0.5"}},
		{"repeated header", []string{clientIP, "10.0.0.5"}},
		{"missing header", nil},
	}
	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			for _, v := range tt.values {
				req.Header.Add(headerXForwardedFor, v)
			}

			before := whoIsCalls
			_, authErr := provider.SeamlessAuth(req)
			require.Error(t, authErr)
			assert.Equal(t, before, whoIsCalls, "WhoIs must not be called")
		})
	}
}

// TestTailscaleWhoisValidateRequestClaimsRequiresSingleIP verifies that an existing session is only valid for requests whose X-Forwarded-For contains exactly one IP, matching the one in the session
func TestTailscaleWhoisValidateRequestClaimsRequiresSingleIP(t *testing.T) {
	provider, err := NewTailscaleWhois(NewTailscaleWhoisOptions{})
	require.NoError(t, err)

	profile := &user.Profile{
		AdditionalClaims: map[string]any{tailscaleWhoisClaimIP: "100.64.0.1"},
	}

	tests := []struct {
		name    string
		values  []string
		wantErr bool
	}{
		{"matching IP", []string{"100.64.0.1"}, false},
		{"matching IP with whitespace", []string{" 100.64.0.1 "}, false},
		{"different IP", []string{"100.64.0.99"}, true},
		{"chain starting with the matching IP", []string{"100.64.0.1, 10.0.0.5"}, true},
		{"chain ending with the matching IP", []string{"10.0.0.5, 100.64.0.1"}, true},
		{"repeated header", []string{"100.64.0.1", "100.64.0.1"}, true},
		{"not an IP", []string{"not-an-ip"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			for _, v := range tt.values {
				req.Header.Add(headerXForwardedFor, v)
			}

			validateErr := provider.ValidateRequestClaims(req, profile)
			if tt.wantErr {
				require.Error(t, validateErr)
			} else {
				require.NoError(t, validateErr)
			}
		})
	}
}
