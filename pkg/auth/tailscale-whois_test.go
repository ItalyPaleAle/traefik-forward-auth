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

// TestTailscaleWhoisSeamlessAuthMultiHopXFF verifies that a comma-separated X-Forwarded-For chain (which is what arrives in real multi-proxy deployments) is parsed correctly
// MiddlewareProxyHeaders already accepts these values, so the Tailscale provider must too
func TestTailscaleWhoisSeamlessAuthMultiHopXFF(t *testing.T) {
	const clientIP = "100.64.0.1"

	provider, err := NewTailscaleWhois(NewTailscaleWhoisOptions{
		AllowedTailnet: "mytailnet.ts.net",
		tsClient: &mockTailscaleWhoIsClient{
			whoIsFn: func(_ context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
				if remoteAddr != clientIP {
					return nil, fmt.Errorf("unexpected remote addr: %s — leftmost IP from XFF chain was not extracted", remoteAddr)
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

	tests := []struct {
		name string
		xff  string
	}{
		{"single hop", clientIP},
		{"two hops", clientIP + ", 10.0.0.5"},
		{"three hops with extra spaces", clientIP + " , 10.0.0.5 , 192.168.1.1"},
		{"two hops no space after comma", clientIP + ",10.0.0.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			req.Header.Set(headerXForwardedFor, tt.xff)

			profile, authErr := provider.SeamlessAuth(req)
			require.NoError(t, authErr)
			assert.Equal(t, "alice", profile.ID)
			assert.Equal(t, clientIP, profile.AdditionalClaims[tailscaleWhoisClaimIP])
		})
	}
}

// TestTailscaleWhoisValidateRequestClaimsMultiHopXFF verifies that when an existing session is validated against a request whose X-Forwarded-For carries a comma-separated chain, the leftmost IP is compared against the claim
// Without this, sessions break the moment a new proxy hop appears upstream of Traefik
func TestTailscaleWhoisValidateRequestClaimsMultiHopXFF(t *testing.T) {
	provider, err := NewTailscaleWhois(NewTailscaleWhoisOptions{})
	require.NoError(t, err)

	profile := &user.Profile{
		AdditionalClaims: map[string]any{tailscaleWhoisClaimIP: "100.64.0.1"},
	}

	tests := []struct {
		name    string
		xff     string
		wantErr bool
	}{
		{"matching single hop", "100.64.0.1", false},
		{"matching two hops", "100.64.0.1, 10.0.0.5", false},
		{"matching three hops with whitespace", "100.64.0.1 , 10.0.0.5 , 192.168.1.1", false},
		{"non-matching leftmost IP", "100.64.0.99, 10.0.0.5", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			req.Header.Set(headerXForwardedFor, tt.xff)

			validateErr := provider.ValidateRequestClaims(req, profile)
			if tt.wantErr {
				require.Error(t, validateErr)
			} else {
				require.NoError(t, validateErr)
			}
		})
	}
}
