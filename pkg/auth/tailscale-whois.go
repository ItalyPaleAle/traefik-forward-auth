package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	tailscale "tailscale.com/client/local"
	"tailscale.com/tailcfg"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

const (
	tailscaleWhoisClaimIP      = "ip"
	tailscaleWhoisClaimTailnet = "tailnet"
	headerXForwardedFor        = "X-Forwarded-For"
)

// TailscaleWhois is a Provider for authenticating with Tailscale Whois, for requests that are coming over a Tailscale network.
type TailscaleWhois struct {
	baseProvider

	requestTimeout  time.Duration
	allowedTailnet  string
	capabilityNames []string

	httpClient *http.Client
}

// NewTailscaleWhoisOptions is the options for NewTailscaleWhois
type NewTailscaleWhoisOptions struct {
	// If non-empty, requires the Tailnet of the user to match this value
	AllowedTailnet string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
	// Names of capabilities to read from Tailscale peer capabilities
	CapabilityNames []string
}

// NewTailscaleWhois returns a new TailscaleWhois provider
func NewTailscaleWhois(opts NewTailscaleWhoisOptions) (*TailscaleWhois, error) {
	reqTimeout := opts.RequestTimeout
	if reqTimeout < time.Second {
		reqTimeout = 10 * time.Second
	}

	// Update the transport for the HTTP client to include tracing information
	httpClient := &http.Client{}
	httpClient.Transport = otelhttp.NewTransport(http.DefaultTransport.(*http.Transport).Clone()) //nolint:forcetypeassert

	a := &TailscaleWhois{
		baseProvider: baseProvider{
			metadata: ProviderMetadata{
				DisplayName: "Tailscale Whois",
				Name:        "tailscalewhois",
				Icon:        "tailscale",
				Color:       "slate",
			},
		},
		httpClient:      httpClient,
		requestTimeout:  reqTimeout,
		allowedTailnet:  opts.AllowedTailnet,
		capabilityNames: opts.CapabilityNames,
	}
	return a, nil
}

func (a *TailscaleWhois) GetProviderType() string {
	return "tailscalewhois"
}

func (a *TailscaleWhois) SeamlessAuth(r *http.Request) (*user.Profile, error) {
	// This code is adapted from the Tailscale source code
	// Source: https://github.com/tailscale/tailscale/blob/169778e23bb8e315b1cdfcb54d9d59daace4a57d/cmd/nginx-auth/nginx-auth.go
	// Copyright: Tailscale Inc & AUTHORS
	// License: BSD-3-Clause

	// Ensure X-Forwarded-For is set and it's an IP
	sourceIP := net.ParseIP(r.Header.Get(headerXForwardedFor))
	if sourceIP == nil {
		return nil, fmt.Errorf("value of X-Forwarded-For header '%s' is not valid: not an IP", r.Header.Get(headerXForwardedFor))
	}

	// Use the Tailscale client to authenticate the user
	client := &tailscale.Client{}
	reqCtx, cancel := context.WithTimeout(r.Context(), a.requestTimeout)
	defer cancel()
	info, err := client.WhoIs(reqCtx, sourceIP.String())
	if err != nil {
		return nil, fmt.Errorf("failed to perform WhoIs using Tailscale: %w", err)
	}

	// The nginx-auth code disallows access to tagged devices
	// https://github.com/tailscale/tailscale/blob/169778e23bb8e315b1cdfcb54d9d59daace4a57d/cmd/nginx-auth/nginx-auth.go#L59-L63
	if info.Node.IsTagged() {
		return nil, fmt.Errorf("node '%s' is tagged", info.Node.Hostinfo.Hostname())
	}

	// Tailnet of connected node
	// When accessing shared nodes, this will be empty because the Tailnet of the sharee is not exposed
	var tailnet string
	if !info.Node.Hostinfo.ShareeNode() {
		var ok bool
		_, tailnet, ok = strings.Cut(info.Node.Name, info.Node.ComputedName+".")
		if !ok {
			return nil, fmt.Errorf("failed to extract Tailnet name from hostname '%s'", info.Node.Name)
		}
		tailnet = strings.TrimSuffix(tailnet, ".beta.tailscale.net")
		tailnet = strings.TrimSuffix(tailnet, ".")
	}

	if a.allowedTailnet != "" && tailnet != a.allowedTailnet {
		return nil, fmt.Errorf("user is part of tailnet '%s', wanted '%s'", tailnet, a.allowedTailnet)
	}

	// Create the user profile object
	profile := &user.Profile{
		Provider: a.GetProviderName(),
		ID:       strings.Split(info.UserProfile.LoginName, "@")[0],
		Email: &user.ProfileEmail{
			Value: info.UserProfile.LoginName,
		},
		Name: user.ProfileName{
			FullName: info.UserProfile.DisplayName,
		},
		Picture: info.UserProfile.ProfilePicURL,
		AdditionalClaims: map[string]any{
			tailscaleWhoisClaimTailnet: tailnet,
			tailscaleWhoisClaimIP:      sourceIP.String(),
		},
	}

	// Add peer capabilities to additional claims if configured
	if len(a.capabilityNames) > 0 && info.CapMap != nil {
		for _, capName := range a.capabilityNames {
			// Look for the capability in the CapMap
			capValues, ok := info.CapMap[tailcfg.PeerCapability(capName)]
			if ok && len(capValues) > 0 {
				// Add with https:// prefix as the key
				profile.AdditionalClaims["https://"+capName] = capValues
			}
		}
	}

	return profile, nil
}

func (a *TailscaleWhois) ValidateRequestClaims(r *http.Request, profile *user.Profile) error {
	// We need to make sure that the IP of the request matches the value in the "ip" claim in the profile
	sourceIP := net.ParseIP(r.Header.Get(headerXForwardedFor))
	if sourceIP == nil {
		return fmt.Errorf("value of X-Forwarded-For header '%s' is not valid: not an IP", r.Header.Get(headerXForwardedFor))
	}

	var expectIP string
	if profile.AdditionalClaims != nil {
		expectIP, _ = profile.AdditionalClaims[tailscaleWhoisClaimIP].(string)
	}
	if expectIP != sourceIP.String() {
		return fmt.Errorf("token was issued for Tailscale IP '%s', but this request is from '%s'", expectIP, sourceIP.String())
	}

	return nil
}

func (a *TailscaleWhois) PopulateAdditionalClaims(token jwt.Token, setClaimFn func(key string, val any)) {
	var val string

	if token.Get(tailscaleWhoisClaimIP, &val) == nil && val != "" {
		setClaimFn(tailscaleWhoisClaimIP, val)
	}
	if token.Get(tailscaleWhoisClaimTailnet, &val) == nil && val != "" {
		setClaimFn(tailscaleWhoisClaimTailnet, val)
	}

	// Also populate capability claims if present
	// Capability claims have keys with https:// prefix
	if len(a.capabilityNames) > 0 {
		for _, capName := range a.capabilityNames {
			claimKey := "https://" + capName
			var capValues any
			if token.Get(claimKey, &capValues) == nil {
				setClaimFn(claimKey, capValues)
			}
		}
	}
}

// Compile-time interface assertion
var _ SeamlessProvider = &TailscaleWhois{}
