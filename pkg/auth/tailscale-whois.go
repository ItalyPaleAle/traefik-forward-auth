package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cast"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"tailscale.com/client/local"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

const (
	tailscaleWhoisClaimIP      = "ip"
	tailscaleWhoisClaimTailnet = "tailnet"
)

// TailscaleWhois is a Provider for authenticating with Tailscale Whois, for requests that are coming over a Tailscale network.
type TailscaleWhois struct {
	requestTimeout time.Duration
	allowedTailnet string
	allowedUsers   []string

	httpClient *http.Client
}

// NewTailscaleWhoisOptions is the options for NewTailscaleWhois
type NewTailscaleWhoisOptions struct {
	// If non-empty, requires the Tailnet of the user to match this value
	AllowedTailnet string
	// If non-empty, allows these user accounts only
	AllowedUsers []string
	// Request timeout; defaults to 10s
	RequestTimeout time.Duration
}

// NewTailscaleWhois returns a new TailscaleWhois provider
func NewTailscaleWhois(opts NewTailscaleWhoisOptions) (*TailscaleWhois, error) {
	reqTimeout := opts.RequestTimeout
	if reqTimeout < time.Second {
		reqTimeout = 10 * time.Second
	}

	// Update the transport for the HTTP client to include tracing information
	httpClient := &http.Client{}
	httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)

	a := &TailscaleWhois{
		httpClient:     httpClient,
		requestTimeout: reqTimeout,
		allowedTailnet: opts.AllowedTailnet,
		allowedUsers:   opts.AllowedUsers,
	}
	return a, nil
}

func (a *TailscaleWhois) GetProviderName() string {
	return "tailscalewhois"
}

func (a *TailscaleWhois) SeamlessAuth(r *http.Request) (*user.Profile, error) {
	// This code is adapted from the Tailscale source code
	// Source: https://github.com/tailscale/tailscale/blob/169778e23bb8e315b1cdfcb54d9d59daace4a57d/cmd/nginx-auth/nginx-auth.go
	// Copyright: Tailscale Inc & AUTHORS
	// License: BSD-3-Clause

	// Ensure X-Forwarded-For is set and it's an IP
	sourceIP := net.ParseIP(r.Header.Get("X-Forwarded-For"))
	if sourceIP == nil {
		return nil, fmt.Errorf("value of X-Forwarded-For header '%s' is not valid: not an IP", r.Header.Get("X-Forwarded-For"))
	}

	// Use the Tailscale client to authenticate the user
	client := &local.Client{}
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
	profile := user.Profile{
		ID: strings.Split(info.UserProfile.LoginName, "@")[0],
		Email: &user.ProfileEmail{
			Value: info.UserProfile.LoginName,
		},
		Name: user.ProfileName{
			FullName: info.UserProfile.DisplayName,
		},
		Picture: info.UserProfile.ProfilePicURL,
		AdditionalClaims: map[string]string{
			tailscaleWhoisClaimTailnet: tailnet,
			tailscaleWhoisClaimIP:      sourceIP.String(),
		},
	}

	return &profile, nil
}

func (a *TailscaleWhois) UserAllowed(profile *user.Profile) error {
	// Check tailnet
	tailnet := profile.AdditionalClaims[tailscaleWhoisClaimTailnet]
	if a.allowedTailnet != "" && tailnet != a.allowedTailnet {
		if tailnet == "" {
			return fmt.Errorf("user profile does not contain a tailnet name (normally, this indicates that the user is connecting to a shared node), but wanted users in tailnet '%s' only", a.allowedTailnet)
		}
		return fmt.Errorf("user is part of tailnet '%s', wanted '%s'", tailnet, a.allowedTailnet)
	}

	// Check allowed users
	if len(a.allowedUsers) > 0 && !slices.Contains(a.allowedUsers, profile.ID) {
		return errors.New("user ID is not in the allowlist")
	}

	return nil
}

func (a *TailscaleWhois) ValidateRequestClaims(r *http.Request, profile *user.Profile) error {
	// We need to make sure that the IP of the request matches the value in the "ip" claim in the profile
	sourceIP := net.ParseIP(r.Header.Get("X-Forwarded-For"))
	if sourceIP == nil {
		return fmt.Errorf("value of X-Forwarded-For header '%s' is not valid: not an IP", r.Header.Get("X-Forwarded-For"))
	}

	var expectIP string
	if profile.AdditionalClaims != nil {
		expectIP = profile.AdditionalClaims[tailscaleWhoisClaimIP]
	}
	if expectIP != sourceIP.String() {
		return fmt.Errorf("token was issued for Tailscale IP '%s', but this request is from '%s'", expectIP, sourceIP.String())
	}

	return nil
}

func (a *TailscaleWhois) UserIDFromProfile(profile *user.Profile) string {
	return profile.ID
}

func (a *TailscaleWhois) PopulateAdditionalClaims(claims map[string]any, setClaimFn func(key, val string)) {
	if v := cast.ToString(claims[tailscaleWhoisClaimIP]); v != "" {
		setClaimFn(tailscaleWhoisClaimIP, v)
	}
	if v := cast.ToString(claims[tailscaleWhoisClaimTailnet]); v != "" {
		setClaimFn(tailscaleWhoisClaimTailnet, v)
	}
}

// Compile-time interface assertion
var _ SeamlessProvider = &TailscaleWhois{}
