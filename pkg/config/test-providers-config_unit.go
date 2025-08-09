//go:build unit

// This file is only built when the "unit" tag is set
// Note: this file must sort after "providers-config.go"

package config

import (
	"context"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

func init() {
	providerConfigFactory["testoauth2"] = func() ProviderConfig { return &ProviderConfig_TestOAuth2{} }
	providerConfigFactory["testseamless"] = func() ProviderConfig { return &ProviderConfig_TestSeamless{} }
}

type ProviderConfig_TestOAuth2 struct{}

func (p *ProviderConfig_TestOAuth2) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewTestProviderOAuth2(), nil
}

func (p *ProviderConfig_TestOAuth2) SetConfigObject(_ *Config) {
	// Nop
}

type ProviderConfig_TestSeamless struct{}

func (p *ProviderConfig_TestSeamless) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewTestProviderSeamless(), nil
}

func (p *ProviderConfig_TestSeamless) SetConfigObject(_ *Config) {
	// Nop
}
