//go:build unit

// This file is only built when the "unit" tag is set
// Note: this file must sort after "providers-config.go"

package config

import (
	"context"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

func init() {
	testProviderConfigFactory = map[string]func() ProviderConfig{
		"testoauth2":   func() ProviderConfig { return &ProviderConfig_TestOAuth2{} },
		"testseamless": func() ProviderConfig { return &ProviderConfig_TestSeamless{} },
	}
}

type testProviderConfigBase struct {
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayName"`
	Icon        string `yaml:"icon"`
	Color       string `yaml:"color"`
}

func (p *testProviderConfigBase) GetProviderMetadata() auth.ProviderMetadata {
	return auth.ProviderMetadata{
		Name:        p.Name,
		DisplayName: p.DisplayName,
		Icon:        p.Icon,
		Color:       p.Color,
	}
}

type ProviderConfig_TestOAuth2 struct {
	testProviderConfigBase
}

func (p *ProviderConfig_TestOAuth2) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewTestProviderOAuth2(), nil
}

func (p *ProviderConfig_TestOAuth2) SetConfigObject(_ *Config) {
	// Nop
}

type ProviderConfig_TestSeamless struct {
	testProviderConfigBase
}

func (p *ProviderConfig_TestSeamless) GetAuthProvider(_ context.Context) (auth.Provider, error) {
	return auth.NewTestProviderSeamless(), nil
}

func (p *ProviderConfig_TestSeamless) SetConfigObject(_ *Config) {
	// Nop
}
