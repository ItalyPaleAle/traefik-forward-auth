package server

import (
	"context"
	"fmt"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

func GetPortalsConfig(ctx context.Context, conf *config.Config) (map[string]Portal, error) {
	portals := make(map[string]Portal, len(conf.Portals))
	for _, p := range conf.Portals {
		providers, err := p.GetAuthProviders(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth providers for portal '%s': %w", p.Name, err)
		}

		portal := Portal{
			Name:                  p.Name,
			DisplayName:           p.DisplayName,
			Providers:             make(map[string]auth.Provider, len(providers)),
			ProvidersList:         make([]string, len(providers)),
			AuthenticationTimeout: p.AuthenticationTimeout,
			AlwaysShowSigninPage:  p.AlwaysShowProvidersPage,
		}
		for i, p := range providers {
			name := p.GetProviderName()
			portal.Providers[name] = p
			portal.ProvidersList[i] = name
		}

		portals[p.Name] = portal
	}

	return portals, nil
}
