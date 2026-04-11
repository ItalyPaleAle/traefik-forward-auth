package server

import (
	"fmt"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
	"github.com/italypaleale/traefik-forward-auth/pkg/config"
	"github.com/italypaleale/traefik-forward-auth/pkg/user"
)

type headerContext struct {
	Portal   headerContextPortal
	Provider headerContextProvider
	profile  *user.Profile
}

func (c headerContext) Claim(claim string) any {
	return c.profile.Get(claim)
}

type headerContextPortal struct {
	Name        string
	DisplayName string
}

type headerContextProvider struct {
	Name        string
	DisplayName string
}

func getHeaders(portal Portal, provider auth.Provider, profile *user.Profile) (map[string]string, error) {
	cfg := config.Get()
	headers := map[string]string{}
	context := headerContext{
		Portal: headerContextPortal{
			Name:        portal.Name,
			DisplayName: portal.DisplayName,
		},
		Provider: headerContextProvider{
			Name:        provider.GetProviderName(),
			DisplayName: provider.GetProviderDisplayName(),
		},
		profile: profile,
	}

	for _, header := range cfg.Headers {
		value, err := header.Evaluate(context)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate header %q: %w", header.Name, err)
		}
		headers[header.Name] = value
	}

	return headers, nil
}
