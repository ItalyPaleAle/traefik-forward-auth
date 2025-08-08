package auth

import (
	"net/http"

	"github.com/italypaleale/traefik-forward-auth/pkg/user"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type baseProvider struct {
	metadata ProviderMetadata
}

func (b *baseProvider) SetProviderMetadata(m ProviderMetadata) {
	if m.Name != "" {
		b.metadata.Name = m.Name
	}
	if m.DisplayName != "" {
		b.metadata.DisplayName = m.DisplayName
	}
	if m.Icon != "" {
		b.metadata.Icon = m.Icon
	}
	if m.Color != "" {
		b.metadata.Color = m.Color
	}
}

func (b *baseProvider) GetProviderName() string {
	return b.metadata.Name
}

func (b *baseProvider) GetProviderDisplayName() string {
	return b.metadata.DisplayName
}

func (b *baseProvider) GetProviderIcon() string {
	return b.metadata.Icon
}

func (b *baseProvider) GetProviderColor() string {
	return b.metadata.Color
}

func (p *baseProvider) ValidateRequestClaims(r *http.Request, profile *user.Profile) error {
	// Do not perform anything in the base provider
	return nil
}

func (p *baseProvider) PopulateAdditionalClaims(token jwt.Token, setClaimFn func(key string, val any)) {
	// Nop in the base provider
}
