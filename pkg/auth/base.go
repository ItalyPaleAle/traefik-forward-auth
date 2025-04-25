package auth

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
