//nolint:revive
package config

import (
	"context"
	"fmt"
	"os"

	"github.com/italypaleale/traefik-forward-auth/pkg/auth"
)

var testProviderConfigFactory map[string]func() ProviderConfig

type ProviderConfig interface {
	GetAuthProvider(ctx context.Context) (auth.Provider, error)
	SetConfigObject(c *Config)
	GetProviderMetadata() auth.ProviderMetadata
}

func populateSecretFromFile(secret *string, secretFile string) error {
	// Do nothing if the secret is already populated or if the file name is empty
	// If the secret is required, let downstream code handle that
	if *secret != "" || secretFile == "" {
		return nil
	}

	r, err := os.ReadFile(secretFile)
	if err != nil {
		return fmt.Errorf("failed to read secret file '%s': %w", secretFile, err)
	}

	if len(r) == 0 {
		return fmt.Errorf("secret file '%s' is empty", secretFile)
	}

	*secret = string(r)

	return nil
}
