package edge

import (
	"context"
	"fmt"
	"gotunnel/internal/tunnel/config"
	"gotunnel/internal/tunnel/registry"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func NewAutocertManager(env *config.ServerConfig, hostRegistry *registry.HostRegistry) *autocert.Manager {
	acmeClient := &acme.Client{
		DirectoryURL: acmeDirectoryURL(env.ACMEEnv),
	}

	return &autocert.Manager{
		Cache:  autocert.DirCache(env.ACMECache),
		Prompt: autocert.AcceptTOS,
		Client: acmeClient,
		HostPolicy: func(_ context.Context, host string) error {
			// 1. Authorized in allowlist
			if hostRegistry.IsAuthorized(host) {
				return nil
			}
			// 2. Currently active tunnel
			if hostRegistry.IsActive(host) {
				return nil
			}
			return fmt.Errorf("unauthorized host: %s", host)
		},
	}
}

func acmeDirectoryURL(env string) string {
	if strings.ToLower(strings.TrimSpace(env)) == "production" {
		return acme.LetsEncryptURL
	}
	return "https://acme-staging-v02.api.letsencrypt.org/directory"
}
