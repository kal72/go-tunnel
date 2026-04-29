package edge

import (
	"context"
	"fmt"
	"gotunnel/internal/tunnel/config"
	"gotunnel/internal/tunnel/registry"
	"gotunnel/internal/tunnel/state"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func NewAutocertManager(env *config.ServerConfig, hostRegistry *registry.HostRegistry, domainStore state.Store, wildcardDomain string) *autocert.Manager {
	acmeClient := &acme.Client{
		DirectoryURL: acmeDirectoryURL(env.ACMEEnv),
	}

	return &autocert.Manager{
		Cache:  autocert.DirCache(env.ACMECache),
		Prompt: autocert.AcceptTOS,
		Client: acmeClient,
		HostPolicy: func(ctx context.Context, host string) error {
			h := strings.ToLower(strings.TrimSpace(host))
			
			// 1. System domains (Gateway & Tunnel)
			if h == strings.ToLower(env.GatewayHost) || h == strings.ToLower(env.TunnelHost) {
				return nil
			}

			// 2. Redis allowlist
			if domainStore != nil {
				allowed, err := domainStore.IsDomainAllowed(ctx, h)
				if err == nil && allowed {
					return nil
				}
			}

			// 3. Currently active tunnel
			if hostRegistry.IsActive(h) {
				return nil
			}

			return fmt.Errorf("unauthorized host: %s", h)
		},
	}
}

func acmeDirectoryURL(env string) string {
	if strings.ToLower(strings.TrimSpace(env)) == "production" {
		return acme.LetsEncryptURL
	}
	return "https://acme-staging-v02.api.letsencrypt.org/directory"
}
func isPattern(host string) bool {
	return strings.Contains(host, "*")
}

func matchWildcard(host, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	base := strings.TrimPrefix(pattern, "*.")
	return strings.HasSuffix(host, "."+base) && !strings.Contains(strings.TrimSuffix(host, "."+base), ".")
}
