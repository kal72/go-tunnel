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
			// 1. Check direct authorization (e.g. GatewayHost)
			if hostRegistry.IsAuthorized(host) {
				// If it matched via wildcard pattern in registry, we STILL need to check Redis
				// unless it's an exact match for Gateway/Tunnel host.
				if !isPattern(host) && !hostRegistry.IsActive(host) {
					// Check if it's a subdomain of our wildcard
					if wildcardDomain != "" && matchWildcard(host, wildcardDomain) {
						if domainStore != nil {
							allowed, err := domainStore.IsDomainAllowed(ctx, host)
							if err != nil || !allowed {
								return fmt.Errorf("subdomain not in allowed list: %s", host)
							}
						}
					}
				}
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
