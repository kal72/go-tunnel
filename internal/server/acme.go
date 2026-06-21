package server

import (
	"context"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// HostPolicyFunc is a function that determines whether a host is allowed
// for ACME certificate issuance. It is injected from the DI layer (cmd/server/main.go).
type HostPolicyFunc func(ctx context.Context, host string) error

// NewAutocertManager creates an autocert.Manager with the given host policy.
func NewAutocertManager(acmeCache string, acmeEnv string, hostPolicy HostPolicyFunc) *autocert.Manager {
	acmeClient := &acme.Client{
		DirectoryURL: acmeDirectoryURL(acmeEnv),
	}

	return &autocert.Manager{
		Cache:      autocert.DirCache(acmeCache),
		Prompt:     autocert.AcceptTOS,
		Client:     acmeClient,
		HostPolicy: autocert.HostPolicy(hostPolicy),
	}
}

func acmeDirectoryURL(env string) string {
	if strings.ToLower(strings.TrimSpace(env)) == "production" {
		return acme.LetsEncryptURL
	}
	return "https://acme-staging-v02.api.letsencrypt.org/directory"
}


func matchWildcard(host, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	base := strings.TrimPrefix(pattern, "*.")
	return strings.HasSuffix(host, "."+base) && !strings.Contains(strings.TrimSuffix(host, "."+base), ".")
}
