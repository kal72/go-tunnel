package di

import (
	"context"
	"fmt"
	"log"

	domainConfig "gotunnel/internal/domain/config"
	domainTunnel "gotunnel/internal/domain/tunnel"
	"gotunnel/internal/gateway"
	postgresrepo "gotunnel/internal/infrastructure/database/postgres"
)

func BuildProxyApp(env *domainConfig.ServerConfig) (*gateway.ProxyServer, func(), error) {
	// Postgres DB for Domain verification
	db, err := postgresrepo.InitDB(env)
	if err != nil {
		return nil, nil, fmt.Errorf("init db: %w", err)
	}

	var domainStore domainTunnel.DomainStore = postgresrepo.NewDomainRepository(db)

	hostPolicy := func(ctx context.Context, host string) error {
		// Just a basic ACME host policy
		return nil
	}

	proxySrv, err := gateway.NewProxy(env, domainStore, hostPolicy)
	if err != nil {
		return nil, nil, fmt.Errorf("init proxy: %w", err)
	}

	cleanup := func() {
		log.Println("[di] Cleaning up Proxy resources...")
		_ = db.Close()
	}

	return proxySrv, cleanup, nil
}
