package di

import (
	"context"
	"fmt"
	"log"

	domainConfig "gotunnel/internal/domain/config"
	domainTunnel "gotunnel/internal/domain/tunnel"
	"gotunnel/internal/gateway"
	redisrepo "gotunnel/internal/infrastructure/cache/redis"
	postgresrepo "gotunnel/internal/infrastructure/database/postgres"
)

func BuildProxyApp(env *domainConfig.ServerConfig) (*gateway.ProxyServer, func(), error) {
	// Initialize DB (for any config if needed, though mostly Redis for domain)
	db, err := postgresrepo.InitDB(env)
	if err != nil {
		return nil, nil, fmt.Errorf("init db: %w", err)
	}

	var domainStore domainTunnel.DomainStore
	if env.WildcardDomain != "" {
		domainStore = redisrepo.NewDomainRedisStore(env.RedisAddr, env.RedisPass, env.DomainRedisDB)
		domainStore.Ping(context.Background())
	}

	hostPolicy := func(ctx context.Context, host string) error {
		// Just a basic ACME host policy
		return nil
	}

	proxySrv, err := gateway.NewProxy(env, domainStore, hostPolicy)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("init proxy: %w", err)
	}

	cleanup := func() {
		log.Println("[di] Cleaning up Proxy resources...")
		db.Close()
	}

	return proxySrv, cleanup, nil
}
