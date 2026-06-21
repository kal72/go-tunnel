package di

import (
	"context"
	"fmt"
	"log"
	"strings"

	"gotunnel/internal/model"
	"gotunnel/internal/repository"
	"gotunnel/internal/repository/memory"
	postgresrepo "gotunnel/internal/repository/postgres"
	redisrepo "gotunnel/internal/repository/redis"
	tunnelhandler "gotunnel/internal/handler/tunnel"
	"gotunnel/internal/server"
	"gotunnel/internal/usecase"
)

// BuildServerApp initializes all dependencies and returns the TunnelGateway and a cleanup function.
func BuildServerApp(env *model.ServerConfig) (*server.TunnelGateway, func(), error) {
	db, err := postgresrepo.InitDB(env)
	if err != nil {
		return nil, nil, fmt.Errorf("init db: %w", err)
	}

	userRepo := postgresrepo.NewUserRepository(db)

	// Redis Repositories
	tunnelStore := redisrepo.NewTunnelRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	tunnelStore.Ping(context.Background())

	var domainStore repository.DomainStore
	if env.WildcardDomain != "" {
		domainStore = redisrepo.NewDomainRedisStore(env.RedisAddr, env.RedisPass, env.DomainRedisDB)
		domainStore.Ping(context.Background())
	} else {
		log.Printf("[gateway] Domain Management disabled (WILDCARD_DOMAIN is empty)")
	}

	// HostRegistry
	hostRegistry := memory.NewHostRegistry()
	for _, d := range []string{env.GatewayHost, env.TunnelHost, env.WebUIDomain} {
		if d = strings.TrimSpace(d); d != "" {
			hostRegistry.Authorize(d)
		}
	}
	if env.WildcardDomain != "" {
		hostRegistry.Authorize(env.WildcardDomain)
	}

	// Usecases
	tunnelUsecase := usecase.NewTunnelUsecase(tunnelStore, domainStore)
	authUsecase := usecase.NewAuthUsecase(userRepo, tunnelStore, env.JWTSecret)

	// Handlers
	tunnelSrv, err := tunnelhandler.NewServerJWT(env.JWTSecret, hostRegistry, env.GatewayHost, env.WildcardDomain, tunnelUsecase, authUsecase)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("init tunnel server: %w", err)
	}

	// Edge Server (Frameworks & Drivers)
	hostPolicy := func(ctx context.Context, host string) error {
		h := strings.ToLower(strings.TrimSpace(host))

		if env.WildcardDomain != "" && matchWildcard(h, env.WildcardDomain) {
			return fmt.Errorf("wildcard domains are managed externally: %s", h)
		}

		if h == strings.ToLower(env.GatewayHost) || h == strings.ToLower(env.TunnelHost) || h == strings.ToLower(env.WebUIDomain) {
			return nil
		}

		if domainStore != nil {
			allowed, err := domainStore.IsDomainAllowed(ctx, h)
			if err == nil && allowed {
				return nil
			}
		}

		if hostRegistry.IsActive(h) {
			return nil
		}

		return fmt.Errorf("unauthorized host: %s", h)
	}

	gatewaySrv, err := server.New(env, tunnelSrv, hostPolicy)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("init gateway: %w", err)
	}

	cleanup := func() {
		log.Println("[di] Cleaning up resources...")
		db.Close()
	}

	return gatewaySrv, cleanup, nil
}

func matchWildcard(host, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	base := strings.TrimPrefix(pattern, "*.")
	return strings.HasSuffix(host, "."+base) && !strings.Contains(strings.TrimSuffix(host, "."+base), ".")
}
