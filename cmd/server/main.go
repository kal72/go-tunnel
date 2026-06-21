package main

import (
	"context"
	"gotunnel/internal/config"
	"gotunnel/internal/model"
	"gotunnel/internal/server"
	"gotunnel/internal/repository/memory"
	postgresrepo "gotunnel/internal/repository/postgres"
	redisrepo "gotunnel/internal/repository/redis"
	"gotunnel/internal/usecase"
	tunnelhandler "gotunnel/internal/handler/tunnel"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	env, err := config.LoadServerConfig(".env")
	if err != nil {
		log.Fatal("load .env:", err)
	}

	log.Printf("[config] Ports: public=%d tunnel=%d",
		env.GatewayPort, env.TunnelPort)
	log.Printf("[config] Domain: %v", env.GatewayHost)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := postgresrepo.InitDB(env)
	if err != nil {
		log.Fatal("init db:", err)
	}
	defer db.Close()

	userRepo := postgresrepo.NewUserRepository(db)
	
	// Redis Repositories
	tunnelStore := redisrepo.NewRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	tunnelStore.Ping(context.Background())

	var domainStore model.DomainStore
	if env.WildcardDomain != "" {
		domainStore = redisrepo.NewRedisStore(env.RedisAddr, env.RedisPass, env.DomainRedisDB)
		domainStore.Ping(context.Background())
	} else {
		log.Printf("[edge] Domain Management disabled (WILDCARD_DOMAIN is empty)")
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
		log.Fatal("init tunnel server:", err)
	}

	// Edge Server (Frameworks & Drivers)
	e, err := server.New(env, hostRegistry, domainStore, tunnelSrv)
	if err != nil {
		log.Fatal("init edge:", err)
	}

	if err := e.Run(ctx); err != nil {
		log.Fatal("edge error:", err)
	}
}
