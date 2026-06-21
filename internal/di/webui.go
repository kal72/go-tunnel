package di

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"gotunnel/assets"
	"gotunnel/internal/model"
	"gotunnel/internal/repository"
	postgresrepo "gotunnel/internal/repository/postgres"
	redisrepo "gotunnel/internal/repository/redis"
	"gotunnel/internal/usecase"
	"gotunnel/internal/handler/api"
	"gotunnel/internal/handler/webui"
)

func BuildWebUIApp(env *model.ServerConfig) (*chi.Mux, func(), error) {
	// Redis Repositories
	tunnelStore := redisrepo.NewTunnelRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	tunnelStore.Ping(context.Background())

	var domainStore repository.DomainStore
	if env.WildcardDomain != "" {
		domainStore = redisrepo.NewDomainRedisStore(env.RedisAddr, env.RedisPass, env.DomainRedisDB)
		domainStore.Ping(context.Background())
	}

	tunnelAddr := env.TunnelHost
	if env.TunnelPort != 0 && env.TunnelPort != 443 {
		tunnelAddr = fmt.Sprintf("%s:%d", env.TunnelHost, env.TunnelPort)
	}

	// Postgres DB
	db, err := postgresrepo.InitDB(env)
	if err != nil {
		return nil, nil, fmt.Errorf("init db: %w", err)
	}

	userRepo := postgresrepo.NewUserRepository(db)
	configRepo := postgresrepo.NewConfigRepository(db)

	// Usecases
	tunnelUsecase := usecase.NewTunnelUsecase(tunnelStore, domainStore)
	configUsecase := usecase.NewConfigUsecase(configRepo)
	authUsecase := usecase.NewAuthUsecase(userRepo, tunnelStore, env.JWTSecret)

	// Handlers
	h := webui.New(assets.EmbeddedFS, tunnelUsecase, configUsecase, env.JWTSecret, tunnelAddr, env.WildcardDomain, env.GatewayHost, env.ACMEEnable)
	authH := webui.NewAuth(assets.EmbeddedFS, authUsecase)
	userH := webui.NewUserHandler(assets.EmbeddedFS, authUsecase)
	cliH := api.NewCLIHandler(configUsecase, tunnelAddr, env.ACMEEnable)

	// Router
	router := webui.SetupRouter(h, authH, userH, cliH, http.FS(assets.EmbeddedFS))

	cleanup := func() {
		log.Println("[di] Cleaning up WebUI resources...")
		db.Close()
	}

	return router, cleanup, nil
}
