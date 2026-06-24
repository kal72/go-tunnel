package di

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"gotunnel/assets"
	api "gotunnel/internal/delivery/api/handler"
	"gotunnel/internal/delivery/web"
	webui "gotunnel/internal/delivery/web/handler"
	domainConfig "gotunnel/internal/domain/config"
	domainTunnel "gotunnel/internal/domain/tunnel"
	redisrepo "gotunnel/internal/infrastructure/cache/redis"
	postgresrepo "gotunnel/internal/infrastructure/database/postgres"
	usecaseConfig "gotunnel/internal/usecase/config"
	usecaseSetting "gotunnel/internal/usecase/setting"
	usecaseTunnel "gotunnel/internal/usecase/tunnel"
	usecaseUser "gotunnel/internal/usecase/user"
)

func BuildWebUIApp(env *domainConfig.ServerConfig) (*chi.Mux, func(), error) {
	// Redis Repositories
	tunnelStore := redisrepo.NewTunnelRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	tunnelStore.Ping(context.Background())

	// Postgres DB
	db, err := postgresrepo.InitDB(env)
	if err != nil {
		return nil, nil, fmt.Errorf("init db: %w", err)
	}

	var domainStore domainTunnel.DomainStore
	if env.WildcardDomain != "" {
		domainStore = postgresrepo.NewDomainRepository(db)
	}

	tunnelAddr := env.TunnelDomain
	if env.ProxyHttpsPort != 0 && env.ProxyHttpsPort != 443 {
		tunnelAddr = fmt.Sprintf("%s:%d", env.TunnelDomain, env.ProxyHttpsPort)
	}

	userRepo := postgresrepo.NewUserRepository(db)
	configRepo := postgresrepo.NewConfigRepository(db)
	settingRepo := postgresrepo.NewSettingRepository(db)

	// Usecases
	tunnelUsecase := usecaseTunnel.NewTunnelUsecase(tunnelStore, domainStore)
	configUsecase := usecaseConfig.NewConfigUsecase(configRepo)
	settingUsecase := usecaseSetting.NewSettingUsecase(settingRepo)
	authUsecase := usecaseUser.NewAuthUsecase(userRepo, tunnelStore, env.JWTSecret, env.JWTExpireHours)

	// Handlers
	h := webui.New(assets.EmbeddedFS, tunnelUsecase, configUsecase, settingUsecase, env.JWTSecret, tunnelAddr, env.WildcardDomain, env.GatewayDomain, env.ACMEEnable, env.MaxFreeDomains, env.CLILatestVersion)
	authH := webui.NewAuth(assets.EmbeddedFS, authUsecase)
	userH := webui.NewUserHandler(assets.EmbeddedFS, authUsecase)
	cliH := api.NewCLIHandler(configUsecase, tunnelAddr, env.ACMEEnable, env.CLILatestVersion)

	// Router
	router := web.SetupRouter(h, authH, userH, cliH, http.FS(assets.EmbeddedFS))

	cleanup := func() {
		log.Println("[di] Cleaning up WebUI resources...")
		db.Close()
	}

	return router, cleanup, nil
}
