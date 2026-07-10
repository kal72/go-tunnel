package di

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"gotunnel/assets"
	"gotunnel/internal/config"
	"gotunnel/internal/delivery/web"
	webui "gotunnel/internal/delivery/web/handler"
	domainTunnel "gotunnel/internal/domain/tunnel"
	redisrepo "gotunnel/internal/infrastructure/cache/redis"
	postgresrepo "gotunnel/internal/infrastructure/database/postgres"
	"gotunnel/internal/shared/stats"
	usecaseConfig "gotunnel/internal/usecase/config"
	usecaseSetting "gotunnel/internal/usecase/setting"
	usecaseTunnel "gotunnel/internal/usecase/tunnel"
	usecaseUser "gotunnel/internal/usecase/user"
)

func BuildWebUIApp(env *config.ServerConfig) (*chi.Mux, func(), error) {
	// Redis Repositories
	tunnelStore := redisrepo.NewTunnelRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	tunnelStore.Ping(context.Background())

	// Postgres DB
	db, err := postgresrepo.InitDB(env)
	if err != nil {
		return nil, nil, fmt.Errorf("init db: %w", err)
	}

	var domainStore domainTunnel.DomainStore = postgresrepo.NewDomainRepository(db)

	tunnelAddr := env.TunnelDomain
	if env.ProxyHttpsPort != 0 && env.ProxyHttpsPort != 443 {
		tunnelAddr = fmt.Sprintf("%s:%d", env.TunnelDomain, env.ProxyHttpsPort)
	}

	userRepo := postgresrepo.NewUserRepository(db)
	configRepo := postgresrepo.NewConfigRepository(db)
	settingRepo := postgresrepo.NewSettingRepository(db)
	apiKeyRepo := postgresrepo.NewAPIKeyRepository(db)

	// Usecases
	tunnelUsecase := usecaseTunnel.NewTunnelUsecase(tunnelStore, domainStore)
	configUsecase := usecaseConfig.NewConfigUsecase(configRepo)
	settingUsecase := usecaseSetting.NewSettingUsecase(settingRepo)
	authUsecase := usecaseUser.NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, env.JWTSecret, env.WebJWTExpireHours, env.CliJWTExpireHours)

	// Stats Collector (5s refresh)
	statsCollector := stats.NewStatsCollector(5 * time.Second)
	statsCollector.Start(context.Background())

	// Handlers
	h := webui.New(assets.EmbeddedFS, tunnelUsecase, configUsecase, settingUsecase, env.JWTSecret, tunnelAddr, env.WildcardDomain, env.GatewayDomain, env.ACMEEnable, env.MaxFreeDomains, env.CLILatestVersion, env.InspectDefaultLimit, statsCollector)
	authH := webui.NewAuth(assets.EmbeddedFS, authUsecase)
	userH := webui.NewUserHandler(assets.EmbeddedFS, authUsecase, settingUsecase)
	cliH := webui.NewCLIHandler(configUsecase, tunnelAddr, env.ACMEEnable, env.CLILatestVersion)
	tokenH := webui.NewToken(assets.EmbeddedFS, authUsecase)

	// Router
	router := web.SetupRouter(h, authH, userH, cliH, tokenH, env.CORSAllowedOrigins, http.FS(assets.EmbeddedFS))

	cleanup := func() {
		log.Println("[di] Cleaning up WebUI resources...")
		statsCollector.Stop()
		_ = db.Close()
	}

	return router, cleanup, nil
}
