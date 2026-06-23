package di

import (
	"crypto/tls"
	"gotunnel/internal/infrastructure/cert"
	"net/http"

	"context"
	"fmt"
	"log"
	"strings"

	tunnelhandler "gotunnel/internal/delivery/tcp"
	domainConfig "gotunnel/internal/domain/config"
	domainTunnel "gotunnel/internal/domain/tunnel"
	"gotunnel/internal/infrastructure/cache/memory"
	redisrepo "gotunnel/internal/infrastructure/cache/redis"
	postgresrepo "gotunnel/internal/infrastructure/database/postgres"
	usecaseTunnel "gotunnel/internal/usecase/tunnel"
	usecaseUser "gotunnel/internal/usecase/user"
)

// BuildServerApp initializes all dependencies and returns the TunnelGateway and a cleanup function.
type TunnelApp struct {
	tunnelSrv *tunnelhandler.Server
	httpSrv   *http.Server
	cfg       *domainConfig.ServerConfig
}

func (a *TunnelApp) Run(ctx context.Context) error {
	tunnelTLS := cert.CloneTLSConfig(nil)

	if a.cfg.ACMEEnable {
		acmeManager := cert.NewAutocertManager(a.cfg.ACMECache, a.cfg.ACMEEnv, func(ctx context.Context, host string) error {
			if host == a.cfg.TunnelDomain {
				return nil
			}
			return fmt.Errorf("acme host not allowed in tunnel: %s", host)
		})
		tunnelTLS.GetCertificate = acmeManager.GetCertificate
	}

	cert.WrapWithWildcardCert(tunnelTLS, a.cfg.WildcardDomain, a.cfg.WildcardCertPath, a.cfg.WildcardKeyPath)

	if len(tunnelTLS.Certificates) == 0 {
		log.Println("[tunnel] Dev Mode / Fallback: Generating self-signed certificate.")
		fallback, err := cert.GenerateSelfSignedCert(a.cfg.TunnelDomain)
		if err == nil {
			tunnelTLS.Certificates = fallback.Certificates
		}
	}
	tunnelTLS.MinVersion = tls.VersionTLS12
	tunnelAddr := fmt.Sprintf("0.0.0.0:%d", a.cfg.TunnelPort)

	// Start TCP Tunnel listener
	tunnelLn, err := a.tunnelSrv.ListenTunnelTLS(tunnelAddr, tunnelTLS)
	if err != nil {
		return err
	}
	defer tunnelLn.Close()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("[tunnel] Internal HTTP listening on :%d", a.cfg.GatewayPort)
		if err := a.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		a.httpSrv.Shutdown(context.Background())
		return nil
	case err := <-errCh:
		return err
	}
}

func BuildTunnelApp(env *domainConfig.ServerConfig) (*TunnelApp, func(), error) {
	db, err := postgresrepo.InitDB(env)
	if err != nil {
		return nil, nil, fmt.Errorf("init db: %w", err)
	}

	userRepo := postgresrepo.NewUserRepository(db)

	// Redis Repositories
	tunnelStore := redisrepo.NewTunnelRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	tunnelStore.Ping(context.Background())

	var domainStore domainTunnel.DomainStore
	if env.WildcardDomain != "" {
		domainStore = postgresrepo.NewDomainRepository(db)
	} else {
		log.Printf("[gateway] Domain Management disabled (WILDCARD_DOMAIN is empty)")
	}

	// HostRegistry
	hostRegistry := memory.NewHostRegistry()
	for _, d := range []string{env.GatewayDomain, env.TunnelDomain, env.WebUIDomain} {
		if d = strings.TrimSpace(d); d != "" {
			hostRegistry.Authorize(d)
		}
	}
	if env.WildcardDomain != "" {
		hostRegistry.Authorize(env.WildcardDomain)
	}

	// Usecases
	tunnelUsecase := usecaseTunnel.NewTunnelUsecase(tunnelStore, domainStore)
	authUsecase := usecaseUser.NewAuthUsecase(userRepo, tunnelStore, env.JWTSecret, env.JWTExpireHours)

	// Handlers
	tunnelSrv, err := tunnelhandler.NewServerJWT(env.JWTSecret, hostRegistry, env.GatewayDomain, env.WildcardDomain, tunnelUsecase, authUsecase)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("init tunnel server: %w", err)
	}

	httpSrv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", env.GatewayPort),
		Handler: tunnelSrv,
	}

	app := &TunnelApp{
		tunnelSrv: tunnelSrv,
		httpSrv:   httpSrv,
		cfg:       env,
	}

	cleanup := func() {
		log.Println("[di] Cleaning up resources...")
		db.Close()
	}

	return app, cleanup, nil
}
