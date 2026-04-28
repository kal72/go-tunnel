package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"gotunnel/internal/tunnel/config"
	"gotunnel/internal/tunnel/registry"
	"gotunnel/internal/tunnel/server"
	"gotunnel/internal/tunnel/state"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Edge struct {
	cfg      *config.ServerConfig
	httpsSrv *http.Server
	acmeSrv  *http.Server
	tunnelLn net.Listener
	store    state.Store
}

func New(env *config.ServerConfig) (*Edge, error) {
	// Registry
	hostRegistry := buildHostRegistry(env)

	// Autocert
	m := NewAutocertManager(env, hostRegistry)

	// Stores
	tunnelStore := state.NewRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	tunnelStore.Ping(context.Background())

	// Load domains from Redis (only if wildcard base is configured)
	if env.WildcardDomain != "" {
		domainStore := state.NewRedisStore(env.RedisAddr, env.RedisPass, env.DomainRedisDB)
		domainStore.Ping(context.Background())

		domains, err := domainStore.ListDomains(context.Background())
		if err == nil {
			for _, d := range domains {
				hostRegistry.Authorize(d)
			}
			log.Printf("[edge] loaded %d domains from redis", len(domains))
		} else {
			log.Printf("[edge] failed to load domains from redis: %v", err)
		}
		hostRegistry.Authorize(env.WildcardDomain)
	} else {
		log.Printf("[edge] Domain Management disabled (WILDCARD_DOMAIN is empty)")
	}

	srv, err := server.NewServerJWT(env.JWTSecret, hostRegistry, env.GatewayHost, tunnelStore)
	if err != nil {
		return nil, fmt.Errorf("init server: %w", err)
	}

	// Public HTTPS
	httpsSrv := buildHTTPSServer(env, m, srv)

	// ACME HTTP-01
	acmeSrv := buildACMEServer(m)

	// Tunnel TLS listener
	tunnelTLS := buildTunnelTLS(m, env.TunnelHost)
	tunnelAddr := fmt.Sprintf("0.0.0.0:%d", env.TunnelPort)
	tunnelLn, err := srv.ListenTunnelTLS(tunnelAddr, tunnelTLS)
	if err != nil {
		return nil, fmt.Errorf("tunnel listener: %w", err)
	}

	return &Edge{
		cfg:      env,
		httpsSrv: httpsSrv,
		acmeSrv:  acmeSrv,
		tunnelLn: tunnelLn,
		store:    tunnelStore,
	}, nil
}

// Run starts all servers and blocks until ctx is cancelled or a fatal error occurs.
func (e *Edge) Run(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		log.Printf("[edge] acme-http listening on :80")
		if err := e.acmeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("[acme-http]", err)
		}
	}()

	go func() {
		log.Printf("[edge] HTTPS public listening on :%d", e.cfg.GatewayPort)
		if err := e.httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("[edge] shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("HTTPS server fatal: %w", err)
	}

	return e.shutdown()
}

func (e *Edge) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := e.httpsSrv.Shutdown(ctx); err != nil {
		log.Printf("[edge] HTTPS shutdown error: %v", err)
	}
	if err := e.acmeSrv.Shutdown(ctx); err != nil {
		log.Printf("[edge] acme-http shutdown error: %v", err)
	}
	if e.tunnelLn != nil {
		_ = e.tunnelLn.Close()
	}

	log.Println("[edge] shutdown complete")
	return nil
}

// --- helpers ---

func buildHostRegistry(env *config.ServerConfig) *registry.HostRegistry {
	hr := registry.NewHostRegistry()
	for _, d := range []string{env.GatewayHost, env.TunnelHost} {
		if d = strings.TrimSpace(d); d != "" {
			hr.Authorize(d)
		}
	}
	return hr
}

func buildHTTPSServer(env *config.ServerConfig, m interface{ TLSConfig() *tls.Config }, srv http.Handler) *http.Server {
	tlsCfg := cloneTLSConfig(m.TLSConfig())
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(128)
	tlsCfg.NextProtos = ensureProto(tlsCfg.NextProtos, "h2")
	tlsCfg.NextProtos = ensureProto(tlsCfg.NextProtos, "http/1.1")
	ensureDefaultServerName(tlsCfg, env.GatewayHost)

	return &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", env.GatewayPort),
		TLSConfig:         tlsCfg,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}

func buildACMEServer(m interface {
	HTTPHandler(http.Handler) http.Handler
}) *http.Server {
	acmeHandler := m.HTTPHandler(nil)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
			return
		}
		acmeHandler.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:         "0.0.0.0:80",
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
}

func buildTunnelTLS(m interface{ TLSConfig() *tls.Config }, tunnelHost string) *tls.Config {
	tlsCfg := cloneTLSConfig(m.TLSConfig())
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.ClientSessionCache = tls.NewLRUClientSessionCache(64)
	ensureDefaultServerName(tlsCfg, tunnelHost)
	return tlsCfg
}
