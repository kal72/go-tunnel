package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gotunnel/internal/config"
	"gotunnel/internal/registry"
	"gotunnel/internal/server"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	env, err := config.LoadServerConfig(".env")
	if err != nil {
		log.Fatal("load .env:", err)
	}

	log.Printf("[config] Ports: public=%d tunnel=%d dashboard=%d", env.GatewayPort, env.TunnelPort, env.DashboardPort)
	log.Printf("[config] Domain: %v", env.GatewayHost)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Setup autocert
	hostRegistry := registry.NewHostRegistry()
	if d := strings.TrimSpace(env.GatewayHost); d != "" {
		if !hostRegistry.Add(d) {
			log.Printf("[config] duplicate domain ignored: %s", d)
		}
	}
	acmeClient := &acme.Client{}
	defaultDir := acme.LetsEncryptURL
	if strings.ToLower(strings.TrimSpace(env.ACMEEnv)) == "staging" {
		defaultDir = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	acmeClient.DirectoryURL = defaultDir

	m := &autocert.Manager{
		Cache:  autocert.DirCache(env.ACMECache),
		Prompt: autocert.AcceptTOS,
		Client: acmeClient,
		HostPolicy: func(_ context.Context, host string) error {
			if hostRegistry.Exists(host) {
				return nil
			}
			return fmt.Errorf("unauthorized host: %s", host)
		},
	}

	// Server init
	srv, err := server.NewServerJWT(env.JWTSecret, hostRegistry, env.GatewayHost)
	if err != nil {
		log.Fatal(err)
	}
	publicTLS := cloneTLSConfig(m.TLSConfig())
	publicTLS.MinVersion = tls.VersionTLS12
	publicTLS.ClientSessionCache = tls.NewLRUClientSessionCache(128)
	publicTLS.NextProtos = ensureProto(publicTLS.NextProtos, "h2")
	publicTLS.NextProtos = ensureProto(publicTLS.NextProtos, "http/1.1")
	ensureDefaultServerName(publicTLS, env.GatewayHost)

	httpsSrv := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", env.GatewayPort),
		TLSConfig:         publicTLS,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	dashboardSrv := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", env.DashboardPort),
		Handler:           srv.DashboardHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("[edge] dashboard at http://%s", dashboardSrv.Addr)
	go func() {
		if err := dashboardSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("[dashboard]", err)
		}
	}()

	// HTTP-01 challenge listener (port 80)
	acmeHandler := m.HTTPHandler(nil)
	http80Handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			target := "https://" + r.Host + r.URL.String()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}

		acmeHandler.ServeHTTP(w, r)
	})

	acmeHTTP := &http.Server{
		Addr:         "0.0.0.0:80",
		Handler:      http80Handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		if err := acmeHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Println("[acme-http]", err)
		}
	}()

	tunnelTLS := cloneTLSConfig(m.TLSConfig())
	tunnelTLS.MinVersion = tls.VersionTLS12
	tunnelTLS.ClientSessionCache = tls.NewLRUClientSessionCache(64)
	ensureDefaultServerName(tunnelTLS, env.TunnelHost)
	tunnelAddr := fmt.Sprintf("0.0.0.0:%d", env.TunnelPort)
	tunnelLn, err := srv.ListenTunnelTLS(tunnelAddr, tunnelTLS)
	if err != nil {
		log.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("[edge] HTTPS public listening on :%d", env.GatewayPort)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("[edge] shutdown signal received")
	case err := <-errCh:
		log.Printf("[edge] HTTPS server error: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpsSrv.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
		log.Printf("[edge] HTTPS shutdown error: %v", err)
	}
	if err := dashboardSrv.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
		log.Printf("[edge] dashboard shutdown error: %v", err)
	}
	if err := acmeHTTP.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
		log.Printf("[edge] acme-http shutdown error: %v", err)
	}
	if tunnelLn != nil {
		_ = tunnelLn.Close()
	}
	log.Println("[edge] shutdown complete")
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func ensureProto(list []string, proto string) []string {
	for _, p := range list {
		if p == proto {
			return list
		}
	}
	return append(list, proto)
}

func ensureDefaultServerName(cfg *tls.Config, fallback string) {
	fallback = strings.TrimSpace(fallback)
	if cfg == nil || fallback == "" {
		return
	}
	baseGetCert := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello != nil && hello.ServerName == "" {
			cloned := *hello
			cloned.ServerName = fallback
			hello = &cloned
		}
		if baseGetCert != nil {
			return baseGetCert(hello)
		}
		if len(cfg.Certificates) > 0 {
			return &cfg.Certificates[0], nil
		}
		return nil, fmt.Errorf("no certificates configured")
	}
}
