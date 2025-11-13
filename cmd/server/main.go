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

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	env, err := config.LoadServerConfig(".env")
	if err != nil {
		log.Fatal("load .env:", err)
	}

	log.Printf("[config] Ports: public=%d tunnel=%d dashboard=%d", env.ServerPort, env.TunnelPort, env.DashboardPort)
	log.Printf("[config] Domains: %v", env.ACMEDomains)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Setup autocert
	hostRegistry := registry.NewHostRegistry()
	for _, domain := range env.ACMEDomains {
		if d := strings.TrimSpace(domain); d != "" {
			if !hostRegistry.Add(d) {
				log.Printf("[config] duplicate domain ignored: %s", d)
			}
		}
	}
	m := &autocert.Manager{
		Cache:  autocert.DirCache(env.ACMECache),
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(_ context.Context, host string) error {
			if hostRegistry.Exists(host) {
				return nil
			}
			return fmt.Errorf("unauthorized host: %s", host)
		},
	}

	// Server init
	srv, err := server.NewServerJWT(env.JWTSecret, hostRegistry)
	if err != nil {
		log.Fatal(err)
	}

	publicTLS := cloneTLSConfig(m.TLSConfig())
	publicTLS.MinVersion = tls.VersionTLS12
	// publicTLS.PreferServerCipherSuites = true
	publicTLS.ClientSessionCache = tls.NewLRUClientSessionCache(128)
	publicTLS.NextProtos = ensureProto(publicTLS.NextProtos, "h2")
	publicTLS.NextProtos = ensureProto(publicTLS.NextProtos, "http/1.1")

	httpsSrv := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", env.ServerPort),
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

	tunnelTLS := cloneTLSConfig(m.TLSConfig())
	tunnelTLS.MinVersion = tls.VersionTLS12
	tunnelTLS.ClientSessionCache = tls.NewLRUClientSessionCache(64)
	tunnelAddr := fmt.Sprintf("0.0.0.0:%d", env.TunnelPort)
	tunnelLn, err := srv.ListenTunnelTLS(tunnelAddr, tunnelTLS)
	if err != nil {
		log.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("[edge] HTTPS public listening on :%d", env.ServerPort)
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
