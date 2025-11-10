package main

import (
	"fmt"
	"log"
	"net/http"

	"gotunnel/internal/config"
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

	// Setup autocert
	m := &autocert.Manager{
		Cache:      autocert.DirCache(env.ACMECache),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(env.ACMEDomains...),
	}

	// Server init
	srv, err := server.NewServerJWT(env.JWTSecret)
	if err != nil {
		log.Fatal(err)
	}

	// HTTPS public
	httpsSrv := &http.Server{
		Addr:      fmt.Sprintf(":%d", env.ServerPort),
		TLSConfig: m.TLSConfig(),
		Handler:   srv,
	}

	// Dashboard
	go func() {
		addr := fmt.Sprintf(":%d", env.DashboardPort)
		log.Printf("[edge] dashboard at http://0.0.0.0%s", addr)
		if err := http.ListenAndServe(addr, srv.DashboardHandler()); err != nil {
			log.Println("[dashboard]", err)
		}
	}()

	// Tunnel listener
	go func() {
		addr := fmt.Sprintf(":%d", env.TunnelPort)
		if err := srv.ListenTunnelTLS(addr, m.TLSConfig()); err != nil {
			log.Fatal(err)
		}
	}()

	log.Printf("[edge] HTTPS public listening on :%d", env.ServerPort)
	log.Fatal(httpsSrv.ListenAndServeTLS("", ""))
}
