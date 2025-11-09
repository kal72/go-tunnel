package main

import (
	"log"
	"net/http"

	"gotunnel/internal/server"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	domains := []string{
		"tunnel.vpskamu.com",
		"app.vpskamu.com",
		"grafana.vpskamu.com",
	}

	// Kunci JWT (HARUS cocok dengan client config)
	const jwtSecret = "supersecretjwtkey"

	// Autocert (Let's Encrypt)
	m := &autocert.Manager{
		Cache:      autocert.DirCache("./cert-cache"),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
	}

	// Server utama
	srv, err := server.NewServerJWT(jwtSecret)
	if err != nil {
		log.Fatal(err)
	}

	// 1) HTTPS publik di :443 (autocert)
	httpsSrv := &http.Server{
		Addr:      ":8443",
		TLSConfig: m.TLSConfig(),
		Handler:   srv, // srv.ServeHTTP untuk meneruskan request ke tunnel
	}

	// 2) Listener dashboard (HTTP) di :8081
	go func() {
		log.Println("[edge] dashboard: http://0.0.0.0:8081")
		if err := http.ListenAndServe(":8081", srv.DashboardHandler()); err != nil {
			log.Println("[edge] dashboard error:", err)
		}
	}()

	// 3) Listener TUNNEL TLS (yamux) di :9443 (pakai cert ACME sama)
	go func() {
		if err := srv.ListenTunnelTLS(":9443", m.TLSConfig()); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("[edge] HTTPS public listening on :8443")
	log.Fatal(httpsSrv.ListenAndServeTLS("", "")) // cert & key dihandle autocert
}
