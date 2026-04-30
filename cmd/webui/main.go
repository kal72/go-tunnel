package main

import (
	"context"
	"flag"
	"fmt"
	"gotunnel/assets"
	"gotunnel/internal/tunnel/config"
	"gotunnel/internal/tunnel/state"
	"gotunnel/internal/webui/handler"

	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	var configPath string
	flag.StringVar(&configPath, "config", ".env", "Path to the .env configuration file")
	flag.StringVar(&configPath, "c", ".env", "Path to the .env configuration file (shorthand)")
	flag.Parse()

	env, err := config.LoadServerConfig(configPath)
	if err != nil {
		log.Printf("Warning: failed to load config from %s: %v", configPath, err)
	}

	redisStore := state.NewRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	redisStore.Ping(context.Background())

	domainStore := state.NewRedisStore(env.RedisAddr, env.RedisPass, env.DomainRedisDB)
	domainStore.Ping(context.Background())

	tunnelAddr := env.TunnelHost
	if env.TunnelPort != 0 && env.TunnelPort != 443 {
		tunnelAddr = fmt.Sprintf("%s:%d", env.TunnelHost, env.TunnelPort)
	}

	h := handler.New(assets.EmbeddedFS, redisStore, domainStore, env.JWTSecret, tunnelAddr, env.WildcardDomain)
	authH := handler.NewAuth(assets.EmbeddedFS, redisStore)

	// Auth routes
	r.Get("/login", authH.LoginPage)
	r.Post("/login", authH.Login)
	r.Get("/logout", authH.Logout)
	r.Get("/docs", h.Docs)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(authH.JWTMiddleware)

		// Pages
		r.Get("/", h.Index)
		r.Get("/configs", h.Configs)
		r.Get("/domains", h.Domains)

		// API
		r.Get("/api/configs", h.ListConfigs)
		r.Post("/api/config/{name}", h.CreateConfig)
		r.Get("/api/config/{name}", h.GetConfig)
		r.Put("/api/config/{name}", h.UpdateConfig)
		r.Delete("/api/config/{name}", h.DeleteConfig)
		r.Get("/api/config/{name}/download", h.DownloadConfig)
		r.Get("/api/generate-token", h.GenerateToken)
		r.Delete("/api/revoke-token", h.RevokeToken)

		r.Get("/api/domains", h.ListDomains)
		r.Post("/api/domains", h.AddDomain)
		r.Delete("/api/domains/{domain}", h.RemoveDomain)
	})

	// Static assets
	r.Handle("/static/*", http.FileServer(http.FS(assets.EmbeddedFS)))

	port := fmt.Sprintf("%d", env.WebUIPort)
	log.Printf("Tunnel Manager running on http://%s:%s", env.WebUIDomain, port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

