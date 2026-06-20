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

	db, err := state.InitDB(env)
	if err != nil {
		log.Fatal("init db:", err)
	}
	defer db.Close()

	userRepo := state.NewUserRepository(db)
	configRepo := state.NewConfigRepository(db)

	h := handler.New(assets.EmbeddedFS, redisStore, domainStore, configRepo, env.JWTSecret, tunnelAddr, env.WildcardDomain, env.GatewayHost)
	authH := handler.NewAuth(assets.EmbeddedFS, redisStore, userRepo)
	userH := handler.NewUserHandler(assets.EmbeddedFS, userRepo)

	// Auth routes
	r.Get("/login", authH.LoginPage)
	r.Post("/login", authH.Login)
	r.Post("/api/cli/login", authH.APILogin)
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
		r.Post("/api/configs", h.CreateConfig)
		r.Get("/api/configs/{id}", h.GetConfig)
		r.Put("/api/configs/{id}", h.UpdateConfig)
		r.Delete("/api/configs/{id}", h.DeleteConfig)

		r.Get("/api/client/config", h.ClientGetConfig)
		r.Get("/api/client/configs", h.ClientGetConfigs)

		r.Get("/api/domains", h.ListDomains)
		r.Post("/api/domains", h.AddDomain)
		r.Delete("/api/domains/{domain}", h.RemoveDomain)

		// Admin only routes
		r.Group(func(r chi.Router) {
			r.Use(handler.AdminMiddleware)
			r.Get("/users", userH.UsersPage)
			r.Get("/api/users", userH.ListUsers)
			r.Post("/api/users", userH.CreateUser)
			r.Put("/api/users/{id}/status", userH.UpdateStatus)
			r.Put("/api/users/{id}/password", userH.UpdatePassword)
			r.Delete("/api/users/{id}", userH.DeleteUser)
		})
	})

	// Static assets
	r.Handle("/static/*", http.FileServer(http.FS(assets.EmbeddedFS)))

	port := fmt.Sprintf("%d", env.WebUIPort)
	log.Printf("Tunnel Manager running on http://%s:%s", env.WebUIDomain, port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

