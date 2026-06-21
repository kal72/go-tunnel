package main

import (
	"context"
	"flag"
	"fmt"
	"gotunnel/assets"
	"gotunnel/internal/config"
	"gotunnel/internal/model"
	postgresrepo "gotunnel/internal/repository/postgres"
	redisrepo "gotunnel/internal/repository/redis"
	"gotunnel/internal/usecase"
	webui "gotunnel/internal/handler/webui"
	"gotunnel/internal/handler/api"

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

	redisStore := redisrepo.NewRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	redisStore.Ping(context.Background())

	var domainStore model.DomainStore
	if env.WildcardDomain != "" {
		domainStore = redisrepo.NewRedisStore(env.RedisAddr, env.RedisPass, env.DomainRedisDB)
		domainStore.Ping(context.Background())
	}

	tunnelAddr := env.TunnelHost
	if env.TunnelPort != 0 && env.TunnelPort != 443 {
		tunnelAddr = fmt.Sprintf("%s:%d", env.TunnelHost, env.TunnelPort)
	}

	db, err := postgresrepo.InitDB(env)
	if err != nil {
		log.Fatal("init db:", err)
	}
	defer db.Close()

	userRepo := postgresrepo.NewUserRepository(db)
	configRepo := postgresrepo.NewConfigRepository(db)

	tunnelUsecase := usecase.NewTunnelUsecase(redisStore, domainStore)
	configUsecase := usecase.NewConfigUsecase(configRepo)
	authUsecase := usecase.NewAuthUsecase(userRepo, redisStore, env.JWTSecret)

	h := webui.New(assets.EmbeddedFS, tunnelUsecase, configUsecase, env.JWTSecret, tunnelAddr, env.WildcardDomain, env.GatewayHost, env.ACMEEnable)
	authH := webui.NewAuth(assets.EmbeddedFS, authUsecase)
	userH := webui.NewUserHandler(assets.EmbeddedFS, authUsecase)
	cliH := api.NewCLIHandler(configUsecase, tunnelAddr, env.ACMEEnable)

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
		r.Get("/downloads", h.Downloads)

		// Serve static binaries inside the protected group
		fs := http.FileServer(http.Dir("./downloads"))
		r.Handle("/dl/*", http.StripPrefix("/dl/", fs))

		// API
		r.Get("/api/configs", h.ListConfigs)
		r.Post("/api/configs", h.CreateConfig)
		r.Get("/api/configs/{id}", h.GetConfig)
		r.Put("/api/configs/{id}", h.UpdateConfig)
		r.Delete("/api/configs/{id}", h.DeleteConfig)

		r.Get("/api/cli/config/{name}", cliH.ClientGetConfig)
		r.Get("/api/cli/configs", cliH.ClientGetConfigs)

		r.Get("/api/domains", h.ListDomains)
		r.Post("/api/domains", h.AddDomain)
		r.Delete("/api/domains/{domain}", h.RemoveDomain)

		// Admin only routes
		r.Group(func(r chi.Router) {
			r.Use(webui.AdminMiddleware)
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

