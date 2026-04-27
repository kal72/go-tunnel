package main

import (
	"context"
	"fmt"
	"gotunnel/assets"
	"gotunnel/internal/tunnel/config"
	"gotunnel/internal/tunnel/state"
	"gotunnel/internal/webui/handler"

	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	env, _ := config.LoadServerConfig(".env")

	redisStore := state.NewRedisStore(env.RedisAddr, env.RedisPass, env.RedisDB)
	redisStore.Ping(context.Background())

	tunnelAddr := env.TunnelHost
	if env.TunnelPort != 0 && env.TunnelPort != 443 {
		tunnelAddr = fmt.Sprintf("%s:%d", env.TunnelHost, env.TunnelPort)
	}

	h := handler.New(assets.EmbeddedFS, redisStore, env.JWTSecret, tunnelAddr)
	authH := handler.NewAuth(assets.EmbeddedFS, redisStore)

	// Auth routes
	r.Get("/login", authH.LoginPage)
	r.Post("/login", authH.Login)
	r.Get("/logout", authH.Logout)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(authH.JWTMiddleware)

		// Pages
		r.Get("/", h.Index)
		r.Get("/configs", h.Configs)

		// API
		r.Get("/api/configs", h.ListConfigs)
		r.Post("/api/config/{name}", h.CreateConfig)
		r.Get("/api/config/{name}", h.GetConfig)
		r.Put("/api/config/{name}", h.UpdateConfig)
		r.Delete("/api/config/{name}", h.DeleteConfig)
		r.Get("/api/config/{name}/download", h.DownloadConfig)
		r.Get("/api/generate-token", h.GenerateToken)
		r.Delete("/api/revoke-token", h.RevokeToken)
	})

	// Static assets
	r.Handle("/static/*", http.FileServer(http.FS(assets.EmbeddedFS)))

	port := os.Getenv("WEBUI_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Tunnel Manager running on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

