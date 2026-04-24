package main

import (
	"gotunnel/assets"
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

	h := handler.New(assets.EmbeddedFS)

	// Pages
	r.Get("/", h.Index)

	// API
	r.Get("/api/configs", h.ListConfigs)
	r.Get("/api/config/{name}", h.GetConfig)
	r.Put("/api/config/{name}", h.UpdateConfig)

	// Static assets
	r.Handle("/static/*", http.FileServer(http.FS(assets.EmbeddedFS)))

	log.Println("Tunnel Dashboard running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
