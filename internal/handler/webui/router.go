package webui

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"gotunnel/internal/handler/api"
)

// SetupRouter creates and configures the Chi router for the WebUI and API.
func SetupRouter(
	h *Handler,
	authH *AuthHandler,
	userH *UserHandler,
	cliH *api.CLIHandler,
	staticFS http.FileSystem,
) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

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
			r.Use(AdminMiddleware)
			r.Get("/users", userH.UsersPage)
			r.Get("/api/users", userH.ListUsers)
			r.Post("/api/users", userH.CreateUser)
			r.Put("/api/users/{id}/status", userH.UpdateStatus)
			r.Put("/api/users/{id}/password", userH.UpdatePassword)
			r.Delete("/api/users/{id}", userH.DeleteUser)
		})
	})

	// Static assets
	r.Handle("/static/*", http.FileServer(staticFS))

	return r
}
