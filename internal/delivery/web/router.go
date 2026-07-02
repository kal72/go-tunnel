package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"gotunnel/internal/delivery/web/handler"
	webMiddleware "gotunnel/internal/delivery/web/middleware"
)

// SetupRouter creates and configures the Chi router for the WebUI and API.

func SetupRouter(
	h *handler.Handler,
	authH *handler.AuthHandler,
	userH *handler.UserHandler,
	cliH *handler.CLIHandler,
	corsAllowedOrigins []string,
	staticFS http.FileSystem,
) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// CLI API routes (without CORS)
	r.Post("/api/cli/login", authH.APILogin)
	r.Get("/api/cli/version", cliH.ClientGetVersion)
	r.Group(func(r chi.Router) {
		r.Use(authH.JWTMiddleware)
		r.Get("/api/cli/config/{name}", cliH.ClientGetConfig)
		r.Get("/api/cli/configs", cliH.ClientGetConfigs)
	})

	// WebUI & WebUI API routes (with CORS & CSRF)
	r.Group(func(r chi.Router) {
		r.Use(webMiddleware.CORS(corsAllowedOrigins))
		r.Use(webMiddleware.SecurityHeaders())

		// Auth routes
		r.Get("/login", authH.LoginPage)
		r.Post("/login", authH.Login)
		r.Get("/logout", authH.Logout)
		r.Get("/docs", h.Docs)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authH.JWTMiddleware)
			r.Use(webMiddleware.CSRF())

			// Pages
			r.Get("/", h.Index)
			r.Get("/configs", h.Configs)
			r.Get("/domains", h.Domains)
			r.Get("/ratelimit", h.RateLimitPage)
			r.Get("/downloads", h.Downloads)

			// API
			r.Get("/api/tunnels/stream", h.HandleTunnelStream)
			r.Get("/api/tunnels/inspect/stream", h.StreamInspectEvents)
			r.Get("/api/ratelimit", h.GetRateLimit)
			r.Put("/api/ratelimit", h.UpdateRateLimit)
			r.Get("/api/configs", h.ListConfigs)
			r.Post("/api/configs", h.CreateConfig)
			r.Get("/api/configs/{id}", h.GetConfig)
			r.Put("/api/configs/{id}", h.UpdateConfig)
			r.Delete("/api/configs/{id}", h.DeleteConfig)

			r.Get("/api/domains", h.ListDomains)
			r.Post("/api/domains", h.AddDomain)
			r.Delete("/api/domains/{domain}", h.RemoveDomain)

			// Admin only routes
			r.Group(func(r chi.Router) {
				r.Use(handler.AdminMiddleware)

				// Settings Admin
				r.Get("/settings", h.SettingsPage)
				r.Get("/api/settings", h.GetSettings)
				r.Put("/api/settings", h.UpdateSettings)

				r.Get("/users", userH.UsersPage)
				r.Get("/api/users", userH.ListUsers)
				r.Post("/api/users", userH.CreateUser)
				r.Put("/api/users/{id}/status", userH.UpdateStatus)
				r.Put("/api/users/{id}/password", userH.UpdatePassword)
				r.Post("/api/users/{id}/revoke-tokens", userH.RevokeTokens)
				r.Delete("/api/users/{id}", userH.DeleteUser)
			})
		})
	})

	// Serve static binaries (public for curl install)
	fs := http.FileServer(http.Dir("./downloads"))
	r.Handle("/dl/*", http.StripPrefix("/dl/", fs))

	// Static assets
	r.Handle("/static/*", http.FileServer(staticFS))

	return r
}
