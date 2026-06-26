package web

import (
	"crypto/subtle"
	"net/http"
	"strings"

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
		r.Use(corsMiddleware(corsAllowedOrigins))
		r.Use(webMiddleware.SecurityHeaders())

		// Auth routes
		r.Get("/login", authH.LoginPage)
		r.Post("/login", authH.Login)
		r.Get("/logout", authH.Logout)
		r.Get("/docs", h.Docs)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(authH.JWTMiddleware)
			r.Use(csrfMiddleware())

			// Pages
			r.Get("/", h.Index)
			r.Get("/configs", h.Configs)
			r.Get("/domains", h.Domains)
			r.Get("/downloads", h.Downloads)

			// API
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

func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowedMap := make(map[string]struct{}, len(allowedOrigins))
	allowAll := false
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			allowAll = true
		}
		allowedMap[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if allowAll {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else if _, ok := allowedMap[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func csrfMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
				sessionToken, _ := r.Context().Value(handler.CSRFTokenKey).(string)
				reqToken := r.Header.Get("X-CSRF-Token")

				if sessionToken == "" || reqToken == "" || subtle.ConstantTimeCompare([]byte(reqToken), []byte(sessionToken)) != 1 {
					http.Error(w, "Forbidden - CSRF token mismatch", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
