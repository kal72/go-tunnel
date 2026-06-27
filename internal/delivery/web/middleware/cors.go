package middleware

import (
	"net/http"
	"strings"
)

// CORS returns a middleware that handles Cross-Origin Resource Sharing based on allowed origins.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
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
