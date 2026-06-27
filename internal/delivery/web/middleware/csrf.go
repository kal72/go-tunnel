package middleware

import (
	"crypto/subtle"
	"net/http"

	"gotunnel/internal/delivery/web/handler"
)

// CSRF returns a middleware that validates X-CSRF-Token headers against context tokens for state-changing requests.
func CSRF() func(http.Handler) http.Handler {
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
