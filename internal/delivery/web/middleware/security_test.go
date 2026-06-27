package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		expectedCSP  string
		expectedXCTO string
		expectedXFO  string
		expectedRP   string
	}{
		{
			name: "standard security headers enforcement",
			expectedCSP: "default-src 'self'; " +
				"script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; " +
				"style-src 'self' 'unsafe-inline'; " +
				"img-src 'self' data: https:; " +
				"connect-src 'self' ws: wss:; " +
				"font-src 'self' data:; " +
				"object-src 'none'; " +
				"base-uri 'self'; " +
				"form-action 'self'",
			expectedXCTO: "nosniff",
			expectedXFO:  "DENY",
			expectedRP:   "strict-origin-when-cross-origin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := SecurityHeaders()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedCSP, rec.Header().Get("Content-Security-Policy"))
			assert.Equal(t, tt.expectedXCTO, rec.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, tt.expectedXFO, rec.Header().Get("X-Frame-Options"))
			assert.Equal(t, tt.expectedRP, rec.Header().Get("Referrer-Policy"))
		})
	}
}
