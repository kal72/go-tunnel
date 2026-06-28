package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCORS(t *testing.T) {
	t.Parallel()

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	tests := []struct {
		name           string
		allowedOrigins []string
		reqOrigin      string
		reqMethod      string
		expectedStatus int
		expectedOrigin string
	}{
		{
			name:           "allow all origins wildcard",
			allowedOrigins: []string{"*"},
			reqOrigin:      "http://example.com",
			reqMethod:      http.MethodGet,
			expectedStatus: http.StatusOK,
			expectedOrigin: "*",
		},
		{
			name:           "allow specific origin matched",
			allowedOrigins: []string{"http://allowed.com", "http://test.com"},
			reqOrigin:      "http://allowed.com",
			reqMethod:      http.MethodGet,
			expectedStatus: http.StatusOK,
			expectedOrigin: "http://allowed.com",
		},
		{
			name:           "allow specific origin not matched",
			allowedOrigins: []string{"http://allowed.com"},
			reqOrigin:      "http://disallowed.com",
			reqMethod:      http.MethodGet,
			expectedStatus: http.StatusOK,
			expectedOrigin: "",
		},
		{
			name:           "options preflight request returns 204",
			allowedOrigins: []string{"*"},
			reqOrigin:      "http://example.com",
			reqMethod:      http.MethodOptions,
			expectedStatus: http.StatusNoContent,
			expectedOrigin: "*",
		},
		{
			name:           "no origin header",
			allowedOrigins: []string{"*"},
			reqOrigin:      "",
			reqMethod:      http.MethodGet,
			expectedStatus: http.StatusOK,
			expectedOrigin: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mw := CORS(tt.allowedOrigins)
			h := mw(dummyHandler)

			req := httptest.NewRequest(tt.reqMethod, "/test", nil)
			if tt.reqOrigin != "" {
				req.Header.Set("Origin", tt.reqOrigin)
			}
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, tt.expectedOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}
