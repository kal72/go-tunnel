package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"gotunnel/internal/delivery/web/handler"
)

func TestCSRF(t *testing.T) {
	t.Parallel()

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	tests := []struct {
		name           string
		method         string
		ctxToken       string
		headerToken    string
		expectedStatus int
	}{
		{
			name:           "get method bypasses csrf check",
			method:         http.MethodGet,
			ctxToken:       "",
			headerToken:    "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "post method matched tokens succeed",
			method:         http.MethodPost,
			ctxToken:       "secret123",
			headerToken:    "secret123",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "post method mismatched tokens fail",
			method:         http.MethodPost,
			ctxToken:       "secret123",
			headerToken:    "wrongtoken",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "put method empty header token fails",
			method:         http.MethodPut,
			ctxToken:       "secret123",
			headerToken:    "",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "delete method empty ctx token fails",
			method:         http.MethodDelete,
			ctxToken:       "",
			headerToken:    "secret123",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mw := CSRF()
			h := mw(dummyHandler)

			req := httptest.NewRequest(tt.method, "/action", nil)
			if tt.ctxToken != "" {
				ctx := context.WithValue(req.Context(), handler.CSRFTokenKey, tt.ctxToken)
				req = req.WithContext(ctx)
			}
			if tt.headerToken != "" {
				req.Header.Set("X-CSRF-Token", tt.headerToken)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}
