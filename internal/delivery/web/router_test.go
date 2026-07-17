package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"gotunnel/internal/delivery/web/handler"
	webMiddleware "gotunnel/internal/delivery/web/middleware"
)

func TestSetupRouter(t *testing.T) {
	t.Parallel()

	h := &handler.Handler{}
	authH := &handler.AuthHandler{}
	userH := &handler.UserHandler{}
	cliH := &handler.CLIHandler{}
	tokenH := &handler.TokenHandler{}

	r := SetupRouter(h, authH, userH, cliH, tokenH, []string{"*"}, http.Dir("."))
	assert.NotNil(t, r)
}

func TestCSRFMiddleware(t *testing.T) {
	t.Parallel()

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	middlewareFunc := webMiddleware.CSRF()
	h := middlewareFunc(dummyHandler)

	t.Run("GET ignores CSRF", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("POST without token fails", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/configs", http.NoBody)
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("POST with matching session token succeeds", func(t *testing.T) {
		token := "super-secret-token-32bytes"
		ctx := context.WithValue(context.Background(), handler.CSRFTokenKey, token)
		reqPost := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/configs", http.NoBody)
		reqPost.Header.Set("X-CSRF-Token", token)
		recPost := httptest.NewRecorder()

		h.ServeHTTP(recPost, reqPost)

		assert.Equal(t, http.StatusOK, recPost.Code)
	})
}
