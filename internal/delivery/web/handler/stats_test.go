package handler_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gotunnel/internal/delivery/web/handler"
	"gotunnel/internal/shared/stats"
	webassets "gotunnel/web"
)

func TestStatsPage(t *testing.T) {
	sc := stats.NewStatsCollector(1 * time.Second)
	h := handler.New(webassets.EmbeddedFS, nil, nil, nil, "secret", "tunnel.test", "example.com", "gateway.test", false, 3, "v1.0.0", 100, sc)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(1))
	ctx = context.WithValue(ctx, handler.UserNameKey, "admin")
	ctx = context.WithValue(ctx, handler.CSRFTokenKey, "csrf-token")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.StatsPage(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "System Statistics")
}

func TestStreamStats(t *testing.T) {
	sc := stats.NewStatsCollector(10 * time.Millisecond)
	h := handler.New(webassets.EmbeddedFS, nil, nil, nil, "secret", "tunnel.test", "example.com", "gateway.test", false, 3, "v1.0.0", 100, sc)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/stats/stream", nil)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.StreamStats(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "data: {")
}

func TestStreamStats_NoCollector(t *testing.T) {
	h := handler.New(webassets.EmbeddedFS, nil, nil, nil, "secret", "tunnel.test", "example.com", "gateway.test", false, 3, "v1.0.0", 100, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/stats/stream", nil)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.StreamStats(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "stats collector not initialized")
}

type nonFlusherWriter struct {
	http.ResponseWriter
}

func TestStreamStats_NonFlusher(t *testing.T) {
	h := handler.New(webassets.EmbeddedFS, nil, nil, nil, "secret", "tunnel.test", "example.com", "gateway.test", false, 3, "v1.0.0", 100, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/stats/stream", nil)
	rec := httptest.NewRecorder()
	nf := &nonFlusherWriter{rec}

	h.StreamStats(nf, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

type errorFlusherWriter struct {
	http.ResponseWriter
}

func (e *errorFlusherWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write error")
}

func (e *errorFlusherWriter) Flush() {}

func TestStreamStats_WriteError(t *testing.T) {
	sc := stats.NewStatsCollector(10 * time.Millisecond)
	h := handler.New(webassets.EmbeddedFS, nil, nil, nil, "secret", "tunnel.test", "example.com", "gateway.test", false, 3, "v1.0.0", 100, sc)

	req := httptest.NewRequest(http.MethodGet, "/api/stats/stream", nil)
	rec := httptest.NewRecorder()
	ef := &errorFlusherWriter{rec}

	h.StreamStats(ef, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
