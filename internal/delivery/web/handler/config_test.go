package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gotunnel/assets"
	"gotunnel/internal/delivery/web/handler"
	"gotunnel/internal/domain/tunnel"
	mockTunnel "gotunnel/internal/usecase/tunnel/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandler_Index_RoleFiltering(t *testing.T) {
	mockUC := new(mockTunnel.MockTunnelUsecase)
	tunnels := []tunnel.TunnelInfo{
		{
			Name:        "admin-tunnel",
			ClientName:  "ADMIN",
			Hosts:       []string{"admin.example.com"},
			ConnectedAt: time.Now(),
			LastPing:    time.Now(),
		},
		{
			Name:        "user1-tunnel",
			ClientName:  "USER1",
			Hosts:       []string{"user1.example.com"},
			ConnectedAt: time.Now(),
			LastPing:    time.Now(),
		},
	}
	mockUC.On("ListTunnels", mock.Anything).Return(tunnels, nil)

	h := handler.New(assets.EmbeddedFS, mockUC, nil, nil, "secret", "tunnel.test", "example.com", "gateway.test", false, 3, "v1.0.0", 100)

	tests := []struct {
		name         string
		role         int16
		username     string
		expectedLen  int
		expectedName string
	}{
		{
			name:         "admin sees all tunnels",
			role:         1,
			username:     "ADMIN",
			expectedLen:  2,
			expectedName: "admin-tunnel",
		},
		{
			name:         "regular user sees only own tunnels",
			role:         0,
			username:     "USER1",
			expectedLen:  1,
			expectedName: "user1-tunnel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			ctx := context.WithValue(req.Context(), handler.UserRoleKey, tt.role)
			ctx = context.WithValue(ctx, handler.UserNameKey, tt.username)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			h.Index(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedName)
			if tt.role == 0 {
				assert.NotContains(t, w.Body.String(), "admin-tunnel")
			}
		})
	}
}

func TestHandler_HandleTunnelStream_RoleFiltering(t *testing.T) {
	mockUC := new(mockTunnel.MockTunnelUsecase)
	tunnels := []tunnel.TunnelInfo{
		{
			Name:        "admin-tunnel",
			ClientName:  "ADMIN",
			Hosts:       []string{"admin.example.com"},
			ConnectedAt: time.Now(),
			LastPing:    time.Now(),
		},
		{
			Name:        "user1-tunnel",
			ClientName:  "USER1",
			Hosts:       []string{"user1.example.com"},
			ConnectedAt: time.Now(),
			LastPing:    time.Now(),
		},
	}
	mockUC.On("ListTunnels", mock.Anything).Return(tunnels, nil)

	ch := make(chan string)
	close(ch)
	mockUC.On("SubscribeTunnelEvents", mock.Anything).Return((<-chan string)(ch), nil)

	h := handler.New(assets.EmbeddedFS, mockUC, nil, nil, "secret", "tunnel.test", "example.com", "gateway.test", false, 3, "v1.0.0", 100)

	req := httptest.NewRequest(http.MethodGet, "/api/tunnels/stream", nil)
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(0))
	ctx = context.WithValue(ctx, handler.UserNameKey, "USER1")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.HandleTunnelStream(w, req)

	body := w.Body.String()
	require.True(t, strings.HasPrefix(body, "data: "))

	var parsed []map[string]any
	dataPart := strings.TrimSpace(strings.TrimPrefix(body, "data: "))
	err := json.Unmarshal([]byte(dataPart), &parsed)
	require.NoError(t, err)
	assert.Len(t, parsed, 1)
	assert.Equal(t, "user1-tunnel", parsed[0]["TunnelName"])
}
