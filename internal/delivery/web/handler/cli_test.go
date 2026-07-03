package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotunnel/internal/delivery/web/dto"
	"gotunnel/internal/delivery/web/handler"
	domainConfig "gotunnel/internal/domain/config"
	mockConfig "gotunnel/internal/usecase/config/mocks"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setCLIURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	if key != "" {
		rctx.URLParams.Add(key, val)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestNewCLIHandler(t *testing.T) {
	mockUC := new(mockConfig.MockConfigUsecase)
	h := handler.NewCLIHandler(mockUC, "tunnel.example.com", true, "v1.1.0")
	assert.NotNil(t, h)
}

func TestCLIHandler_ClientGetConfigs(t *testing.T) {
	testID := uuid.New()
	tests := []struct {
		name       string
		userID     string
		mockReturn []domainConfig.ClientConfig
		mockErr    error
		wantCode   int
	}{
		{
			name:   "success get configs",
			userID: testID.String(),
			mockReturn: []domainConfig.ClientConfig{
				{ID: uuid.New(), Name: "default-config"},
			},
			mockErr:  nil,
			wantCode: http.StatusOK,
		},
		{
			name:       "error from usecase",
			userID:     testID.String(),
			mockReturn: nil,
			mockErr:    errors.New("db error"),
			wantCode:   http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockConfig.MockConfigUsecase)
			mockUC.On("GetConfigsByUserID", mock.Anything, testID).Return(tt.mockReturn, tt.mockErr)

			h := handler.NewCLIHandler(mockUC, "tunnel.example.com", true, "v1.1.0")

			req := httptest.NewRequest(http.MethodGet, "/api/cli/configs", http.NoBody)
			ctx := context.WithValue(req.Context(), handler.UserIDKey, tt.userID)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			h.ClientGetConfigs(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.wantCode == http.StatusOK {
				var res []map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Len(t, res, 1)
				assert.Equal(t, "default-config", res[0]["name"])
			}
			mockUC.AssertExpectations(t)
		})
	}
}

func TestCLIHandler_ClientGetConfig(t *testing.T) {
	testID := uuid.New()
	cfgID := uuid.New()

	tests := []struct {
		name       string
		paramName  string
		acmeEnable bool
		mockSetup  func(*mockConfig.MockConfigUsecase)
		wantCode   int
	}{
		{
			name:       "missing name param",
			paramName:  "",
			acmeEnable: true,
			mockSetup:  func(m *mockConfig.MockConfigUsecase) {},
			wantCode:   http.StatusBadRequest,
		},
		{
			name:       "error from get config by name",
			paramName:  "my-cfg",
			acmeEnable: true,
			mockSetup: func(m *mockConfig.MockConfigUsecase) {
				m.On("GetConfigByName", mock.Anything, testID, "my-cfg").Return(nil, errors.New("db error"))
			},
			wantCode: http.StatusInternalServerError,
		},
		{
			name:       "config not found",
			paramName:  "my-cfg",
			acmeEnable: true,
			mockSetup: func(m *mockConfig.MockConfigUsecase) {
				m.On("GetConfigByName", mock.Anything, testID, "my-cfg").Return(nil, nil)
			},
			wantCode: http.StatusNotFound,
		},
		{
			name:       "success get config with acme enable true",
			paramName:  "my-cfg",
			acmeEnable: true,
			mockSetup: func(m *mockConfig.MockConfigUsecase) {
				m.On("GetConfigByName", mock.Anything, testID, "my-cfg").Return(&domainConfig.ClientConfig{
					ID:   cfgID,
					Name: "my-cfg",
				}, nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:       "success get config with acme enable false",
			paramName:  "my-cfg",
			acmeEnable: false,
			mockSetup: func(m *mockConfig.MockConfigUsecase) {
				m.On("GetConfigByName", mock.Anything, testID, "my-cfg").Return(&domainConfig.ClientConfig{
					ID:   cfgID,
					Name: "my-cfg",
				}, nil)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockConfig.MockConfigUsecase)
			tt.mockSetup(mockUC)

			h := handler.NewCLIHandler(mockUC, "tunnel.example.com", tt.acmeEnable, "v1.1.0")

			req := httptest.NewRequest(http.MethodGet, "/api/cli/configs/my-cfg", http.NoBody)
			if tt.paramName != "" {
				req = setCLIURLParam(req, "name", tt.paramName)
			} else {
				req = setCLIURLParam(req, "", "")
			}
			ctx := context.WithValue(req.Context(), handler.UserIDKey, testID.String())
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			h.ClientGetConfig(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.wantCode == http.StatusOK {
				var res dto.ClientConfigDTO
				err := json.Unmarshal(rec.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "tunnel.example.com", res.TunnelAddr)
				assert.Equal(t, !tt.acmeEnable, res.SkipTLSVerify)
				assert.Equal(t, cfgID.String(), res.ClientID)
				assert.Equal(t, "my-cfg", res.ClientName)
			}
			mockUC.AssertExpectations(t)
		})
	}
}

func TestCLIHandler_ClientGetVersion(t *testing.T) {
	h := handler.NewCLIHandler(nil, "tunnel.example.com", true, "v1.2.3")

	req := httptest.NewRequest(http.MethodGet, "/api/cli/version", http.NoBody)
	rec := httptest.NewRecorder()
	h.ClientGetVersion(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var res map[string]string
	err := json.Unmarshal(rec.Body.Bytes(), &res)
	assert.NoError(t, err)
	assert.Equal(t, "v1.2.3", res["version"])
	assert.Equal(t, "/dl/gotunnel-{os}-{arch}", res["download_url"])
}
