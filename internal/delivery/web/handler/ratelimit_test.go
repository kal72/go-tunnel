package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotunnel/assets"
	"gotunnel/internal/delivery/web/handler"
	mockSetting "gotunnel/internal/usecase/setting/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandler_RateLimitPage(t *testing.T) {
	mockSettingUsecase := new(mockSetting.MockSettingUsecase)
	h := handler.New(assets.EmbeddedFS, nil, nil, mockSettingUsecase, "sec", "addr", "wildcard", "gateway", false, 3, "v1.0.0", 100, nil)

	req := httptest.NewRequest(http.MethodGet, "/ratelimit", http.NoBody)
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(0))
	ctx = context.WithValue(ctx, handler.UserNameKey, "testuser")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.RateLimitPage(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Rate Limiting & Traffic Protection")
}

func TestHandler_GetRateLimit(t *testing.T) {
	mockSettingUsecase := new(mockSetting.MockSettingUsecase)
	h := handler.New(assets.EmbeddedFS, nil, nil, mockSettingUsecase, "sec", "addr", "wildcard", "gateway", false, 3, "v1.0.0", 100, nil)

	mockSettingUsecase.On("GetAllSettings", mock.Anything).Return(map[string]string{
		"rate_limit_enabled":          "true",
		"rate_limit_enabled:user123": "false",
		"rate_limit_rate":             "150",
		"rate_limit_burst":            "30",
	}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/ratelimit", http.NoBody)
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(0))
	ctx = context.WithValue(ctx, handler.UserNameKey, "user123")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.GetRateLimit(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.NoError(t, err)
	cfg := resp["config"].(map[string]interface{})
	assert.Equal(t, false, cfg["enabled"])
	assert.Equal(t, "150", cfg["rate"])
}

func TestHandler_UpdateRateLimit_RegularUser(t *testing.T) {
	mockSettingUsecase := new(mockSetting.MockSettingUsecase)
	h := handler.New(assets.EmbeddedFS, nil, nil, mockSettingUsecase, "sec", "addr", "wildcard", "gateway", false, 3, "v1.0.0", 100, nil)

	mockSettingUsecase.On("SetSetting", mock.Anything, "rate_limit_enabled:user123", "false").Return(nil)

	payload := `{"config":{"enabled":false,"rate":500,"burst":100}}`
	req := httptest.NewRequest(http.MethodPut, "/api/ratelimit", bytes.NewBufferString(payload))
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(0))
	ctx = context.WithValue(ctx, handler.UserNameKey, "user123")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.UpdateRateLimit(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSettingUsecase.AssertExpectations(t)
}

func TestHandler_UpdateRateLimit_AdminUser(t *testing.T) {
	mockSettingUsecase := new(mockSetting.MockSettingUsecase)
	h := handler.New(assets.EmbeddedFS, nil, nil, mockSettingUsecase, "sec", "addr", "wildcard", "gateway", false, 3, "v1.0.0", 100, nil)

	mockSettingUsecase.On("SetSetting", mock.Anything, "rate_limit_enabled", "true").Return(nil)
	mockSettingUsecase.On("SetSetting", mock.Anything, "rate_limit_rate", "250").Return(nil)
	mockSettingUsecase.On("SetSetting", mock.Anything, "rate_limit_burst", "50").Return(nil)
	mockSettingUsecase.On("SetSetting", mock.Anything, "rate_limit_admin_allowed", "true").Return(nil)

	payload := `{"config":{"enabled":true,"rate":250,"burst":50,"admin_allowed":true}}`
	req := httptest.NewRequest(http.MethodPut, "/api/ratelimit", bytes.NewBufferString(payload))
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(1))
	ctx = context.WithValue(ctx, handler.UserNameKey, "admin")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.UpdateRateLimit(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockSettingUsecase.AssertExpectations(t)
}
