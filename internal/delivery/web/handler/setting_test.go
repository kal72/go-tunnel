package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotunnel/assets"
	"gotunnel/internal/delivery/web/handler"
	mockSetting "gotunnel/internal/usecase/setting/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandler_SettingsPage(t *testing.T) {
	mockSettingUsecase := new(mockSetting.MockSettingUsecase)
	h := handler.New(assets.EmbeddedFS, nil, nil, mockSettingUsecase, "sec", "addr", "wildcard", "gateway", false, 3, "v1.0.0", 100, nil)

	req := httptest.NewRequest(http.MethodGet, "/settings", http.NoBody)
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(1))
	ctx = context.WithValue(ctx, handler.UserNameKey, "admin")
	ctx = context.WithValue(ctx, handler.CSRFTokenKey, "csrf123")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.SettingsPage(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "System Settings")
}

func TestHandler_GetSettings(t *testing.T) {
	tests := []struct {
		name       string
		mockReturn map[string]string
		mockErr    error
		wantCode   int
	}{
		{
			name: "success get settings with empty defaults populated",
			mockReturn: map[string]string{
				"custom_key": "val",
			},
			mockErr:  nil,
			wantCode: http.StatusOK,
		},
		{
			name:       "error from setting usecase",
			mockReturn: nil,
			mockErr:    errors.New("db error"),
			wantCode:   http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSettingUsecase := new(mockSetting.MockSettingUsecase)
			h := handler.New(assets.EmbeddedFS, nil, nil, mockSettingUsecase, "sec", "addr", "wildcard", "gateway", false, 3, "v1.0.0", 100, nil)

			mockSettingUsecase.On("GetAllSettings", mock.Anything).Return(tt.mockReturn, tt.mockErr)

			req := httptest.NewRequest(http.MethodGet, "/api/settings", http.NoBody)
			rec := httptest.NewRecorder()
			h.GetSettings(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.wantCode == http.StatusOK {
				var resp map[string]interface{}
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				assert.NoError(t, err)
				settings := resp["settings"].(map[string]interface{})
				assert.Equal(t, "5", settings["max_free_domains"])
				assert.Equal(t, "true", settings["allow_registration"])
				assert.Equal(t, "val", settings["custom_key"])
			}
			mockSettingUsecase.AssertExpectations(t)
		})
	}
}

func TestHandler_UpdateSettings(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		mockSetup func(*mockSetting.MockSettingUsecase)
		wantCode  int
	}{
		{
			name: "success update settings",
			body: `{"settings":{"max_free_domains":"10","allow_registration":"false"}}`,
			mockSetup: func(m *mockSetting.MockSettingUsecase) {
				m.On("SetSetting", mock.Anything, "max_free_domains", "10").Return(nil)
				m.On("SetSetting", mock.Anything, "allow_registration", "false").Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "invalid json payload",
			body:      `invalid json`,
			mockSetup: func(m *mockSetting.MockSettingUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name: "error saving setting",
			body: `{"settings":{"max_free_domains":"10"}}`,
			mockSetup: func(m *mockSetting.MockSettingUsecase) {
				m.On("SetSetting", mock.Anything, "max_free_domains", "10").Return(errors.New("save error"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSettingUsecase := new(mockSetting.MockSettingUsecase)
			if tt.mockSetup != nil {
				tt.mockSetup(mockSettingUsecase)
			}
			h := handler.New(assets.EmbeddedFS, nil, nil, mockSettingUsecase, "sec", "addr", "wildcard", "gateway", false, 3, "v1.0.0", 100, nil)

			req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()
			h.UpdateSettings(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			mockSettingUsecase.AssertExpectations(t)
		})
	}
}
