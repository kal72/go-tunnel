package tunnel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	domainSetting "gotunnel/internal/domain/setting"
	"gotunnel/internal/shared/ratelimit"
	usecaseSettingMocks "gotunnel/internal/usecase/setting/mocks"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestServer_ServeHTTP_RateLimiting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		role               int16
		cfg                domainSetting.RateLimitConfig
		requests           int
		expectedStatusCode int
	}{
		{
			name: "user rate limited after burst",
			role: 0,
			cfg: domainSetting.RateLimitConfig{
				Enabled:      true,
				Rate:         1,
				Burst:        1,
				AdminAllowed: false,
			},
			requests:           2,
			expectedStatusCode: http.StatusTooManyRequests,
		},
		{
			name: "admin bypassed when AdminAllowed is false",
			role: 1,
			cfg: domainSetting.RateLimitConfig{
				Enabled:      true,
				Rate:         1,
				Burst:        1,
				AdminAllowed: false,
			},
			requests:           2,
			expectedStatusCode: http.StatusBadGateway, // hits open stream failure after bypassing rate limit
		},
		{
			name: "admin rate limited when AdminAllowed is true",
			role: 1,
			cfg: domainSetting.RateLimitConfig{
				Enabled:      true,
				Rate:         1,
				Burst:        1,
				AdminAllowed: true,
			},
			requests:           2,
			expectedStatusCode: http.StatusTooManyRequests,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockSetting := usecaseSettingMocks.NewMockSettingUsecase(t)
			mockSetting.On("GetRateLimitConfig", context.Background()).Return(tt.cfg)

			server := &Server{
				hostToSes:      map[string]*TunnelSession{},
				settingUsecase: mockSetting,
				limiter:        ratelimit.NewLimiter(),
			}

			server.hostToSes["test.example.com"] = &TunnelSession{
				Role: tt.role,
			}

			var lastCode int
			for i := 0; i < tt.requests; i++ {
				req := httptest.NewRequest(http.MethodGet, "http://test.example.com/", nil)
				req.Host = "test.example.com"
				req = req.WithContext(context.Background())
				w := httptest.NewRecorder()

				server.ServeHTTP(w, req)
				lastCode = w.Code
			}

			assert.Equal(t, tt.expectedStatusCode, lastCode)
		})
	}
}

func TestServer_UserRateLimitIsolation(t *testing.T) {
	t.Parallel()

	mockSetting := usecaseSettingMocks.NewMockSettingUsecase(t)
	mockSetting.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{
		Enabled:      false, // global disabled
		Rate:         1,
		Burst:        1,
		AdminAllowed: false,
	})
	mockSetting.On("GetSetting", mock.Anything, "rate_limit_enabled:usera").Return("true", nil)
	mockSetting.On("GetSetting", mock.Anything, "rate_limit_enabled:userb").Return("false", nil)

	server := &Server{
		hostToSes:      map[string]*TunnelSession{},
		settingUsecase: mockSetting,
		limiter:        ratelimit.NewLimiter(),
	}

	server.hostToSes["usera.example.com"] = &TunnelSession{
		Role:     0,
		Username: "usera",
	}
	server.hostToSes["userb.example.com"] = &TunnelSession{
		Role:     0,
		Username: "userb",
	}
	server.hostToSes["admin.example.com"] = &TunnelSession{
		Role:     1,
		Username: "admin",
	}

	// 1. User A exhausts their rate limit burst
	reqA1 := httptest.NewRequest(http.MethodGet, "http://usera.example.com/", nil)
	reqA1.Host = "usera.example.com"
	wA1 := httptest.NewRecorder()
	server.ServeHTTP(wA1, reqA1)
	assert.Equal(t, http.StatusBadGateway, wA1.Code) // first request allowed by limiter (hits open stream failure)

	reqA2 := httptest.NewRequest(http.MethodGet, "http://usera.example.com/", nil)
	reqA2.Host = "usera.example.com"
	wA2 := httptest.NewRecorder()
	server.ServeHTTP(wA2, reqA2)
	assert.Equal(t, http.StatusTooManyRequests, wA2.Code) // second request rate limited 429 for usera

	// 2. User B makes requests and is NOT impacted by User A's rate limit or toggle
	for i := 0; i < 3; i++ {
		reqB := httptest.NewRequest(http.MethodGet, "http://userb.example.com/", nil)
		reqB.Host = "userb.example.com"
		wB := httptest.NewRecorder()
		server.ServeHTTP(wB, reqB)
		assert.Equal(t, http.StatusBadGateway, wB.Code) // not 429
	}

	// 3. Admin makes requests and is NOT impacted by User A's rate limit
	for i := 0; i < 3; i++ {
		reqAdmin := httptest.NewRequest(http.MethodGet, "http://admin.example.com/", nil)
		reqAdmin.Host = "admin.example.com"
		wAdmin := httptest.NewRecorder()
		server.ServeHTTP(wAdmin, reqAdmin)
		assert.Equal(t, http.StatusBadGateway, wAdmin.Code) // not 429
	}
}

