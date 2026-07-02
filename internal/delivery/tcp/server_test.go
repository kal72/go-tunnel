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
