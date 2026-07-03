package handler_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gotunnel/assets"
	"gotunnel/internal/delivery/web/handler"
	domainErrors "gotunnel/internal/domain/errors"
	domainUser "gotunnel/internal/domain/user"
	mockUser "gotunnel/internal/usecase/user/mocks"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewAuth(t *testing.T) {
	mockUC := new(mockUser.MockAuthUsecase)
	h := handler.NewAuth(assets.EmbeddedFS, mockUC)
	assert.NotNil(t, h)
}

func TestAuthHandler_LoginPage(t *testing.T) {
	mockUC := new(mockUser.MockAuthUsecase)
	h := handler.NewAuth(assets.EmbeddedFS, mockUC)

	req := httptest.NewRequest(http.MethodGet, "/login", http.NoBody)
	rec := httptest.NewRecorder()
	h.LoginPage(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Real-time Web UI")
}

func TestAuthHandler_Login(t *testing.T) {
	tests := []struct {
		name      string
		form      url.Values
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
		checkBody bool
	}{
		{
			name: "login failure returns error message on login page",
			form: url.Values{"username": {"bad"}, "password": {"bad"}},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("Login", mock.Anything, "bad", "bad").Return("", errors.New("invalid"))
			},
			wantCode:  http.StatusOK,
			checkBody: true,
		},
		{
			name: "login success redirects and sets cookie",
			form: url.Values{"username": {"user"}, "password": {"pass"}},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("Login", mock.Anything, "user", "pass").Return("token-123", nil)
				m.On("GetWebExpireDuration").Return(24 * time.Hour)
			},
			wantCode:  http.StatusSeeOther,
			checkBody: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			tt.mockSetup(mockUC)
			h := handler.NewAuth(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			h.Login(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.checkBody {
				assert.Contains(t, rec.Body.String(), "Invalid username or password")
			} else {
				assert.Equal(t, "/", rec.Header().Get("Location"))
				cookies := rec.Result().Cookies()
				var found bool
				for _, c := range cookies {
					if c.Name == "tunnel_token" && c.Value == "token-123" {
						found = true
						assert.True(t, c.HttpOnly)
						assert.True(t, c.Secure)
					}
				}
				assert.True(t, found)
			}
			mockUC.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Logout(t *testing.T) {
	tests := []struct {
		name      string
		cookie    *http.Cookie
		mockSetup func(*mockUser.MockAuthUsecase)
	}{
		{
			name:   "logout with cookie present",
			cookie: &http.Cookie{Name: "tunnel_token", Value: "token-123"},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("Logout", mock.Anything, "token-123").Return(nil)
			},
		},
		{
			name:      "logout without cookie present",
			cookie:    nil,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			tt.mockSetup(mockUC)
			h := handler.NewAuth(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(http.MethodGet, "/logout", http.NoBody)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			rec := httptest.NewRecorder()

			h.Logout(rec, req)

			assert.Equal(t, http.StatusSeeOther, rec.Code)
			assert.Equal(t, "/login", rec.Header().Get("Location"))
			mockUC.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_JWTMiddleware(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(handler.UserRoleKey).(int16)
		username, _ := r.Context().Value(handler.UserNameKey).(string)
		id, _ := r.Context().Value(handler.UserIDKey).(string)
		csrf, _ := r.Context().Value(handler.CSRFTokenKey).(string)

		w.Header().Set("X-Test-Role", string(rune(role+'0')))
		w.Header().Set("X-Test-User", username)
		w.Header().Set("X-Test-ID", id)
		w.Header().Set("X-Test-CSRF", csrf)
		w.WriteHeader(http.StatusOK)
	})

	testUser := &domainUser.User{
		ID:        uuid.New(),
		Username:  "john",
		Role:      1,
		CSRFToken: "csrf-999",
	}

	tests := []struct {
		name      string
		path      string
		authHdr   string
		cookie    *http.Cookie
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:      "allow login path",
			path:      "/login",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusOK,
		},
		{
			name:      "allow static path",
			path:      "/static/app.css",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusOK,
		},
		{
			name:      "missing token on api returns 401",
			path:      "/api/tunnels",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusUnauthorized,
		},
		{
			name:      "missing token on web redirects to login",
			path:      "/dashboard",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusSeeOther,
		},
		{
			name:    "verify error on api returns 401",
			path:    "/api/tunnels",
			authHdr: "Bearer bad-token",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("VerifyToken", mock.Anything, "bad-token").Return(nil, errors.New("expired"))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:    "verify error on web redirects to login",
			path:    "/dashboard",
			cookie:  &http.Cookie{Name: "tunnel_token", Value: "bad-token"},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("VerifyToken", mock.Anything, "bad-token").Return(nil, errors.New("expired"))
			},
			wantCode: http.StatusSeeOther,
		},
		{
			name:    "success verify token via authorization header",
			path:    "/api/tunnels",
			authHdr: "Bearer valid-token",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("VerifyToken", mock.Anything, "valid-token").Return(testUser, nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "success verify token via cookie fallback",
			path:   "/dashboard",
			cookie: &http.Cookie{Name: "tunnel_token", Value: "valid-token"},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("VerifyToken", mock.Anything, "valid-token").Return(testUser, nil)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			if tt.mockSetup != nil {
				tt.mockSetup(mockUC)
			}
			h := handler.NewAuth(assets.EmbeddedFS, mockUC)
			mw := h.JWTMiddleware(dummyHandler)

			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			if tt.authHdr != "" {
				req.Header.Set("Authorization", tt.authHdr)
			}
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.wantCode == http.StatusOK && tt.authHdr == "Bearer valid-token" {
				assert.Equal(t, "JOHN", rec.Header().Get("X-Test-User"))
				assert.Equal(t, "csrf-999", rec.Header().Get("X-Test-CSRF"))
			}
			mockUC.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_APILogin(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		form      url.Values
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:      "get method not allowed",
			method:    http.MethodGet,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusMethodNotAllowed,
		},
		{
			name:   "unauthorized error returns 401",
			method: http.MethodPost,
			form:   url.Values{"username": {"user"}, "password": {"wrong"}},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("LoginCLI", mock.Anything, "user", "wrong").Return("", domainErrors.ErrUnauthorized)
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:   "other error returns 500",
			method: http.MethodPost,
			form:   url.Values{"username": {"user"}, "password": {"pass"}},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("LoginCLI", mock.Anything, "user", "pass").Return("", errors.New("internal"))
			},
			wantCode: http.StatusInternalServerError,
		},
		{
			name:   "success returns token json",
			method: http.MethodPost,
			form:   url.Values{"username": {"user"}, "password": {"pass"}},
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("LoginCLI", mock.Anything, "user", "pass").Return("cli-jwt-token", nil)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			tt.mockSetup(mockUC)
			h := handler.NewAuth(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(tt.method, "/api/login", strings.NewReader(tt.form.Encode()))
			if tt.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rec := httptest.NewRecorder()
			h.APILogin(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.wantCode == http.StatusOK {
				var res map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &res)
				assert.NoError(t, err)
				assert.Equal(t, "cli-jwt-token", res["token"])
			}
			mockUC.AssertExpectations(t)
		})
	}
}
