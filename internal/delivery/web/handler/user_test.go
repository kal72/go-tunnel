package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotunnel/internal/delivery/web/handler"
	domainUser "gotunnel/internal/domain/user"
	mockSetting "gotunnel/internal/usecase/setting/mocks"
	mockUser "gotunnel/internal/usecase/user/mocks"
	webassets "gotunnel/web"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestUserHandler_AdminMiddleware(t *testing.T) {
	tests := []struct {
		name     string
		role     interface{}
		wantCode int
	}{
		{
			name:     "admin allowed",
			role:     int16(1),
			wantCode: http.StatusOK,
		},
		{
			name:     "regular user forbidden",
			role:     int16(0),
			wantCode: http.StatusForbidden,
		},
		{
			name:     "missing role context forbidden",
			role:     nil,
			wantCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			mw := handler.AdminMiddleware(dummyHandler)

			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			if tt.role != nil {
				ctx := context.WithValue(req.Context(), handler.UserRoleKey, tt.role)
				req = req.WithContext(ctx)
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
		})
	}
}

func TestUserHandler_UsersPage(t *testing.T) {
	mockAuth := new(mockUser.MockAuthUsecase)
	mockSetting := new(mockSetting.MockSettingUsecase)
	h := handler.NewUserHandler(webassets.EmbeddedFS, mockAuth, mockSetting)

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	ctx := context.WithValue(req.Context(), handler.UserRoleKey, int16(1))
	ctx = context.WithValue(ctx, handler.UserNameKey, "admin")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.UsersPage(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "System Users")
}

func TestUserHandler_ListUsers(t *testing.T) {
	tests := []struct {
		name       string
		mockReturn []domainUser.User
		mockErr    error
		wantCode   int
	}{
		{
			name: "success list users hiding password",
			mockReturn: []domainUser.User{
				{ID: uuid.New(), Username: "user1", Password: "hashedpassword", Role: 0},
			},
			mockErr:  nil,
			wantCode: http.StatusOK,
		},
		{
			name:       "error listing users",
			mockReturn: nil,
			mockErr:    errors.New("db error"),
			wantCode:   http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(mockUser.MockAuthUsecase)
			mockAuth.On("ListUsers", mock.Anything).Return(tt.mockReturn, tt.mockErr)

			h := handler.NewUserHandler(webassets.EmbeddedFS, mockAuth, nil)

			req := httptest.NewRequest(http.MethodGet, "/api/users", http.NoBody)
			rec := httptest.NewRecorder()
			h.ListUsers(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			if tt.wantCode == http.StatusOK {
				var users []domainUser.User
				err := json.Unmarshal(rec.Body.Bytes(), &users)
				assert.NoError(t, err)
				assert.Len(t, users, 1)
				assert.Empty(t, users[0].Password)
			}
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestUserHandler_CreateUser(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		mockSetup func(*mockUser.MockAuthUsecase, *mockSetting.MockSettingUsecase)
		wantCode  int
	}{
		{
			name: "success create admin user without rate limit setting call",
			body: `{"username":"admin2","password":"sec","role":1}`,
			mockSetup: func(ma *mockUser.MockAuthUsecase, ms *mockSetting.MockSettingUsecase) {
				ma.On("CreateUser", mock.Anything, "admin2", "sec", int16(1)).Return(nil)
			},
			wantCode: http.StatusCreated,
		},
		{
			name: "success create regular user initializes rate limit false",
			body: `{"username":"user1","password":"sec","role":0}`,
			mockSetup: func(ma *mockUser.MockAuthUsecase, ms *mockSetting.MockSettingUsecase) {
				ma.On("CreateUser", mock.Anything, "user1", "sec", int16(0)).Return(nil)
				ms.On("SetSetting", mock.Anything, "rate_limit_enabled:user1", "false").Return(nil)
			},
			wantCode: http.StatusCreated,
		},
		{
			name:      "invalid json",
			body:      `invalid json`,
			mockSetup: func(ma *mockUser.MockAuthUsecase, ms *mockSetting.MockSettingUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "missing username or password",
			body:      `{"username":"","password":"sec"}`,
			mockSetup: func(ma *mockUser.MockAuthUsecase, ms *mockSetting.MockSettingUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name: "create user failure",
			body: `{"username":"user1","password":"sec","role":0}`,
			mockSetup: func(ma *mockUser.MockAuthUsecase, ms *mockSetting.MockSettingUsecase) {
				ma.On("CreateUser", mock.Anything, "user1", "sec", int16(0)).Return(errors.New("create error"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(mockUser.MockAuthUsecase)
			mockSet := new(mockSetting.MockSettingUsecase)
			if tt.mockSetup != nil {
				tt.mockSetup(mockAuth, mockSet)
			}
			h := handler.NewUserHandler(webassets.EmbeddedFS, mockAuth, mockSet)

			req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBufferString(tt.body))
			rec := httptest.NewRecorder()
			h.CreateUser(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			mockAuth.AssertExpectations(t)
			mockSet.AssertExpectations(t)
		})
	}
}

func TestUserHandler_UpdateStatus(t *testing.T) {
	testID := uuid.New()
	tests := []struct {
		name      string
		idParam   string
		body      string
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:    "success update status",
			idParam: testID.String(),
			body:    `{"status":0}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("UpdateUserStatus", mock.Anything, testID, int16(0)).Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "invalid uuid",
			idParam:   "not-a-uuid",
			body:      `{"status":0}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "invalid json",
			idParam:   testID.String(),
			body:      `invalid`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:    "update status error",
			idParam: testID.String(),
			body:    `{"status":0}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("UpdateUserStatus", mock.Anything, testID, int16(0)).Return(errors.New("err"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(mockUser.MockAuthUsecase)
			if tt.mockSetup != nil {
				tt.mockSetup(mockAuth)
			}
			h := handler.NewUserHandler(webassets.EmbeddedFS, mockAuth, nil)

			req := httptest.NewRequest(http.MethodPut, "/api/users/"+tt.idParam+"/status", bytes.NewBufferString(tt.body))
			req = setURLParam(req, "id", tt.idParam)
			rec := httptest.NewRecorder()
			h.UpdateStatus(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestUserHandler_UpdatePassword(t *testing.T) {
	testID := uuid.New()
	tests := []struct {
		name      string
		idParam   string
		body      string
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:    "success update password",
			idParam: testID.String(),
			body:    `{"password":"newpassword"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("UpdateUserPassword", mock.Anything, testID, "newpassword").Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "invalid uuid",
			idParam:   "not-a-uuid",
			body:      `{"password":"newpassword"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "missing password",
			idParam:   testID.String(),
			body:      `{"password":""}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:    "update password error",
			idParam: testID.String(),
			body:    `{"password":"newpassword"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("UpdateUserPassword", mock.Anything, testID, "newpassword").Return(errors.New("err"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(mockUser.MockAuthUsecase)
			if tt.mockSetup != nil {
				tt.mockSetup(mockAuth)
			}
			h := handler.NewUserHandler(webassets.EmbeddedFS, mockAuth, nil)

			req := httptest.NewRequest(http.MethodPut, "/api/users/"+tt.idParam+"/password", bytes.NewBufferString(tt.body))
			req = setURLParam(req, "id", tt.idParam)
			rec := httptest.NewRecorder()
			h.UpdatePassword(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestUserHandler_DeleteUser(t *testing.T) {
	testID := uuid.New()
	tests := []struct {
		name      string
		idParam   string
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:    "success delete user",
			idParam: testID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("DeleteUser", mock.Anything, testID).Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "invalid uuid",
			idParam:   "bad-uuid",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:    "delete error",
			idParam: testID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("DeleteUser", mock.Anything, testID).Return(errors.New("err"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(mockUser.MockAuthUsecase)
			if tt.mockSetup != nil {
				tt.mockSetup(mockAuth)
			}
			h := handler.NewUserHandler(webassets.EmbeddedFS, mockAuth, nil)

			req := httptest.NewRequest(http.MethodDelete, "/api/users/"+tt.idParam, http.NoBody)
			req = setURLParam(req, "id", tt.idParam)
			rec := httptest.NewRecorder()
			h.DeleteUser(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestUserHandler_RevokeTokens(t *testing.T) {
	testID := uuid.New()
	tests := []struct {
		name      string
		idParam   string
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:    "success revoke tokens",
			idParam: testID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("RevokeUserTokens", mock.Anything, testID).Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "invalid uuid",
			idParam:   "bad-uuid",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:    "revoke error",
			idParam: testID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("RevokeUserTokens", mock.Anything, testID).Return(errors.New("err"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(mockUser.MockAuthUsecase)
			if tt.mockSetup != nil {
				tt.mockSetup(mockAuth)
			}
			h := handler.NewUserHandler(webassets.EmbeddedFS, mockAuth, nil)

			req := httptest.NewRequest(http.MethodPost, "/api/users/"+tt.idParam+"/revoke-tokens", http.NoBody)
			req = setURLParam(req, "id", tt.idParam)
			rec := httptest.NewRecorder()
			h.RevokeTokens(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)
			mockAuth.AssertExpectations(t)
		})
	}
}
