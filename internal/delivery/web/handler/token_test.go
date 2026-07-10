package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotunnel/assets"
	"gotunnel/internal/delivery/web/handler"
	"gotunnel/internal/domain/apikey"
	domainErrors "gotunnel/internal/domain/errors"
	mockUser "gotunnel/internal/usecase/user/mocks"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setTokenURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestNewToken(t *testing.T) {
	mockUC := new(mockUser.MockAuthUsecase)
	h := handler.NewToken(assets.EmbeddedFS, mockUC)
	assert.NotNil(t, h)
}

func TestTokenHandler_TokensPage(t *testing.T) {
	tests := []struct {
		name     string
		role     int16
		username string
	}{
		{
			name:     "regular user can access tokens page",
			role:     0,
			username: "user1",
		},
		{
			name:     "admin can access tokens page",
			role:     1,
			username: "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			h := handler.NewToken(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(http.MethodGet, "/tokens", http.NoBody)
			ctx := context.WithValue(req.Context(), handler.UserRoleKey, tt.role)
			ctx = context.WithValue(ctx, handler.UserNameKey, tt.username)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			h.TokensPage(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Body.String(), "API Keys")
		})
	}
}

func TestTokenHandler_ListTokens(t *testing.T) {
	testUserID := uuid.New()
	testKeyID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	tests := []struct {
		name       string
		userID     string
		role       int16
		query      string
		mockSetup  func(*mockUser.MockAuthUsecase)
		wantCode   int
		wantTotal  int
		wantLimit  int
		wantOffset int
	}{
		{
			name:   "regular user lists own tokens with default pagination",
			userID: testUserID.String(),
			role:   0,
			query:  "",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				keys := []apikey.APIKeyWithOwner{
					{
						APIKey: apikey.APIKey{
							ID:        testKeyID,
							UserID:    testUserID,
							Name:      "my-key",
							Status:    apikey.StatusActive,
							CreatedAt: now,
							ExpiresAt: &expiresAt,
						},
						Username: "user1",
					},
				}
				m.On("ListAPIKeys", mock.Anything, testUserID, int16(0), 50, 0, "").
					Return(keys, 1, nil)
			},
			wantCode:   http.StatusOK,
			wantTotal:  1,
			wantLimit:  50,
			wantOffset: 0,
		},
		{
			name:   "regular user lists tokens with custom pagination",
			userID: testUserID.String(),
			role:   0,
			query:  "?limit=10&offset=5",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("ListAPIKeys", mock.Anything, testUserID, int16(0), 10, 5, "").
					Return([]apikey.APIKeyWithOwner{}, 0, nil)
			},
			wantCode:   http.StatusOK,
			wantTotal:  0,
			wantLimit:  10,
			wantOffset: 5,
		},
		{
			name:   "admin lists all tokens with username filter",
			userID: testUserID.String(),
			role:   1,
			query:  "?username=john",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("ListAPIKeys", mock.Anything, testUserID, int16(1), 50, 0, "john").
					Return([]apikey.APIKeyWithOwner{}, 0, nil)
			},
			wantCode:   http.StatusOK,
			wantTotal:  0,
			wantLimit:  50,
			wantOffset: 0,
		},
		{
			name:   "username filter ignored for regular user",
			userID: testUserID.String(),
			role:   0,
			query:  "?username=john",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				// Regular users (role=0) should have empty username filter
				m.On("ListAPIKeys", mock.Anything, testUserID, int16(0), 50, 0, "").
					Return([]apikey.APIKeyWithOwner{}, 0, nil)
			},
			wantCode:   http.StatusOK,
			wantTotal:  0,
			wantLimit:  50,
			wantOffset: 0,
		},
		{
			name:   "limit capped at 100",
			userID: testUserID.String(),
			role:   0,
			query:  "?limit=200",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				// Limit > 100 should use default 50
				m.On("ListAPIKeys", mock.Anything, testUserID, int16(0), 50, 0, "").
					Return([]apikey.APIKeyWithOwner{}, 0, nil)
			},
			wantCode:   http.StatusOK,
			wantTotal:  0,
			wantLimit:  50,
			wantOffset: 0,
		},
		{
			name:   "usecase error returns 500",
			userID: testUserID.String(),
			role:   0,
			query:  "",
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("ListAPIKeys", mock.Anything, testUserID, int16(0), 50, 0, "").
					Return(nil, 0, errors.New("db error"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			tt.mockSetup(mockUC)
			h := handler.NewToken(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(http.MethodGet, "/api/tokens"+tt.query, http.NoBody)
			ctx := context.WithValue(req.Context(), handler.UserIDKey, tt.userID)
			ctx = context.WithValue(ctx, handler.UserRoleKey, tt.role)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			h.ListTokens(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)

			if tt.wantCode == http.StatusOK {
				var resp map[string]any
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Equal(t, float64(tt.wantTotal), resp["total"])
				assert.Equal(t, float64(tt.wantLimit), resp["limit"])
				assert.Equal(t, float64(tt.wantOffset), resp["offset"])
			}

			mockUC.AssertExpectations(t)
		})
	}
}

func TestTokenHandler_CreateToken(t *testing.T) {
	testUserID := uuid.New()
	testKeyID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	tests := []struct {
		name      string
		userID    string
		body      string
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
		wantKey   bool
	}{
		{
			name:   "success create token without expiration",
			userID: testUserID.String(),
			body:   `{"name":"my-api-key"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				key := &apikey.APIKey{
					ID:        testKeyID,
					UserID:    testUserID,
					Name:      "my-api-key",
					Status:    apikey.StatusActive,
					CreatedAt: now,
				}
				m.On("CreateAPIKey", mock.Anything, testUserID, "my-api-key", (*time.Time)(nil)).
					Return("gtk_testplaintext123", key, nil)
			},
			wantCode: http.StatusCreated,
			wantKey:  true,
		},
		{
			name:   "success create token with expiration",
			userID: testUserID.String(),
			body:   `{"name":"my-api-key","expires_at":"` + expiresAt.Format(time.RFC3339) + `"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				key := &apikey.APIKey{
					ID:        testKeyID,
					UserID:    testUserID,
					Name:      "my-api-key",
					Status:    apikey.StatusActive,
					CreatedAt: now,
					ExpiresAt: &expiresAt,
				}
				m.On("CreateAPIKey", mock.Anything, testUserID, "my-api-key", mock.AnythingOfType("*time.Time")).
					Return("gtk_testplaintext123", key, nil)
			},
			wantCode: http.StatusCreated,
			wantKey:  true,
		},
		{
			name:      "invalid json body",
			userID:    testUserID.String(),
			body:      `invalid json`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:      "invalid expires_at format",
			userID:    testUserID.String(),
			body:      `{"name":"my-key","expires_at":"not-a-date"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:   "duplicate name error returns 409",
			userID: testUserID.String(),
			body:   `{"name":"existing-key"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("CreateAPIKey", mock.Anything, testUserID, "existing-key", (*time.Time)(nil)).
					Return("", nil, domainErrors.ErrAlreadyExists)
			},
			wantCode: http.StatusConflict,
		},
		{
			name:   "validation error returns 400",
			userID: testUserID.String(),
			body:   `{"name":""}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("CreateAPIKey", mock.Anything, testUserID, "", (*time.Time)(nil)).
					Return("", nil, errors.New("name is required"))
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:   "max keys error returns 400",
			userID: testUserID.String(),
			body:   `{"name":"new-key"}`,
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("CreateAPIKey", mock.Anything, testUserID, "new-key", (*time.Time)(nil)).
					Return("", nil, errors.New("maximum of 10 active API keys reached"))
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			tt.mockSetup(mockUC)
			h := handler.NewToken(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(tt.body))
			ctx := context.WithValue(req.Context(), handler.UserIDKey, tt.userID)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			h.CreateToken(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)

			if tt.wantKey {
				var resp map[string]any
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Equal(t, "gtk_testplaintext123", resp["key"])
				assert.Equal(t, testKeyID.String(), resp["id"])
				assert.Equal(t, "my-api-key", resp["name"])
			}

			mockUC.AssertExpectations(t)
		})
	}
}

func TestTokenHandler_RevokeToken(t *testing.T) {
	testUserID := uuid.New()
	testKeyID := uuid.New()

	tests := []struct {
		name      string
		userID    string
		role      int16
		keyID     string
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:   "success revoke own token",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("RevokeAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "admin success revoke any token",
			userID: testUserID.String(),
			role:   1,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("RevokeAPIKey", mock.Anything, testKeyID, testUserID, int16(1)).
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "invalid key ID format",
			userID:    testUserID.String(),
			role:      0,
			keyID:     "not-a-uuid",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:   "key not found returns 404",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("RevokeAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(domainErrors.ErrNotFound)
			},
			wantCode: http.StatusNotFound,
		},
		{
			name:   "forbidden returns 403",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("RevokeAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(domainErrors.ErrForbidden)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name:   "internal error returns 500",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("RevokeAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(errors.New("db error"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			tt.mockSetup(mockUC)
			h := handler.NewToken(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(http.MethodDelete, "/api/tokens/"+tt.keyID, http.NoBody)
			ctx := context.WithValue(req.Context(), handler.UserIDKey, tt.userID)
			ctx = context.WithValue(ctx, handler.UserRoleKey, tt.role)
			req = req.WithContext(ctx)
			req = setTokenURLParam(req, "id", tt.keyID)

			rec := httptest.NewRecorder()
			h.RevokeToken(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)

			if tt.wantCode == http.StatusOK {
				var resp map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Contains(t, resp["message"], "revoked")
			}

			mockUC.AssertExpectations(t)
		})
	}
}

func TestTokenHandler_DeleteToken(t *testing.T) {
	testUserID := uuid.New()
	testKeyID := uuid.New()

	tests := []struct {
		name      string
		userID    string
		role      int16
		keyID     string
		mockSetup func(*mockUser.MockAuthUsecase)
		wantCode  int
	}{
		{
			name:   "success delete own token",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("DeleteAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:   "admin success delete any token",
			userID: testUserID.String(),
			role:   1,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("DeleteAPIKey", mock.Anything, testKeyID, testUserID, int16(1)).
					Return(nil)
			},
			wantCode: http.StatusOK,
		},
		{
			name:      "invalid key ID format",
			userID:    testUserID.String(),
			role:      0,
			keyID:     "not-a-uuid",
			mockSetup: func(m *mockUser.MockAuthUsecase) {},
			wantCode:  http.StatusBadRequest,
		},
		{
			name:   "key not found returns 404",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("DeleteAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(domainErrors.ErrNotFound)
			},
			wantCode: http.StatusNotFound,
		},
		{
			name:   "forbidden returns 403",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("DeleteAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(domainErrors.ErrForbidden)
			},
			wantCode: http.StatusForbidden,
		},
		{
			name:   "internal error returns 500",
			userID: testUserID.String(),
			role:   0,
			keyID:  testKeyID.String(),
			mockSetup: func(m *mockUser.MockAuthUsecase) {
				m.On("DeleteAPIKey", mock.Anything, testKeyID, testUserID, int16(0)).
					Return(errors.New("db error"))
			},
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUC := new(mockUser.MockAuthUsecase)
			tt.mockSetup(mockUC)
			h := handler.NewToken(assets.EmbeddedFS, mockUC)

			req := httptest.NewRequest(http.MethodDelete, "/api/tokens/"+tt.keyID, http.NoBody)
			ctx := context.WithValue(req.Context(), handler.UserIDKey, tt.userID)
			ctx = context.WithValue(ctx, handler.UserRoleKey, tt.role)
			req = req.WithContext(ctx)
			req = setTokenURLParam(req, "id", tt.keyID)

			rec := httptest.NewRecorder()
			h.DeleteToken(rec, req)

			assert.Equal(t, tt.wantCode, rec.Code)

			if tt.wantCode == http.StatusOK {
				var resp map[string]string
				err := json.Unmarshal(rec.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Contains(t, resp["message"], "deleted")
			}

			mockUC.AssertExpectations(t)
		})
	}
}
