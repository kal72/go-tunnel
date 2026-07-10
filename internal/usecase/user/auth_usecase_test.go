package user

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	domainAPIKey "gotunnel/internal/domain/apikey"
	apikeyMocks "gotunnel/internal/domain/apikey/mocks"
	domainErrors "gotunnel/internal/domain/errors"
	tunnelMocks "gotunnel/internal/domain/tunnel/mocks"
	domainUser "gotunnel/internal/domain/user"
	userMocks "gotunnel/internal/domain/user/mocks"
	util "gotunnel/internal/shared/crypto"
)

func TestNewAuthUsecase(t *testing.T) {
	t.Parallel()

	userRepo := userMocks.NewMockUserRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 0, -1)
	assert.Equal(t, 24*time.Hour, uc.GetWebExpireDuration())
}

func TestAuthUsecase_Login_and_LoginCLI(t *testing.T) {
	t.Parallel()

	password := "mypassword"
	hashedPassword, err := util.HashPassword(password)
	require.NoError(t, err)

	userID := uuid.New()
	validUser := &domainUser.User{
		ID:       userID,
		Username: "admin",
		Password: hashedPassword,
		Role:     1,
		Status:   1,
	}

	tests := []struct {
		name      string
		isCLI     bool
		username  string
		password  string
		mockSetup func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   error
	}{
		{
			name:     "success login web",
			isCLI:    false,
			username: "admin",
			password: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(validUser, nil).Once()
				tunnelStore.On("SetToken", mock.Anything, validUser.ID.String(), mock.AnythingOfType("string"), 24*time.Hour).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name:     "success login cli",
			isCLI:    true,
			username: "admin",
			password: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(validUser, nil).Once()
				tunnelStore.On("SetToken", mock.Anything, validUser.ID.String(), mock.AnythingOfType("string"), 720*time.Hour).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name:     "repo get user error",
			isCLI:    false,
			username: "admin",
			password: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(nil, errors.New("db error")).Once()
			},
			wantErr: errors.New("db error"),
		},
		{
			name:     "repo get user error cli",
			isCLI:    true,
			username: "admin",
			password: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(nil, errors.New("db error")).Once()
			},
			wantErr: errors.New("db error"),
		},
		{
			name:     "user not found returns ErrUnauthorized",
			isCLI:    false,
			username: "unknown",
			password: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("GetUserByUsername", mock.Anything, "unknown").Return(nil, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "inactive user returns ErrUnauthorized",
			isCLI:    false,
			username: "admin",
			password: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				inactiveUser := &domainUser.User{ID: userID, Username: "admin", Status: 0}
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(inactiveUser, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "wrong password returns ErrUnauthorized",
			isCLI:    false,
			username: "admin",
			password: "wrongpassword",
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(validUser, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "set token error returns error",
			isCLI:    false,
			username: "admin",
			password: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(validUser, nil).Once()
				tunnelStore.On("SetToken", mock.Anything, validUser.ID.String(), mock.AnythingOfType("string"), 24*time.Hour).Return(errors.New("redis error")).Once()
			},
			wantErr: errors.New("failed to save token session: redis error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "myjwtsecret", 24, 720)

			var token string
			var loginErr error
			if tt.isCLI {
				token, loginErr = uc.LoginCLI(context.Background(), tt.username, tt.password)
			} else {
				token, loginErr = uc.Login(context.Background(), tt.username, tt.password)
			}

			if tt.wantErr != nil {
				assert.Error(t, loginErr)
				assert.Equal(t, tt.wantErr.Error(), loginErr.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, loginErr)
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestAuthUsecase_VerifyToken(t *testing.T) {
	t.Parallel()

	jwtSecret := "myjwtsecret"
	userID := uuid.New()
	validUser := &domainUser.User{ID: userID, Username: "admin", Role: 1, Status: 1}

	// Helper to generate valid token
	generateToken := func(secret string, claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		str, _ := token.SignedString([]byte(secret))
		return str
	}

	validClaims := jwt.MapClaims{
		"sub":  userID.String(),
		"user": "admin",
		"role": 1,
		"csrf": "csrf123",
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	}
	validTokenStr := generateToken(jwtSecret, validClaims)

	expiredClaims := jwt.MapClaims{
		"sub":  userID.String(),
		"user": "admin",
		"role": 1,
		"exp":  time.Now().Add(-1 * time.Hour).Unix(),
	}
	expiredTokenStr := generateToken(jwtSecret, expiredClaims)

	noUserClaims := jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}
	noUserTokenStr := generateToken(jwtSecret, noUserClaims)

	noCsrfClaims := jwt.MapClaims{
		"sub":  userID.String(),
		"user": "admin",
		"role": 1,
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	}
	noCsrfTokenStr := generateToken(jwtSecret, noCsrfClaims)

	// Token signed with wrong secret
	wrongSecretTokenStr := generateToken("wrongsecret", validClaims)

	// Token signed with none algorithm
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims)
	noneTokenStr, _ := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)

	tests := []struct {
		name      string
		tokenStr  string
		mockSetup func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   error
	}{
		{
			name:     "success verify token",
			tokenStr: validTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, validTokenStr).Return(false, nil).Once()
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(validUser, nil).Once()
			},
			wantErr: nil,
		},
		{
			name:     "success verify token without csrf",
			tokenStr: noCsrfTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, noCsrfTokenStr).Return(false, nil).Once()
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(&domainUser.User{ID: userID, Username: "admin"}, nil).Once()
			},
			wantErr: nil,
		},
		{
			name:     "check revoked error returns error",
			tokenStr: validTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, validTokenStr).Return(false, errors.New("redis err")).Once()
			},
			wantErr: errors.New("redis err"),
		},
		{
			name:     "token revoked returns ErrUnauthorized",
			tokenStr: validTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, validTokenStr).Return(true, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "invalid signature returns ErrUnauthorized",
			tokenStr: wrongSecretTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, wrongSecretTokenStr).Return(false, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "expired token returns ErrUnauthorized",
			tokenStr: expiredTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, expiredTokenStr).Return(false, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "unexpected signing method returns ErrUnauthorized",
			tokenStr: noneTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, noneTokenStr).Return(false, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "missing user claim returns ErrUnauthorized",
			tokenStr: noUserTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, noUserTokenStr).Return(false, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "get user by username error returns ErrUnauthorized",
			tokenStr: validTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, validTokenStr).Return(false, nil).Once()
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(nil, errors.New("db error")).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
		{
			name:     "user not found returns ErrUnauthorized",
			tokenStr: validTokenStr,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("IsTokenRevoked", mock.Anything, validTokenStr).Return(false, nil).Once()
				userRepo.On("GetUserByUsername", mock.Anything, "admin").Return(nil, nil).Once()
			},
			wantErr: domainErrors.ErrUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, jwtSecret, 24, 720)
			res, err := uc.VerifyToken(context.Background(), tt.tokenStr)

			if tt.wantErr != nil {
				assert.Error(t, err)
				if errors.Is(tt.wantErr, domainErrors.ErrUnauthorized) {
					assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
				}
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, "admin", res.Username)
				if tt.tokenStr == validTokenStr {
					assert.Equal(t, "csrf123", res.CSRFToken)
				} else {
					assert.Empty(t, res.CSRFToken)
				}
			}
		})
	}
}

func TestAuthUsecase_Logout(t *testing.T) {
	t.Parallel()

	tokenStr := "sometoken"

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success logout",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RevokeToken", mock.Anything, tokenStr).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "error logout",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RevokeToken", mock.Anything, tokenStr).Return(errors.New("store err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 24, 720)
			err := uc.Logout(context.Background(), tokenStr)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthUsecase_CreateUser(t *testing.T) {
	t.Parallel()

	username := "newuser"
	password := "pass123"
	role := int16(2)

	tests := []struct {
		name      string
		pass      string
		mockSetup func(userRepo *userMocks.MockUserRepository)
		wantErr   bool
	}{
		{
			name: "success create user",
			pass: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository) {
				userRepo.On("CreateUser", mock.Anything, mock.MatchedBy(func(u *domainUser.User) bool {
					return u.Username == username && u.Role == role && u.Status == 1 && util.CheckPasswordHash(password, u.Password)
				})).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "hash error returns error",
			pass: strings.Repeat("a", 80),
			mockSetup: func(userRepo *userMocks.MockUserRepository) {
			},
			wantErr: true,
		},
		{
			name: "repo error returns error",
			pass: password,
			mockSetup: func(userRepo *userMocks.MockUserRepository) {
				userRepo.On("CreateUser", mock.Anything, mock.Anything).Return(errors.New("insert err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 24, 720)
			err := uc.CreateUser(context.Background(), username, tt.pass, role)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthUsecase_ListUsers(t *testing.T) {
	t.Parallel()

	expectedUsers := []domainUser.User{{ID: uuid.New(), Username: "u1"}}

	tests := []struct {
		name      string
		mockSetup func(userRepo *userMocks.MockUserRepository)
		wantErr   bool
	}{
		{
			name: "success list users",
			mockSetup: func(userRepo *userMocks.MockUserRepository) {
				userRepo.On("GetUsers", mock.Anything).Return(expectedUsers, nil).Once()
			},
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(userRepo *userMocks.MockUserRepository) {
				userRepo.On("GetUsers", mock.Anything).Return(nil, errors.New("db err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 24, 720)
			res, err := uc.ListUsers(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, expectedUsers, res)
			}
		})
	}
}

func TestAuthUsecase_UpdateUserStatus(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	status := int16(0)

	tests := []struct {
		name      string
		mockSetup func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success update status",
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("UpdateUserStatus", mock.Anything, userID, status).Return(nil).Once()
				tunnelStore.On("RevokeUserTokens", mock.Anything, userID.String()).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("UpdateUserStatus", mock.Anything, userID, status).Return(errors.New("db err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 24, 720)
			err := uc.UpdateUserStatus(context.Background(), userID, status)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthUsecase_UpdateUserPassword(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	newPass := "newpass123"

	tests := []struct {
		name      string
		pass      string
		mockSetup func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success update password",
			pass: newPass,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("UpdateUserPassword", mock.Anything, userID, mock.MatchedBy(func(hash string) bool {
					return util.CheckPasswordHash(newPass, hash)
				})).Return(nil).Once()
				tunnelStore.On("RevokeUserTokens", mock.Anything, userID.String()).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "hash error returns error",
			pass: strings.Repeat("a", 80),
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
			},
			wantErr: true,
		},
		{
			name: "repo error returns error",
			pass: newPass,
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("UpdateUserPassword", mock.Anything, userID, mock.Anything).Return(errors.New("db err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 24, 720)
			err := uc.UpdateUserPassword(context.Background(), userID, tt.pass)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthUsecase_DeleteUser(t *testing.T) {
	t.Parallel()

	userID := uuid.New()

	tests := []struct {
		name      string
		mockSetup func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success delete user",
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("DeleteUser", mock.Anything, userID).Return(nil).Once()
				tunnelStore.On("RevokeUserTokens", mock.Anything, userID.String()).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "repo error returns error",
			mockSetup: func(userRepo *userMocks.MockUserRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				userRepo.On("DeleteUser", mock.Anything, userID).Return(errors.New("db err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 24, 720)
			err := uc.DeleteUser(context.Background(), userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthUsecase_DeleteUser_WithAPIKeyRepo(t *testing.T) {
	t.Parallel()

	userID := uuid.New()

	tests := []struct {
		name      string
		mockSetup func(userRepo *userMocks.MockUserRepository, apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success delete user revokes API keys first",
			mockSetup: func(userRepo *userMocks.MockUserRepository, apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("RevokeAllByUserID", mock.Anything, userID).Return(nil).Once()
				userRepo.On("DeleteUser", mock.Anything, userID).Return(nil).Once()
				tunnelStore.On("RevokeUserTokens", mock.Anything, userID.String()).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "delete user succeeds even if API key revocation fails",
			mockSetup: func(userRepo *userMocks.MockUserRepository, apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("RevokeAllByUserID", mock.Anything, userID).Return(errors.New("redis err")).Once()
				userRepo.On("DeleteUser", mock.Anything, userID).Return(nil).Once()
				tunnelStore.On("RevokeUserTokens", mock.Anything, userID.String()).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "repo error returns error after API key revocation",
			mockSetup: func(userRepo *userMocks.MockUserRepository, apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("RevokeAllByUserID", mock.Anything, userID).Return(nil).Once()
				userRepo.On("DeleteUser", mock.Anything, userID).Return(errors.New("db err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(userRepo, apiKeyRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)
			err := uc.DeleteUser(context.Background(), userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthUsecase_RevokeUserTokens(t *testing.T) {
	t.Parallel()

	userID := uuid.New()

	tests := []struct {
		name      string
		mockSetup func(tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr   bool
	}{
		{
			name: "success revoke user tokens",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RevokeUserTokens", mock.Anything, userID.String()).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "store error returns error",
			mockSetup: func(tunnelStore *tunnelMocks.MockTunnelStore) {
				tunnelStore.On("RevokeUserTokens", mock.Anything, userID.String()).Return(errors.New("redis err")).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(tunnelStore)

			uc := NewAuthUsecase(userRepo, nil, tunnelStore, "secret", 24, 720)
			err := uc.RevokeUserTokens(context.Background(), userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateKeyName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		// Valid names
		{
			name:    "valid simple name",
			input:   "my-api-key",
			wantErr: false,
		},
		{
			name:    "valid alphanumeric",
			input:   "key123",
			wantErr: false,
		},
		{
			name:    "valid with underscore",
			input:   "my_key_name",
			wantErr: false,
		},
		{
			name:    "valid with hyphen",
			input:   "my-key-name",
			wantErr: false,
		},
		{
			name:    "valid mixed characters",
			input:   "My_Key-123",
			wantErr: false,
		},
		{
			name:    "valid single character",
			input:   "a",
			wantErr: false,
		},
		{
			name:    "valid 64 characters",
			input:   strings.Repeat("a", 64),
			wantErr: false,
		},
		// Invalid names - length constraints
		{
			name:    "invalid empty name",
			input:   "",
			wantErr: true,
			errMsg:  "name is required and must be 1-64 characters",
		},
		{
			name:    "invalid 65 characters",
			input:   strings.Repeat("a", 65),
			wantErr: true,
			errMsg:  "name is required and must be 1-64 characters",
		},
		{
			name:    "invalid 100 characters",
			input:   strings.Repeat("a", 100),
			wantErr: true,
			errMsg:  "name is required and must be 1-64 characters",
		},
		// Invalid names - character constraints
		{
			name:    "invalid with space",
			input:   "my key",
			wantErr: true,
			errMsg:  "name can only contain alphanumeric characters, hyphens, and underscores",
		},
		{
			name:    "invalid with dot",
			input:   "my.key",
			wantErr: true,
			errMsg:  "name can only contain alphanumeric characters, hyphens, and underscores",
		},
		{
			name:    "invalid with at sign",
			input:   "my@key",
			wantErr: true,
			errMsg:  "name can only contain alphanumeric characters, hyphens, and underscores",
		},
		{
			name:    "invalid with slash",
			input:   "my/key",
			wantErr: true,
			errMsg:  "name can only contain alphanumeric characters, hyphens, and underscores",
		},
		{
			name:    "invalid with special characters",
			input:   "key!@#$%",
			wantErr: true,
			errMsg:  "name can only contain alphanumeric characters, hyphens, and underscores",
		},
		{
			name:    "invalid with unicode",
			input:   "key日本語",
			wantErr: true,
			errMsg:  "name can only contain alphanumeric characters, hyphens, and underscores",
		},
		{
			name:    "invalid with emoji",
			input:   "key🔑",
			wantErr: true,
			errMsg:  "name can only contain alphanumeric characters, hyphens, and underscores",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateKeyName(tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tt.errMsg, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAPIKeyConstants(t *testing.T) {
	t.Parallel()

	// Verify constants have expected values per design document
	assert.Equal(t, "gtk_", apiKeyPrefix, "API key prefix should be 'gtk_'")
	assert.Equal(t, 32, apiKeyByteLen, "API key should use 32 bytes (256 bits) of entropy")
	assert.Equal(t, 10, maxKeysPerUser, "Maximum keys per user should be 10")
	assert.Equal(t, 365, maxExpiryDays, "Maximum expiry days should be 365")
}

func TestCreateAPIKey_Success(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "my-api-key"
	expiresAt := time.Now().Add(24 * time.Hour)

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return false (no duplicate)
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	// Mock CountActiveByUserID to return < 10
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(5, nil).Once()
	// Mock Create to succeed
	apiKeyRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(key *domainAPIKey.APIKey) bool {
		return key.UserID == userID &&
			key.Name == keyName &&
			key.Status == domainAPIKey.StatusActive &&
			key.KeyHash != "" &&
			key.ExpiresAt != nil &&
			key.ExpiresAt.Equal(expiresAt)
	})).Return(nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, &expiresAt)

	require.NoError(t, err)
	assert.NotEmpty(t, plaintext)
	assert.True(t, strings.HasPrefix(plaintext, "gtk_"), "API key should start with gtk_ prefix")
	assert.GreaterOrEqual(t, len(plaintext), 47, "API key should have minimum 47 characters (4 prefix + 43 base64)")
	require.NotNil(t, key)
	assert.Equal(t, keyName, key.Name)
	assert.Equal(t, userID, key.UserID)
	assert.Equal(t, domainAPIKey.StatusActive, key.Status)
	assert.NotEmpty(t, key.KeyHash)
}

func TestCreateAPIKey_NoExpiration(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "permanent-key"

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return false (no duplicate)
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	// Mock CountActiveByUserID to return < 10
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(0, nil).Once()
	// Mock Create to succeed with nil ExpiresAt
	apiKeyRepo.EXPECT().Create(mock.Anything, mock.MatchedBy(func(key *domainAPIKey.APIKey) bool {
		return key.UserID == userID &&
			key.Name == keyName &&
			key.Status == domainAPIKey.StatusActive &&
			key.ExpiresAt == nil
	})).Return(nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, nil)

	require.NoError(t, err)
	assert.NotEmpty(t, plaintext)
	assert.True(t, strings.HasPrefix(plaintext, "gtk_"))
	require.NotNil(t, key)
	assert.Equal(t, keyName, key.Name)
	assert.Nil(t, key.ExpiresAt, "Key should have no expiration")
}

func TestCreateAPIKey_DuplicateName(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "existing-key"

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return true (duplicate exists)
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(true, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrAlreadyExists)
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_MaxKeysReached(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "new-key"

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return false
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	// Mock CountActiveByUserID to return 10 (max reached)
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(10, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum of 10 active API keys reached")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_InvalidNameEmpty(t *testing.T) {
	t.Parallel()

	userID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, "", nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required and must be 1-64 characters")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_InvalidNameTooLong(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	longName := strings.Repeat("a", 65) // 65 characters, exceeds 64 limit

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, longName, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required and must be 1-64 characters")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_InvalidNameChars(t *testing.T) {
	t.Parallel()

	userID := uuid.New()

	tests := []struct {
		name    string
		keyName string
	}{
		{"with space", "my key"},
		{"with dot", "my.key"},
		{"with at sign", "my@key"},
		{"with slash", "my/key"},
		{"with special chars", "key!@#$%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

			plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, tt.keyName, nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "name can only contain alphanumeric characters, hyphens, and underscores")
			assert.Empty(t, plaintext)
			assert.Nil(t, key)
		})
	}
}

func TestCreateAPIKey_ExpirationInPast(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "past-key"
	pastTime := time.Now().Add(-1 * time.Hour) // 1 hour in the past

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return false
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	// Mock CountActiveByUserID to return < 10
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(0, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, &pastTime)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expiration date must be in the future")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_ExpirationTooFarFuture(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "far-future-key"
	farFuture := time.Now().AddDate(0, 0, 366) // 366 days in the future, exceeds 365 limit

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return false
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	// Mock CountActiveByUserID to return < 10
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(0, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, &farFuture)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expiration date cannot exceed 365 days")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_ExistsActiveByNameError(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "test-key"

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return error
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, errors.New("db error")).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "check duplicate name")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_CountActiveError(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "test-key"

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return false
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	// Mock CountActiveByUserID to return error
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(0, errors.New("db error")).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "count active keys")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_CreateError(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyName := "test-key"

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	// Mock ExistsActiveByName to return false
	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	// Mock CountActiveByUserID to return < 10
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(0, nil).Once()
	// Mock Create to return error
	apiKeyRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(errors.New("db error")).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist API key")
	assert.Empty(t, plaintext)
	assert.Nil(t, key)
}

func TestCreateAPIKey_KeyFormat(t *testing.T) {
	t.Parallel()

	// Test that generated keys consistently have the correct format
	userID := uuid.New()
	keyName := "format-test-key"

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	tunnelStore := tunnelMocks.NewMockTunnelStore(t)

	apiKeyRepo.EXPECT().ExistsActiveByName(mock.Anything, userID, keyName).Return(false, nil).Once()
	apiKeyRepo.EXPECT().CountActiveByUserID(mock.Anything, userID).Return(0, nil).Once()
	apiKeyRepo.EXPECT().Create(mock.Anything, mock.Anything).Return(nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)

	plaintext, key, err := uc.CreateAPIKey(context.Background(), userID, keyName, nil)

	require.NoError(t, err)
	require.NotEmpty(t, plaintext)
	require.NotNil(t, key)

	// Verify format: gtk_ prefix + base64 encoded 32 bytes
	// 32 bytes base64 encoded = 44 characters (with padding) or 43 (URL encoding without padding)
	// Total: 4 (prefix) + ~43 = ~47 characters minimum
	assert.True(t, strings.HasPrefix(plaintext, "gtk_"), "Key should start with gtk_ prefix")
	assert.GreaterOrEqual(t, len(plaintext), 47, "Key should have at least 47 characters")

	// Verify the hash is 64 characters (SHA-256 hex encoding)
	assert.Len(t, key.KeyHash, 64, "Key hash should be 64 characters (SHA-256 hex)")
}

func TestAuthUsecase_RevokeAPIKey(t *testing.T) {
	t.Parallel()

	ownerUserID := uuid.New()
	otherUserID := uuid.New()
	keyID := uuid.New()
	keyHash := "somehashvalue123"

	validAPIKey := &domainAPIKey.APIKey{
		ID:      keyID,
		UserID:  ownerUserID,
		Name:    "my-api-key",
		KeyHash: keyHash,
		Status:  domainAPIKey.StatusActive,
	}

	tests := []struct {
		name          string
		keyID         uuid.UUID
		requesterID   uuid.UUID
		requesterRole int16
		mockSetup     func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore)
		wantErr       error
	}{
		{
			name:          "owner revokes own key success",
			keyID:         keyID,
			requesterID:   ownerUserID,
			requesterRole: 0, // Regular user
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
				apiKeyRepo.On("Revoke", mock.Anything, keyID).Return(nil).Once()
				tunnelStore.On("RevokeToken", mock.Anything, keyHash).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name:          "admin revokes any key success",
			keyID:         keyID,
			requesterID:   otherUserID, // Different user but admin
			requesterRole: 1,           // Admin
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
				apiKeyRepo.On("Revoke", mock.Anything, keyID).Return(nil).Once()
				tunnelStore.On("RevokeToken", mock.Anything, keyHash).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name:          "non-owner non-admin returns forbidden",
			keyID:         keyID,
			requesterID:   otherUserID, // Different user
			requesterRole: 0,           // Not admin
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
			},
			wantErr: domainErrors.ErrForbidden,
		},
		{
			name:          "key not found returns not found",
			keyID:         keyID,
			requesterID:   ownerUserID,
			requesterRole: 0,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(nil, nil).Once()
			},
			wantErr: domainErrors.ErrNotFound,
		},
		{
			name:          "get key db error returns error",
			keyID:         keyID,
			requesterID:   ownerUserID,
			requesterRole: 0,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(nil, errors.New("db error")).Once()
			},
			wantErr: errors.New("get API key: db error"),
		},
		{
			name:          "revoke db error returns error",
			keyID:         keyID,
			requesterID:   ownerUserID,
			requesterRole: 0,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
				apiKeyRepo.On("Revoke", mock.Anything, keyID).Return(errors.New("revoke failed")).Once()
			},
			wantErr: errors.New("revoke API key: revoke failed"),
		},
		{
			name:          "redis revoke token error is ignored (best effort)",
			keyID:         keyID,
			requesterID:   ownerUserID,
			requesterRole: 0,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
				apiKeyRepo.On("Revoke", mock.Anything, keyID).Return(nil).Once()
				tunnelStore.On("RevokeToken", mock.Anything, keyHash).Return(errors.New("redis error")).Once()
			},
			wantErr: nil, // Should succeed even if Redis fails
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(apiKeyRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)
			err := uc.RevokeAPIKey(context.Background(), tt.keyID, tt.requesterID, tt.requesterRole)

			if tt.wantErr != nil {
				assert.Error(t, err)
				if errors.Is(tt.wantErr, domainErrors.ErrForbidden) {
					assert.ErrorIs(t, err, domainErrors.ErrForbidden)
				} else if errors.Is(tt.wantErr, domainErrors.ErrNotFound) {
					assert.ErrorIs(t, err, domainErrors.ErrNotFound)
				} else {
					assert.Equal(t, tt.wantErr.Error(), err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthUsecase_DeleteAPIKey(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	adminID := uuid.New()
	otherID := uuid.New()
	keyID := uuid.New()
	keyHash := "testhash"

	validAPIKey := &domainAPIKey.APIKey{
		ID:      keyID,
		UserID:  userID,
		Name:    "test-key",
		KeyHash: keyHash,
		Status:  domainAPIKey.StatusActive,
	}

	tests := []struct {
		name          string
		keyID         uuid.UUID
		requesterID   uuid.UUID
		requesterRole int16
		mockSetup     func(*apikeyMocks.MockAPIKeyRepository, *tunnelMocks.MockTunnelStore)
		wantErr       error
	}{
		{
			name:          "success owner deletes key",
			keyID:         keyID,
			requesterID:   userID,
			requesterRole: 0,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
				apiKeyRepo.On("Delete", mock.Anything, keyID).Return(nil).Once()
				tunnelStore.On("RevokeToken", mock.Anything, keyHash).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name:          "success admin deletes key",
			keyID:         keyID,
			requesterID:   adminID,
			requesterRole: 1,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
				apiKeyRepo.On("Delete", mock.Anything, keyID).Return(nil).Once()
				tunnelStore.On("RevokeToken", mock.Anything, keyHash).Return(nil).Once()
			},
			wantErr: nil,
		},
		{
			name:          "not found",
			keyID:         keyID,
			requesterID:   userID,
			requesterRole: 0,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(nil, nil).Once()
			},
			wantErr: domainErrors.ErrNotFound,
		},
		{
			name:          "forbidden non owner non admin",
			keyID:         keyID,
			requesterID:   otherID,
			requesterRole: 0,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository, tunnelStore *tunnelMocks.MockTunnelStore) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
			},
			wantErr: domainErrors.ErrForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(apiKeyRepo, tunnelStore)

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)
			err := uc.DeleteAPIKey(context.Background(), tt.keyID, tt.requesterID, tt.requesterRole)

			if tt.wantErr != nil {
				assert.Error(t, err)
				if errors.Is(tt.wantErr, domainErrors.ErrForbidden) {
					assert.ErrorIs(t, err, domainErrors.ErrForbidden)
				} else if errors.Is(tt.wantErr, domainErrors.ErrNotFound) {
					assert.ErrorIs(t, err, domainErrors.ErrNotFound)
				} else {
					assert.Equal(t, tt.wantErr.Error(), err.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}


func TestAuthUsecase_GetAPIKeyByID(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	userID := uuid.New()

	validAPIKey := &domainAPIKey.APIKey{
		ID:      keyID,
		UserID:  userID,
		Name:    "test-key",
		KeyHash: "somehash",
		Status:  domainAPIKey.StatusActive,
	}

	tests := []struct {
		name      string
		keyID     uuid.UUID
		mockSetup func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository)
		wantKey   *domainAPIKey.APIKey
		wantErr   error
	}{
		{
			name:  "success get key by id",
			keyID: keyID,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(validAPIKey, nil).Once()
			},
			wantKey: validAPIKey,
			wantErr: nil,
		},
		{
			name:  "key not found returns not found",
			keyID: keyID,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(nil, nil).Once()
			},
			wantKey: nil,
			wantErr: domainErrors.ErrNotFound,
		},
		{
			name:  "db error returns error",
			keyID: keyID,
			mockSetup: func(apiKeyRepo *apikeyMocks.MockAPIKeyRepository) {
				apiKeyRepo.On("GetByID", mock.Anything, keyID).Return(nil, errors.New("db error")).Once()
			},
			wantKey: nil,
			wantErr: errors.New("get API key: db error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			userRepo := userMocks.NewMockUserRepository(t)
			apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
			tunnelStore := tunnelMocks.NewMockTunnelStore(t)
			tt.mockSetup(apiKeyRepo)

			uc := NewAuthUsecase(userRepo, apiKeyRepo, tunnelStore, "secret", 24, 720)
			key, err := uc.GetAPIKeyByID(context.Background(), tt.keyID)

			if tt.wantErr != nil {
				assert.Error(t, err)
				if errors.Is(tt.wantErr, domainErrors.ErrNotFound) {
					assert.ErrorIs(t, err, domainErrors.ErrNotFound)
				} else {
					assert.Equal(t, tt.wantErr.Error(), err.Error())
				}
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, key)
				assert.Equal(t, tt.wantKey.ID, key.ID)
				assert.Equal(t, tt.wantKey.Name, key.Name)
			}
		})
	}
}

// =============================================================================
// verifyAPIKey Unit Tests
// Task 7.3: Write unit tests for verifyAPIKey
// Requirements: 4.1, 4.2, 4.3, 4.4
// =============================================================================

func TestVerifyAPIKey_Success(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	// Create a real token with proper hash
	plaintext := "gtk_validtokenhere123456789012345678901234567"
	hash := computeSHA256Hash(plaintext)

	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: nil, // No expiration
	}

	user := &domainUser.User{
		ID:       userID,
		Username: "testuser",
		Role:     0,
		Status:   1, // Active user
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()
	userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(user, nil).Once()
	apiKeyRepo.EXPECT().UpdateLastUsedAt(mock.Anything, keyID).Return(nil).Maybe()
	store.EXPECT().SetToken(mock.Anything, userID.String(), plaintext, mock.AnythingOfType("time.Duration")).Return(nil).Maybe()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, userID, result.ID)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, int16(0), result.Role)
}

func TestVerifyAPIKey_SuccessWithExpiration(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_validtokenwithexpiration12345678901234567"
	hash := computeSHA256Hash(plaintext)

	// Key with future expiration
	futureExpiry := time.Now().Add(24 * time.Hour)
	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "expiring-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: &futureExpiry,
	}

	user := &domainUser.User{
		ID:       userID,
		Username: "testuser",
		Role:     1, // Admin
		Status:   1, // Active
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()
	userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(user, nil).Once()
	apiKeyRepo.EXPECT().UpdateLastUsedAt(mock.Anything, keyID).Return(nil).Maybe()
	store.EXPECT().SetToken(mock.Anything, userID.String(), plaintext, mock.AnythingOfType("time.Duration")).Return(nil).Maybe()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, userID, result.ID)
	assert.Equal(t, int16(1), result.Role)
}

func TestVerifyAPIKey_KeyNotFound(t *testing.T) {
	t.Parallel()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_nonexistentkeyhere123456789012345678901"
	hash := computeSHA256Hash(plaintext)

	// Key not found - returns nil, nil
	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(nil, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

func TestVerifyAPIKey_RevokedKey(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_revokedkeytoken123456789012345678901234"
	hash := computeSHA256Hash(plaintext)

	// Key exists but is revoked
	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "revoked-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusRevoked, // Revoked status
		ExpiresAt: nil,
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

func TestVerifyAPIKey_ExpiredKey(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_expiredkeytoken1234567890123456789012345"
	hash := computeSHA256Hash(plaintext)

	// Key with past expiration
	pastExpiry := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "expired-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: &pastExpiry, // Expired
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

func TestVerifyAPIKey_InactiveUser(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_validkeybutinactiveuser12345678901234567"
	hash := computeSHA256Hash(plaintext)

	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: nil,
	}

	// User is inactive (status != 1)
	user := &domainUser.User{
		ID:       userID,
		Username: "inactiveuser",
		Role:     0,
		Status:   0, // Inactive user
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()
	userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(user, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

func TestVerifyAPIKey_EmptyTokenAfterPrefix(t *testing.T) {
	t.Parallel()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	// Token is just the prefix with no content after
	plaintext := "gtk_"

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

func TestVerifyAPIKey_DBError(t *testing.T) {
	t.Parallel()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_tokenwithdberror123456789012345678901234"
	hash := computeSHA256Hash(plaintext)

	// Database error during lookup
	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(nil, errors.New("database connection failed")).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

func TestVerifyAPIKey_UserNotFound(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_validkeybutusergone12345678901234567890"
	hash := computeSHA256Hash(plaintext)

	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "orphan-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: nil,
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()
	// User not found - returns nil, nil
	userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(nil, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

func TestVerifyAPIKey_UserDBError(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_validkeybutuserlookupfails1234567890123"
	hash := computeSHA256Hash(plaintext)

	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "test-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: nil,
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()
	// User lookup fails with error
	userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(nil, errors.New("user db error")).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.Error(t, err)
	assert.ErrorIs(t, err, domainErrors.ErrUnauthorized)
	assert.Nil(t, result)
}

// TestVerifyToken_RoutingToAPIKey verifies that tokens with gtk_ prefix are routed to API key verification.
// Validates: Requirements 4.1, 4.2
func TestVerifyToken_RoutingToAPIKey(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_routingtesttoken1234567890123456789012"
	hash := computeSHA256Hash(plaintext)

	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "routing-test-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: nil,
	}

	user := &domainUser.User{
		ID:       userID,
		Username: "routinguser",
		Role:     0,
		Status:   1,
	}

	// Expect API key path to be called (GetByHash), not JWT path (IsTokenRevoked)
	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()
	userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(user, nil).Once()
	apiKeyRepo.EXPECT().UpdateLastUsedAt(mock.Anything, keyID).Return(nil).Maybe()
	store.EXPECT().SetToken(mock.Anything, userID.String(), plaintext, mock.AnythingOfType("time.Duration")).Return(nil).Maybe()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, userID, result.ID)
}

// TestVerifyToken_APIKeyNoRedisOverload verifies that verifying an API key never calls SetToken on Redis,
// preventing Redis memory overload when many keys are verified or generated with long TTLs.
func TestVerifyToken_APIKeyNoRedisOverload(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	keyID := uuid.New()

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	plaintext := "gtk_noredisoverloadtoken123456789012345678"
	hash := computeSHA256Hash(plaintext)

	key := &domainAPIKey.APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      "no-redis-key",
		KeyHash:   hash,
		Status:    domainAPIKey.StatusActive,
		ExpiresAt: nil,
	}

	user := &domainUser.User{
		ID:       userID,
		Username: "noredisuser",
		Role:     0,
		Status:   1,
	}

	apiKeyRepo.EXPECT().GetByHash(mock.Anything, hash).Return(key, nil).Once()
	userRepo.EXPECT().GetUserByID(mock.Anything, userID).Return(user, nil).Once()
	apiKeyRepo.EXPECT().UpdateLastUsedAt(mock.Anything, keyID).Return(nil).Maybe()
	// NOTE: store.SetToken must NOT be expected or called (`store` is strict mock, calling SetToken will fail the test)

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, "secret", 24, 720)

	result, err := uc.VerifyToken(context.Background(), plaintext)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, userID, result.ID)
}

// TestVerifyToken_RoutingToJWT verifies that tokens without gtk_ prefix are routed to JWT verification.
// Validates: Requirements 4.1, 4.2
func TestVerifyToken_RoutingToJWT(t *testing.T) {
	t.Parallel()

	jwtSecret := "myjwtsecret"
	userID := uuid.New()

	// Generate a valid JWT token (no gtk_ prefix)
	validUser := &domainUser.User{ID: userID, Username: "jwtuser", Role: 1, Status: 1}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID.String(),
		"user": "jwtuser",
		"role": 1,
		"csrf": "csrf123",
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	})
	jwtTokenStr, _ := token.SignedString([]byte(jwtSecret))

	userRepo := userMocks.NewMockUserRepository(t)
	apiKeyRepo := apikeyMocks.NewMockAPIKeyRepository(t)
	store := tunnelMocks.NewMockTunnelStore(t)

	// Expect JWT path to be called (IsTokenRevoked), not API key path (GetByHash)
	store.EXPECT().IsTokenRevoked(mock.Anything, jwtTokenStr).Return(false, nil).Once()
	userRepo.EXPECT().GetUserByUsername(mock.Anything, "jwtuser").Return(validUser, nil).Once()

	uc := NewAuthUsecase(userRepo, apiKeyRepo, store, jwtSecret, 24, 720)

	result, err := uc.VerifyToken(context.Background(), jwtTokenStr)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, userID, result.ID)
	assert.Equal(t, "jwtuser", result.Username)
}

// computeSHA256Hash computes SHA-256 hash of plaintext and returns hex string.
// Helper function for tests to generate correct hash values.
func computeSHA256Hash(plaintext string) string {
	hash := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(hash[:])
}
