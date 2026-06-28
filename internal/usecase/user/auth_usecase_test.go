package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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

	uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 0, -1)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "myjwtsecret", 24, 720)

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

			uc := NewAuthUsecase(userRepo, tunnelStore, jwtSecret, 24, 720)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 24, 720)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 24, 720)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 24, 720)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 24, 720)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 24, 720)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 24, 720)
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

			uc := NewAuthUsecase(userRepo, tunnelStore, "secret", 24, 720)
			err := uc.RevokeUserTokens(context.Background(), userID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
