package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	domainErrors "gotunnel/internal/domain/errors"
	domainTunnel "gotunnel/internal/domain/tunnel"
	domainUser "gotunnel/internal/domain/user"

	util "gotunnel/internal/shared/crypto"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type authUsecase struct {
	userRepo          domainUser.UserRepository
	store             domainTunnel.TunnelStore
	jwtSecret         string
	webJWTExpireHours int
	cliJWTExpireHours int
}

func NewAuthUsecase(userRepo domainUser.UserRepository, store domainTunnel.TunnelStore, jwtSecret string, webExpireHours, cliExpireHours int) AuthUsecase {
	if webExpireHours <= 0 {
		webExpireHours = 24
	}
	if cliExpireHours <= 0 {
		cliExpireHours = 720
	}
	return &authUsecase{
		userRepo:          userRepo,
		store:             store,
		jwtSecret:         jwtSecret,
		webJWTExpireHours: webExpireHours,
		cliJWTExpireHours: cliExpireHours,
	}
}

func (u *authUsecase) GetWebExpireDuration() time.Duration {
	return time.Duration(u.webJWTExpireHours) * time.Hour
}

func (u *authUsecase) authenticateUser(ctx context.Context, username, password string) (*domainUser.User, error) {
	user, err := u.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != 1 {
		return nil, domainErrors.ErrUnauthorized
	}

	if !util.CheckPasswordHash(password, user.Password) {
		return nil, domainErrors.ErrUnauthorized
	}
	return user, nil
}

func (u *authUsecase) issueToken(ctx context.Context, user *domainUser.User, expireHours int) (string, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	csrfToken := hex.EncodeToString(b)

	expiration := time.Duration(expireHours) * time.Hour
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID.String(),
		"user": user.Username,
		"role": user.Role,
		"csrf": csrfToken,
		"exp":  time.Now().Add(expiration).Unix(),
	})

	tokenString, err := token.SignedString([]byte(u.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	err = u.store.SetToken(ctx, tokenString, expiration)
	if err != nil {
		return "", fmt.Errorf("failed to save token session: %w", err)
	}

	return tokenString, nil
}

func (u *authUsecase) Login(ctx context.Context, username, password string) (string, error) {
	user, err := u.authenticateUser(ctx, username, password)
	if err != nil {
		return "", err
	}
	return u.issueToken(ctx, user, u.webJWTExpireHours)
}

func (u *authUsecase) LoginCLI(ctx context.Context, username, password string) (string, error) {
	user, err := u.authenticateUser(ctx, username, password)
	if err != nil {
		return "", err
	}
	return u.issueToken(ctx, user, u.cliJWTExpireHours)
}

func (u *authUsecase) VerifyToken(ctx context.Context, tokenStr string) (*domainUser.User, error) {
	revoked, err := u.store.IsTokenRevoked(ctx, tokenStr)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, domainErrors.ErrUnauthorized
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(u.jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return nil, domainErrors.ErrUnauthorized
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domainErrors.ErrUnauthorized
	}

	username, ok := claims["user"].(string)
	if !ok {
		return nil, domainErrors.ErrUnauthorized
	}

	user, err := u.userRepo.GetUserByUsername(ctx, username)
	if err != nil || user == nil {
		return nil, domainErrors.ErrUnauthorized
	}

	if csrf, ok := claims["csrf"].(string); ok {
		user.CSRFToken = csrf
	}

	return user, nil
}

func (u *authUsecase) Logout(ctx context.Context, tokenStr string) error {
	return u.store.RevokeToken(ctx, tokenStr)
}

func (u *authUsecase) CreateUser(ctx context.Context, username, password string, role int16) error {
	hash, err := util.HashPassword(password)
	if err != nil {
		return err
	}

	user := &domainUser.User{
		Username: username,
		Password: hash,
		Role:     role,
		Status:   1,
	}

	return u.userRepo.CreateUser(ctx, user)
}

func (u *authUsecase) ListUsers(ctx context.Context) ([]domainUser.User, error) {
	return u.userRepo.GetUsers(ctx)
}

func (u *authUsecase) UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error {
	return u.userRepo.UpdateUserStatus(ctx, id, status)
}

func (u *authUsecase) UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error {
	hash, err := util.HashPassword(password)
	if err != nil {
		return err
	}
	return u.userRepo.UpdateUserPassword(ctx, id, hash)
}

func (u *authUsecase) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return u.userRepo.DeleteUser(ctx, id)
}
