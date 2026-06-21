package user

import (
	"context"
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
	userRepo  domainUser.UserRepository
	store     domainTunnel.TunnelStore
	jwtSecret string
}

func NewAuthUsecase(userRepo domainUser.UserRepository, store domainTunnel.TunnelStore, jwtSecret string) AuthUsecase {
	return &authUsecase{
		userRepo:  userRepo,
		store:     store,
		jwtSecret: jwtSecret,
	}
}

func (u *authUsecase) Login(ctx context.Context, username, password string) (string, error) {
	user, err := u.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", domainErrors.ErrUnauthorized
	}
	if user.Status != 1 {
		return "", domainErrors.ErrUnauthorized
	}

	if !util.CheckPasswordHash(password, user.Password) {
		return "", domainErrors.ErrUnauthorized
	}

	expiration := 30 * 24 * time.Hour // default 30 days
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID.String(),
		"user": user.Username,
		"role": user.Role,
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
		Password: string(hash),
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
	return u.userRepo.UpdateUserPassword(ctx, id, string(hash))
}

func (u *authUsecase) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return u.userRepo.DeleteUser(ctx, id)
}
