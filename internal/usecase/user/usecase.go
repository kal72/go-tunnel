package user

import (
	"context"
	"time"

	domainUser "gotunnel/internal/domain/user"

	"github.com/google/uuid"
)

//go:generate mockery --name=AuthUsecase --case=underscore --output=mocks --outpkg=mocks
type AuthUsecase interface {
	Login(ctx context.Context, username, password string) (token string, err error)
	LoginCLI(ctx context.Context, username, password string) (token string, err error)
	GetWebExpireDuration() time.Duration
	VerifyToken(ctx context.Context, token string) (*domainUser.User, error)
	Logout(ctx context.Context, token string) error
	CreateUser(ctx context.Context, username, password string, role int16) error
	ListUsers(ctx context.Context) ([]domainUser.User, error)
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}
