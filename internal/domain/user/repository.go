package user

import (
	"context"

	"github.com/google/uuid"
)

//mockery:generate: true
type UserRepository interface {
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	GetUsers(ctx context.Context) ([]User, error)
}
