package user

import (
	"context"

	"github.com/google/uuid"
)

//mockery:generate: true
type UserRepository interface {
	// GetUserByID retrieves a user by their UUID.
	// Returns nil, nil when the user is not found.
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	GetUsers(ctx context.Context) ([]User, error)
}
