package state

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID `db:"id"`
	Username  string    `db:"username"`
	Password  string    `db:"password"`
	Role      int16     `db:"role"`   // 1: admin, 2: user
	Status    int16     `db:"status"` // 0: inactive, 1: active
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

//go:generate mockery --name=UserRepository --case=underscore --output=mocks --outpkg=mocks
type UserRepository interface {
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	GetUsers(ctx context.Context) ([]User, error)
}
