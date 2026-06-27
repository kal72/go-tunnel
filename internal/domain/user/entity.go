package user

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
	Username  string    `db:"username" json:"username"`
	Password  string    `db:"password" json:"-"`
	CSRFToken string    `db:"-" json:"-"`
	ID        uuid.UUID `db:"id" json:"id"`
	Role      int16     `db:"role" json:"role"`
	Status    int16     `db:"status" json:"status"`
}
