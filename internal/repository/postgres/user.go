package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"gotunnel/internal/model"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type sqlxUserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) model.UserRepository {
	return &sqlxUserRepository{db: db}
}

func (r *sqlxUserRepository) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User
	err := r.db.GetContext(ctx, &user, "SELECT id, username, password, role, status, created_at, updated_at FROM users WHERE username = $1", username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Return nil if not found
		}
		return nil, fmt.Errorf("GetUserByUsername error: %w", err)
	}
	return &user, nil
}

func (r *sqlxUserRepository) CreateUser(ctx context.Context, user *model.User) error {
	query := `INSERT INTO users (id, username, password, role, status) VALUES (:id, :username, :password, :role, :status)`
	_, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("CreateUser error: %w", err)
	}
	return nil
}

func (r *sqlxUserRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status int16) error {
	query := `UPDATE users SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, status, id)
	if err != nil {
		return fmt.Errorf("UpdateUserStatus error: %w", err)
	}
	return nil
}

func (r *sqlxUserRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	query := `UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, passwordHash, id)
	if err != nil {
		return fmt.Errorf("UpdateUserPassword error: %w", err)
	}
	return nil
}

func (r *sqlxUserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DeleteUser error: %w", err)
	}
	return nil
}

func (r *sqlxUserRepository) GetUsers(ctx context.Context) ([]model.User, error) {
	var users []model.User
	err := r.db.SelectContext(ctx, &users, "SELECT id, username, password, role, status, created_at, updated_at FROM users ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("GetUsers error: %w", err)
	}
	return users, nil
}
