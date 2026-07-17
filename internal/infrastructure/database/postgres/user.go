package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	domainUser "gotunnel/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type sqlxUserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) domainUser.UserRepository {
	return &sqlxUserRepository{db: db}
}

func (r *sqlxUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*domainUser.User, error) {
	var user domainUser.User
	err := r.db.GetContext(ctx, &user, "SELECT id, username, password, role, status, created_at, updated_at FROM users WHERE id = $1", id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // Return nil if not found
		}
		return nil, fmt.Errorf("GetUserByID error: %w", err)
	}
	return &user, nil
}

func (r *sqlxUserRepository) GetUserByUsername(ctx context.Context, username string) (*domainUser.User, error) {
	var user domainUser.User
	err := r.db.GetContext(ctx, &user, "SELECT id, username, password, role, status, created_at, updated_at FROM users WHERE username = $1", username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil //nolint:nilnil // Return nil if not found
		}
		return nil, fmt.Errorf("GetUserByUsername error: %w", err)
	}
	return &user, nil
}

func (r *sqlxUserRepository) CreateUser(ctx context.Context, user *domainUser.User) error {
	query := `INSERT INTO users (username, password, role, status) VALUES (:username, :password, :role, :status)`
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

func (r *sqlxUserRepository) GetUsers(ctx context.Context) ([]domainUser.User, error) {
	var users []domainUser.User
	err := r.db.SelectContext(ctx, &users, "SELECT id, username, password, role, status, created_at, updated_at FROM users ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("GetUsers error: %w", err)
	}
	return users, nil
}
