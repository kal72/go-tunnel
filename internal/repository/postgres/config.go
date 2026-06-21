package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"gotunnel/internal/model"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type sqlxConfigRepository struct {
	db *sqlx.DB
}

func NewConfigRepository(db *sqlx.DB) model.ConfigRepository {
	return &sqlxConfigRepository{db: db}
}

func (r *sqlxConfigRepository) GetConfigByName(ctx context.Context, userID uuid.UUID, name string) (*model.ClientConfig, error) {
	var cfg model.ClientConfig
	err := r.db.GetContext(ctx, &cfg, "SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs WHERE user_id = $1 AND name = $2", userID, name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("GetConfigByName error: %w", err)
	}
	return &cfg, nil
}

func (r *sqlxConfigRepository) GetConfigByID(ctx context.Context, id uuid.UUID) (*model.ClientConfig, error) {
	var cfg model.ClientConfig
	err := r.db.GetContext(ctx, &cfg, "SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs WHERE id = $1", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("GetConfigByID error: %w", err)
	}
	return &cfg, nil
}

func (r *sqlxConfigRepository) GetConfigsByUserID(ctx context.Context, userID uuid.UUID) ([]model.ClientConfig, error) {
	var configs []model.ClientConfig
	err := r.db.SelectContext(ctx, &configs, "SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs WHERE user_id = $1 ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, fmt.Errorf("GetConfigsByUserID error: %w", err)
	}
	if configs == nil {
		configs = []model.ClientConfig{}
	}
	return configs, nil
}

func (r *sqlxConfigRepository) GetAllConfigs(ctx context.Context) ([]model.ClientConfig, error) {
	var configs []model.ClientConfig
	err := r.db.SelectContext(ctx, &configs, "SELECT id, user_id, name, tunnels, created_at, updated_at FROM client_configs ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("GetAllConfigs error: %w", err)
	}
	if configs == nil {
		configs = []model.ClientConfig{}
	}
	return configs, nil
}

func (r *sqlxConfigRepository) CreateConfig(ctx context.Context, cfg *model.ClientConfig) error {
	query := `INSERT INTO client_configs (id, user_id, name, tunnels) VALUES (:id, :user_id, :name, :tunnels)`
	_, err := r.db.NamedExecContext(ctx, query, cfg)
	if err != nil {
		return fmt.Errorf("CreateConfig error: %w", err)
	}
	return nil
}

func (r *sqlxConfigRepository) UpdateConfig(ctx context.Context, cfg *model.ClientConfig) error {
	query := `UPDATE client_configs SET name = :name, tunnels = :tunnels, updated_at = CURRENT_TIMESTAMP WHERE id = :id`
	_, err := r.db.NamedExecContext(ctx, query, cfg)
	if err != nil {
		return fmt.Errorf("UpdateConfig error: %w", err)
	}
	return nil
}

func (r *sqlxConfigRepository) DeleteConfig(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM client_configs WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("DeleteConfig error: %w", err)
	}
	return nil
}
