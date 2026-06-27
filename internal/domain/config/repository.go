package config

import (
	"context"

	"github.com/google/uuid"
)

//mockery:generate: true
type ConfigRepository interface {
	GetConfigByName(ctx context.Context, userID uuid.UUID, name string) (*ClientConfig, error)
	GetConfigByID(ctx context.Context, id uuid.UUID) (*ClientConfig, error)
	GetConfigsByUserID(ctx context.Context, userID uuid.UUID) ([]ClientConfig, error)
	GetAllConfigs(ctx context.Context) ([]ClientConfig, error)
	CreateConfig(ctx context.Context, cfg *ClientConfig) error
	UpdateConfig(ctx context.Context, cfg *ClientConfig) error
	DeleteConfig(ctx context.Context, id uuid.UUID) error
}
