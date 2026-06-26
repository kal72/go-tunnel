package config

import (
	"context"

	domainConfig "gotunnel/internal/domain/config"

	"github.com/google/uuid"
)

//go:generate mockery --name=ConfigUsecase --case=underscore --output=mocks --outpkg=mocks
type ConfigUsecase interface {
	GetConfigByName(ctx context.Context, userID uuid.UUID, name string) (*domainConfig.ClientConfig, error)
	GetConfigByID(ctx context.Context, id uuid.UUID) (*domainConfig.ClientConfig, error)
	GetConfigsByUserID(ctx context.Context, userID uuid.UUID) ([]domainConfig.ClientConfig, error)
	GetAllConfigs(ctx context.Context) ([]domainConfig.ClientConfig, error)
	CreateConfig(ctx context.Context, userID uuid.UUID, name string, tunnels domainConfig.TunnelsJSONB) error
	UpdateConfig(ctx context.Context, id uuid.UUID, name string, tunnels domainConfig.TunnelsJSONB) error
	DeleteConfig(ctx context.Context, id uuid.UUID) error
}
