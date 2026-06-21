package usecase

import (
	"context"

	"gotunnel/internal/model"

	"github.com/google/uuid"
)

type configUsecase struct {
	configRepo model.ConfigRepository
}

func NewConfigUsecase(configRepo model.ConfigRepository) ConfigUsecase {
	return &configUsecase{
		configRepo: configRepo,
	}
}

func (u *configUsecase) GetConfigByName(ctx context.Context, userID uuid.UUID, name string) (*model.ClientConfig, error) {
	return u.configRepo.GetConfigByName(ctx, userID, name)
}

func (u *configUsecase) GetConfigByID(ctx context.Context, id uuid.UUID) (*model.ClientConfig, error) {
	return u.configRepo.GetConfigByID(ctx, id)
}

func (u *configUsecase) GetConfigsByUserID(ctx context.Context, userID uuid.UUID) ([]model.ClientConfig, error) {
	return u.configRepo.GetConfigsByUserID(ctx, userID)
}

func (u *configUsecase) GetAllConfigs(ctx context.Context) ([]model.ClientConfig, error) {
	return u.configRepo.GetAllConfigs(ctx)
}

func (u *configUsecase) CreateConfig(ctx context.Context, userID uuid.UUID, name string, tunnels model.TunnelsJSONB) error {
	existing, err := u.configRepo.GetConfigByName(ctx, userID, name)
	if err != nil {
		return err
	}
	if existing != nil {
		return model.ErrAlreadyExists
	}

	cfg := &model.ClientConfig{
		UserID:  userID,
		Name:    name,
		Tunnels: tunnels,
	}

	return u.configRepo.CreateConfig(ctx, cfg)
}

func (u *configUsecase) UpdateConfig(ctx context.Context, id uuid.UUID, name string, tunnels model.TunnelsJSONB) error {
	cfg, err := u.configRepo.GetConfigByID(ctx, id)
	if err != nil {
		return err
	}
	if cfg == nil {
		return model.ErrNotFound
	}

	// Check if renaming to an existing name
	if cfg.Name != name {
		existing, err := u.configRepo.GetConfigByName(ctx, cfg.UserID, name)
		if err != nil {
			return err
		}
		if existing != nil && existing.ID != id {
			return model.ErrAlreadyExists
		}
	}

	cfg.Name = name
	cfg.Tunnels = tunnels

	return u.configRepo.UpdateConfig(ctx, cfg)
}

func (u *configUsecase) DeleteConfig(ctx context.Context, id uuid.UUID) error {
	return u.configRepo.DeleteConfig(ctx, id)
}
