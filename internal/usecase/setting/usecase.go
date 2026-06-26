package setting

import (
	"context"
	"strconv"

	domainSetting "gotunnel/internal/domain/setting"
)

//go:generate mockery --name=SettingUsecase --case=underscore --output=mocks --outpkg=mocks
type SettingUsecase interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)

	// Typed Helpers
	GetMaxFreeDomains(ctx context.Context, fallback int) int
	GetMaxTunnelsPerUser(ctx context.Context, fallback int) int
	GetAllowRegistration(ctx context.Context, fallback bool) bool
}

type settingUsecase struct {
	store domainSetting.SettingStore
}

func NewSettingUsecase(store domainSetting.SettingStore) SettingUsecase {
	return &settingUsecase{
		store: store,
	}
}

func (u *settingUsecase) GetSetting(ctx context.Context, key string) (string, error) {
	return u.store.GetSetting(ctx, key)
}

func (u *settingUsecase) SetSetting(ctx context.Context, key, value string) error {
	return u.store.SetSetting(ctx, key, value)
}

func (u *settingUsecase) GetAllSettings(ctx context.Context) (map[string]string, error) {
	return u.store.GetAllSettings(ctx)
}

func (u *settingUsecase) GetMaxFreeDomains(ctx context.Context, fallback int) int {
	val, err := u.GetSetting(ctx, "max_free_domains")
	if err != nil || val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return parsed
}

func (u *settingUsecase) GetMaxTunnelsPerUser(ctx context.Context, fallback int) int {
	val, err := u.GetSetting(ctx, "max_tunnels_per_user")
	if err != nil || val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return parsed
}

func (u *settingUsecase) GetAllowRegistration(ctx context.Context, fallback bool) bool {
	val, err := u.GetSetting(ctx, "allow_registration")
	if err != nil || val == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		return fallback
	}
	return parsed
}
