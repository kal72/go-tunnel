package setting

import (
	"context"
	"strconv"

	domainSetting "gotunnel/internal/domain/setting"
)

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

func (u *settingUsecase) GetRateLimitConfig(ctx context.Context) domainSetting.RateLimitConfig {
	cfg := domainSetting.RateLimitConfig{
		Enabled:      true,
		Rate:         100,
		Burst:        20,
		AdminAllowed: false,
	}
	if val, err := u.GetSetting(ctx, "rate_limit_enabled"); err == nil && val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			cfg.Enabled = b
		}
	}
	if val, err := u.GetSetting(ctx, "rate_limit_rate"); err == nil && val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Rate = n
		}
	}
	if val, err := u.GetSetting(ctx, "rate_limit_burst"); err == nil && val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Burst = n
		}
	}
	if val, err := u.GetSetting(ctx, "rate_limit_admin_allowed"); err == nil && val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			cfg.AdminAllowed = b
		}
	}
	return cfg
}
