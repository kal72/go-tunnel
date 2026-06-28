package setting

import (
	"context"
)

//mockery:generate: true
type SettingUsecase interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)

	// Typed Helpers
	GetMaxFreeDomains(ctx context.Context, fallback int) int
	GetMaxTunnelsPerUser(ctx context.Context, fallback int) int
	GetAllowRegistration(ctx context.Context, fallback bool) bool
}
