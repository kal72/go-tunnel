package setting

import (
	"context"
	"time"
)

// Setting represents a key-value system configuration.
type Setting struct {
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
	Key       string    `db:"key" json:"key"`
	Value     string    `db:"value" json:"value"`
}

// RateLimitConfig defines traffic rate limiting parameters.
type RateLimitConfig struct {
	Rate         int  `json:"rate"`
	Burst        int  `json:"burst"`
	Enabled      bool `json:"enabled"`
	AdminAllowed bool `json:"admin_allowed"`
}

//mockery:generate: true
type SettingStore interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key string, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)
}
