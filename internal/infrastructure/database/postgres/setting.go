package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	domainSetting "gotunnel/internal/domain/setting"

	"github.com/jmoiron/sqlx"
)

type settingRepository struct {
	db *sqlx.DB
}

func NewSettingRepository(db *sqlx.DB) domainSetting.SettingStore {
	return &settingRepository{
		db: db,
	}
}

func (r *settingRepository) GetSetting(ctx context.Context, key string) (string, error) {
	query := `SELECT value FROM system_settings WHERE key = $1`
	var val []byte
	err := r.db.GetContext(ctx, &val, query, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil // Not found is handled gracefully in usecase
		}
		return "", err
	}
	
	// Value is stored as JSONB, so it might be wrapped in quotes if it's a string
	var strVal string
	if err := json.Unmarshal(val, &strVal); err != nil {
		// If unmarshalling fails, it might just be a raw value (though we enforce JSONB in DB)
		return string(val), nil
	}
	return strVal, nil
}

func (r *settingRepository) SetSetting(ctx context.Context, key string, value string) error {
	// Marshal the value to ensure valid JSONB storage
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO system_settings (key, value, updated_at) 
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		ON CONFLICT (key) DO UPDATE 
		SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP
	`
	_, err = r.db.ExecContext(ctx, query, key, jsonBytes)
	return err
}

func (r *settingRepository) GetAllSettings(ctx context.Context) (map[string]string, error) {
	query := `SELECT key, value FROM system_settings`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var key string
		var val []byte
		if err := rows.Scan(&key, &val); err != nil {
			return nil, err
		}
		
		var strVal string
		if err := json.Unmarshal(val, &strVal); err != nil {
			strVal = string(val)
		}
		settings[key] = strVal
	}
	
	return settings, rows.Err()
}
